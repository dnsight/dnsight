"""Tests for checks/mx — fake resolver, fake STARTTLS, registry."""

from __future__ import annotations

import importlib

import dns.reversename
import pytest

import dnsight.checks  # noqa: F401 — registers checks
from dnsight.checks.mx import (
    MXCheck,
    MXIssueId,
    MXRecommendationId,
    check_mx,
    generate_mx,
    get_mx,
)
from dnsight.checks.mx.models import MXGenerateParams, MXGenerateTarget
from dnsight.checks.mx.rules import build_mx_generated_value
from dnsight.core.config.blocks import Config, MxConfig
from dnsight.core.models import GeneratedRecord
from dnsight.core.registry import get
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.dns import FakeDNSResolver, set_resolver
from dnsight.utils.smtp import (
    FakeStartTLSProbe,
    StartTLSOutcome,
    StartTLSProbeResult,
    set_starttls_probe,
)


def _ptr_key(ipv4: str) -> str:
    rev = dns.reversename.from_address(ipv4)
    return rev.to_text(omit_final_dot=True)


class TestMXRegistry:
    def test_mx_registered(self) -> None:
        import dnsight.checks.mx

        importlib.reload(dnsight.checks.mx)
        d = get("mx")
        assert d.name == "mx"
        assert Capability.CHECK in d.capabilities
        assert Capability.GENERATE in d.capabilities


class TestMXCheckClass:
    def test_name_and_capabilities(self) -> None:
        assert MXCheck.name == "mx"
        assert MXCheck.capabilities == frozenset(
            {Capability.CHECK, Capability.GENERATE}
        )


@pytest.mark.asyncio
async def test_get_mx_basic() -> None:
    set_resolver(FakeDNSResolver({"example.com/MX": [(10, "mail.example.com")]}))
    data = await get_mx("example.com")
    assert len(data.mx_hosts) == 1
    assert data.mx_hosts[0].hostname == "mail.example.com"
    assert data.mx_hosts[0].priority == 10
    assert data.mx_hosts[0].ptr is None
    assert data.mx_hosts[0].starttls_supported is None


@pytest.mark.asyncio
async def test_check_mx_pass_with_ptr_and_starttls() -> None:
    ip = "203.0.113.10"
    ptr_k = _ptr_key(ip)
    host = "mail.example.com"
    set_resolver(
        FakeDNSResolver(
            {"example.com/MX": [(10, host)], f"{host}/A": [ip], f"{ptr_k}/PTR": [host]}
        )
    )
    set_starttls_probe(
        FakeStartTLSProbe({(host.lower(), 25): StartTLSProbeResult(StartTLSOutcome.OK)})
    )
    cfg = MxConfig(check_ptr=True, check_starttls=True, starttls_timeout_seconds=5.0)
    result = await check_mx("example.com", config=cfg)
    assert result.status == Status.COMPLETED
    assert result.data is not None
    assert result.data.mx_hosts[0].ptr_matches is True
    assert result.data.mx_hosts[0].starttls_supported is True
    assert result.issues == []


@pytest.mark.asyncio
async def test_check_mx_record_missing() -> None:
    set_resolver(FakeDNSResolver({"example.com/MX": []}))
    result = await check_mx("example.com")
    assert result.status == Status.COMPLETED
    ids = [i.id for i in result.issues]
    assert MXIssueId.RECORD_MISSING in ids


@pytest.mark.asyncio
async def test_check_mx_duplicate_priority() -> None:
    set_resolver(
        FakeDNSResolver(
            {"example.com/MX": [(10, "a.example.com"), (10, "b.example.com")]}
        )
    )
    result = await check_mx("example.com")
    assert MXIssueId.DUPLICATE_PRIORITY in [i.id for i in result.issues]


@pytest.mark.asyncio
async def test_check_mx_ptr_missing() -> None:
    host = "mail.example.com"
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/MX": [(10, host)],
                f"{host}/A": ["203.0.113.20"],
                f"{_ptr_key('203.0.113.20')}/PTR": ["wrong.example.com"],
            }
        )
    )
    result = await check_mx(
        "example.com", config=MxConfig(check_ptr=True, check_starttls=False)
    )
    assert MXIssueId.PTR_MISSING in [i.id for i in result.issues]
    assert any(r.id == MXRecommendationId.ADD_PTR for r in result.recommendations)


@pytest.mark.asyncio
async def test_check_mx_starttls_not_supported() -> None:
    host = "mail.example.com"
    set_resolver(FakeDNSResolver({"example.com/MX": [(10, host)]}))
    set_starttls_probe(
        FakeStartTLSProbe(
            {
                (host.lower(), 25): StartTLSProbeResult(
                    StartTLSOutcome.NOT_SUPPORTED,
                    "STARTTLS not advertised in EHLO response",
                )
            }
        )
    )
    result = await check_mx("example.com", config=MxConfig(check_starttls=True))
    assert MXIssueId.STARTTLS_NOT_SUPPORTED in [i.id for i in result.issues]


@pytest.mark.asyncio
async def test_check_mx_starttls_failed() -> None:
    host = "mail.example.com"
    set_resolver(FakeDNSResolver({"example.com/MX": [(10, host)]}))
    set_starttls_probe(
        FakeStartTLSProbe(
            {
                (host.lower(), 25): StartTLSProbeResult(
                    StartTLSOutcome.FAILED, "connection timed out after 5.0s"
                )
            }
        )
    )
    result = await check_mx(
        "example.com",
        config=MxConfig(check_starttls=True, starttls_timeout_seconds=5.0),
    )
    assert MXIssueId.STARTTLS_FAILED in [i.id for i in result.issues]


@pytest.mark.asyncio
async def test_check_mx_dns_failure_partial() -> None:
    set_resolver(FakeDNSResolver({}))
    result = await check_mx("example.com")
    assert result.status == Status.FAILED
    assert result.error is not None
    assert "MX" in (result.error or "")


@pytest.mark.asyncio
async def test_config_slice_from_root() -> None:
    set_resolver(FakeDNSResolver({"example.com/MX": [(10, "m.example.com")]}))
    cfg = Config(mx=MxConfig(check_ptr=False))
    data = await get_mx("example.com", config=cfg)
    assert len(data.mx_hosts) == 1


class TestMXGenerate:
    def test_generate_mx_single(self) -> None:
        rec = generate_mx(
            params=MXGenerateParams(
                targets=[MXGenerateTarget(priority=10, hostname="mail.example.com")]
            )
        )
        assert isinstance(rec, GeneratedRecord)
        assert rec.record_type == RecordType.MX
        assert rec.host == "@"
        assert rec.value == "10 mail.example.com."

    def test_generate_mx_sorted_by_priority_then_host(self) -> None:
        rec = generate_mx(
            params=MXGenerateParams(
                targets=[
                    MXGenerateTarget(priority=20, hostname="b.example.com"),
                    MXGenerateTarget(priority=10, hostname="a.example.com"),
                    MXGenerateTarget(priority=10, hostname="z.example.com"),
                ]
            )
        )
        assert rec.value.splitlines() == [
            "10 a.example.com.",
            "10 z.example.com.",
            "20 b.example.com.",
        ]

    def test_generate_mx_normalises_trailing_dot(self) -> None:
        rec = generate_mx(
            params=MXGenerateParams(
                targets=[MXGenerateTarget(priority=5, hostname="MAIL.EXAMPLE.COM.")]
            )
        )
        assert rec.value == "5 mail.example.com."

    def test_build_mx_generated_value_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one target"):
            build_mx_generated_value(MXGenerateParams())

    def test_generate_mx_with_config_only_empty_targets_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one target"):
            generate_mx(config=MxConfig())
