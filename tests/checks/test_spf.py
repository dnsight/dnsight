"""Tests for checks/spf — flatten logic, validation, registry."""

from __future__ import annotations

import importlib

import pytest

import dnsight.checks  # noqa: F401 — registers checks
from dnsight.checks.spf import (
    SPFCheck,
    SPFGenerateParams,
    SPFIssueId,
    check_spf,
    generate_spf,
    get_spf,
)
from dnsight.checks.spf.rules import flatten_spf as flatten_spf_impl
from dnsight.core.config.blocks import SpfConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.registry import get
from dnsight.core.types import Capability, Status
from dnsight.utils.dns import FakeDNSResolver, reset_resolver, set_resolver


@pytest.fixture(autouse=True)
def _reset_dns_resolver() -> None:
    yield
    reset_resolver()


class TestSPFRegistry:
    def test_spf_registered(self) -> None:
        # conftest clears the registry before each test; reload to re-run @register.
        import dnsight.checks.spf

        importlib.reload(dnsight.checks.spf)
        d = get("spf")
        assert d.name == "spf"
        assert Capability.CHECK in d.capabilities


class TestSPFCheckClass:
    def test_name_and_capabilities(self) -> None:
        assert SPFCheck.name == "spf"
        assert Capability.CHECK in SPFCheck.capabilities
        assert Capability.GENERATE in SPFCheck.capabilities


@pytest.mark.asyncio
async def test_check_spf_dns_failed() -> None:
    set_resolver(FakeDNSResolver({}))
    r = await check_spf("example.com")
    assert r.status == Status.FAILED
    assert r.error


@pytest.mark.asyncio
async def test_get_spf_raises_on_apex_failure() -> None:
    set_resolver(FakeDNSResolver({}))
    with pytest.raises(CheckError):
        await get_spf("example.com")


@pytest.mark.asyncio
async def test_redirect_tokens_after_redirect_ignored() -> None:
    """include:evil is after redirect= — must not query evil.com."""
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/TXT": [
                    "v=spf1 include:foo.com redirect=bar.com include:evil.com"
                ],
                "foo.com/TXT": ["v=spf1 -all"],
                "bar.com/TXT": ["v=spf1 -all"],
            }
        )
    )
    from dnsight.utils.dns import get_resolver

    out = await flatten_spf_impl(
        "example.com", get_resolver(), allow_redirect=True, lookup_limit=20
    )
    assert "evil.com" not in out.include_resolution_errors
    assert "include:foo.com" in out.flat.resolved_mechanisms


@pytest.mark.asyncio
async def test_redirect_not_allowed_issue() -> None:
    set_resolver(
        FakeDNSResolver({"example.com/TXT": ["v=spf1 redirect=other.com -all"]})
    )
    r = await check_spf("example.com", config=SpfConfig(allow_redirect=False))
    assert any(i.id == SPFIssueId.REDIRECT_NOT_ALLOWED for i in r.issues)
    assert r.data is not None


@pytest.mark.asyncio
async def test_lookup_count_no_double_count_mx_a() -> None:
    """a + mx mechanisms each add one lookup (plus one TXT fetch)."""
    set_resolver(FakeDNSResolver({"example.com/TXT": ["v=spf1 a mx -all"]}))
    from dnsight.utils.dns import get_resolver

    out = await flatten_spf_impl("example.com", get_resolver(), lookup_limit=20)
    assert out.flat.effective_lookup_count == 3


@pytest.mark.asyncio
async def test_disposition_softfail_no_duplicate_weaker_issue() -> None:
    """~all vs required -all should emit SOFTFAIL only, not generic weaker SYNTAX_INVALID."""
    set_resolver(FakeDNSResolver({"example.com/TXT": ["v=spf1 ~all"]}))
    r = await check_spf("example.com", config=SpfConfig(required_disposition="-all"))
    ids = [i.id for i in r.issues]
    assert SPFIssueId.DISPOSITION_SOFTFAIL in ids
    assert ids.count(SPFIssueId.SYNTAX_INVALID) == 0 or not any(
        i.title == "SPF disposition weaker than required" for i in r.issues
    )


@pytest.mark.asyncio
async def test_include_resolution_error_issue() -> None:
    set_resolver(
        FakeDNSResolver({"example.com/TXT": ["v=spf1 include:missing.zone -all"]})
    )
    r = await check_spf("example.com")
    assert any(
        "include" in i.title.lower() or "resolve" in i.description.lower()
        for i in r.issues
    )


def test_generate_spf() -> None:
    gr = generate_spf(
        params=SPFGenerateParams(includes=["spf.example.com"], disposition="-all")
    )
    assert "v=spf1" in gr.value
    assert "-all" in gr.value
