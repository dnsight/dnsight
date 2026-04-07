"""Tests for checks/dkim — validation, fake resolver, registry."""

from __future__ import annotations

from collections.abc import Iterator
import importlib

import pytest

import dnsight.checks  # noqa: F401 — registers checks
from dnsight.checks.dkim import DKIMCheck, DKIMIssueId, check_dkim, get_dkim
from dnsight.checks.dkim.rules import (
    build_selector_fqdn,
    dkim_query_plan,
    merge_selector_names,
    parse_dkim_txt,
)
from dnsight.core.config.blocks import Config, DkimConfig
from dnsight.core.config.defaults import DEFAULT_DKIM_COMMON_SELECTORS
from dnsight.core.registry import get_check_def
from dnsight.core.types import Capability, Status
from dnsight.utils.dns import FakeDNSResolver, reset_resolver, set_resolver


# openssl-generated RSA public keys (DER, base64)
RSA2048_P_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArW4cCSiZQ2Pva8QFxoUN"
    "B/ke6FExi0rV4cg5FleDA5UuZfwfgWtJe5nFmMMY+Df8n6JZnOwre1CITDjQWnZ8"
    "3+mFODg0sbbOff4fhowG9etKiQ1EzEKgcPrExjhYt2wg7Vd8KT8dlF7eozfDs7OmC"
    "8m5XbJ0w14OLg3ohDk7Ichv64vOqPtIsfoZmAFWcHbzfwp0i3qDbhAMpiOnR+QBJZ"
    "iHXjSw2P0bdzzv0W2J8k6wI1D0fi3+SSi56HJMqcJbHNF0DM0mLXj0BJj+cGfHJnO"
    "zNSEP1ozemxQpNp8rhE3OspM86YK89gDk7Cwh5F50gujsPVzJDyhw274QKMaG3QID"
    "AQAB"
)
RSA1024_P_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHTnt8yqdb9zWnBDzhM3e6TmPy"
    "kWFYHoyy+qvr000BN+ToeL3J/MkF+PRxSw8VffVzH9OBOkPxxQLUeEs6bb4NCRqx"
    "nYZ1NJjKC9E+oL7bd+n9zvpVMKRlSXuoTE3GM3kEalVyjwf9DSWUgqnx4YLsnBsX/"
    "cG3rY5HmPLlLJ+/BQIDAQAB"
)


@pytest.fixture(autouse=True)
def _reset_dns_resolver() -> Iterator[None]:
    yield
    reset_resolver()


def _txt2048() -> str:
    return f"v=DKIM1; k=rsa; p={RSA2048_P_B64}"


def _txt1024() -> str:
    return f"v=DKIM1; k=rsa; p={RSA1024_P_B64}"


def _fake_for_selector(domain: str, selector: str, record: str) -> dict[str, list[str]]:
    fqdn = build_selector_fqdn(selector, domain)
    return {f"{fqdn}/TXT": [record]}


def _fake_all_common(domain: str, record: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for sel in DEFAULT_DKIM_COMMON_SELECTORS:
        fqdn = build_selector_fqdn(sel, domain)
        out[f"{fqdn}/TXT"] = [record]
    return out


_SEL = "s1"


class TestDKIMRegistry:
    def test_dkim_registered(self) -> None:
        import dnsight.checks.dkim

        importlib.reload(dnsight.checks.dkim)
        d = get_check_def("dkim")
        assert d.name == "dkim"
        assert Capability.CHECK in d.capabilities
        assert Capability.GENERATE not in d.capabilities


class TestDKIMCheckClass:
    def test_name_and_capabilities(self) -> None:
        assert DKIMCheck.name == "dkim"
        assert DKIMCheck.capabilities == frozenset({Capability.CHECK})


def test_dkim_query_plan() -> None:
    n, a = dkim_query_plan(DkimConfig())
    assert a == ()
    assert n == list(DEFAULT_DKIM_COMMON_SELECTORS)
    n2, a2 = dkim_query_plan(DkimConfig(selectors=["mail"]))
    assert a2 == ("mail",)
    assert n2[:1] == ["mail"]
    assert set(n2) == {"mail", *DEFAULT_DKIM_COMMON_SELECTORS}


@pytest.mark.asyncio
async def test_check_dkim_discovery_pass_when_common_valid() -> None:
    domain = "example.com"
    set_resolver(FakeDNSResolver(_fake_all_common(domain, _txt2048())))
    r = await check_dkim(domain)
    assert r.status == Status.COMPLETED
    assert r.data is not None
    assert r.data.explicit_allowlist == ()
    assert not r.issues
    assert r.data.selectors_tried == list(DEFAULT_DKIM_COMMON_SELECTORS)


@pytest.mark.asyncio
async def test_check_dkim_discovery_pass_when_one_probe_valid() -> None:
    """Missing TXT on other probes must not fail discovery."""
    domain = "example.com"
    records = _fake_for_selector(domain, "google", _txt2048())
    set_resolver(FakeDNSResolver(records))
    r = await check_dkim(domain)
    assert r.status == Status.COMPLETED
    assert not r.issues


@pytest.mark.asyncio
async def test_check_dkim_explicit_pass() -> None:
    domain = "example.com"
    set_resolver(FakeDNSResolver(_fake_for_selector(domain, _SEL, _txt2048())))
    r = await check_dkim(domain, config=DkimConfig(selectors=[_SEL]))
    assert r.status == Status.COMPLETED
    assert r.data is not None
    assert r.data.explicit_allowlist == (_SEL,)
    assert not r.issues


@pytest.mark.asyncio
async def test_check_dkim_key_too_short() -> None:
    domain = "example.com"
    set_resolver(FakeDNSResolver(_fake_for_selector(domain, _SEL, _txt1024())))
    r = await check_dkim(domain, config=DkimConfig(selectors=[_SEL], min_key_bits=2048))
    assert r.status == Status.COMPLETED
    assert r.data is not None
    ids = [i.id for i in r.issues]
    assert DKIMIssueId.KEY_TOO_SHORT in ids
    assert not r.recommendations


@pytest.mark.asyncio
async def test_check_dkim_algorithm_weak() -> None:
    domain = "example.com"
    weak = f"v=DKIM1; k=rsa; p={RSA2048_P_B64}; h=sha1:sha256"
    set_resolver(FakeDNSResolver(_fake_for_selector(domain, _SEL, weak)))
    r = await check_dkim(
        domain, config=DkimConfig(selectors=[_SEL], disallowed_algorithms=["sha1"])
    )
    assert r.status == Status.COMPLETED
    assert DKIMIssueId.ALGORITHM_WEAK in [i.id for i in r.issues]
    assert "dkim.stronger_algorithm" in [rec.id for rec in r.recommendations]


@pytest.mark.asyncio
async def test_check_dkim_discovery_empty_resolver() -> None:
    set_resolver(FakeDNSResolver({}))
    r = await check_dkim("example.com")
    assert r.status == Status.COMPLETED
    assert r.data is not None
    assert r.data.explicit_allowlist == ()
    assert r.data.selectors_tried == list(DEFAULT_DKIM_COMMON_SELECTORS)
    assert DKIMIssueId.DISCOVERY_NO_VALID_KEY in [i.id for i in r.issues]
    assert "dkim.add_common_selectors" in [rec.id for rec in r.recommendations]


@pytest.mark.asyncio
async def test_check_dkim_explicit_missing_selector() -> None:
    set_resolver(FakeDNSResolver({}))
    r = await check_dkim("example.com", config=DkimConfig(selectors=["default"]))
    assert r.status == Status.COMPLETED
    assert DKIMIssueId.SELECTOR_NOT_FOUND in [i.id for i in r.issues]
    assert not r.recommendations


@pytest.mark.asyncio
async def test_check_dkim_explicit_extra_selector_txt() -> None:
    domain = "example.com"
    rec = _fake_for_selector(domain, _SEL, _txt2048())
    rec.update(_fake_for_selector(domain, "google", _txt2048()))
    set_resolver(FakeDNSResolver(rec))
    r = await check_dkim(domain, config=DkimConfig(selectors=[_SEL]))
    assert DKIMIssueId.EXTRA_SELECTOR_PUBLISHED in [i.id for i in r.issues]
    assert not any(i.id == DKIMIssueId.SELECTOR_NOT_FOUND for i in r.issues)


@pytest.mark.asyncio
async def test_check_dkim_resolver_unexpected_error() -> None:
    class _BoomResolver(FakeDNSResolver):
        async def resolve_txt(self, name: str) -> list[str]:  # noqa: ARG002
            msg = "simulated resolver failure"
            raise RuntimeError(msg)

    set_resolver(_BoomResolver({}))
    r = await check_dkim("example.com", config=DkimConfig(selectors=["x"]))
    assert r.status == Status.FAILED
    assert r.error
    assert r.data is None


@pytest.mark.asyncio
async def test_get_dkim_discovery_probes_common() -> None:
    set_resolver(FakeDNSResolver({}))
    data = await get_dkim("example.com")
    assert data.selectors_tried == list(DEFAULT_DKIM_COMMON_SELECTORS)
    assert len(data.selectors_found) == len(DEFAULT_DKIM_COMMON_SELECTORS)
    assert all(not row.found for row in data.selectors_found)
    assert data.explicit_allowlist == ()


def test_merge_selector_names_strips_dedupes() -> None:
    assert merge_selector_names([]) == []
    assert merge_selector_names(["a", " a ", "b", "a"]) == ["a", "b"]


def test_parse_revoked_empty_p() -> None:
    p = parse_dkim_txt("v=DKIM1; k=rsa; p=")
    assert p.version_ok
    assert p.public_key_b64 == ""


@pytest.mark.asyncio
async def test_strict_rec_from_root_config() -> None:
    domain = "example.com"
    set_resolver(FakeDNSResolver(_fake_for_selector(domain, _SEL, _txt1024())))
    cfg = Config(
        dkim=DkimConfig(selectors=[_SEL], min_key_bits=2048),
        strict_recommendations=True,
    )
    r = await check_dkim(domain, config=cfg)
    assert r.status == Status.COMPLETED
    assert DKIMIssueId.KEY_TOO_SHORT in [i.id for i in r.issues]
