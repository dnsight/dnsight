"""Tests for checks/dnssec — FakeDNSResolver, registry, validation paths."""

from __future__ import annotations

import importlib

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
from dns.rdtypes.ANY.DNSKEY import DNSKEY
import dns.rrset
import pytest

import dnsight.checks  # noqa: F401 — registers checks
import dnsight.checks.dnssec
from dnsight.checks.dnssec import DNSSECIssueId, check_dnssec, get_dnssec
from dnsight.core.config.blocks import DnssecConfig
from dnsight.core.registry import get_check_def
from dnsight.core.types import Capability, Status
from dnsight.utils.dns import FakeDNSResolver, set_resolver


def _dnskey_msg_no_rrsig() -> dns.message.Message:
    """DNSKEY answer without RRSIG (validation must fail)."""
    import dns.flags
    import dns.rdataclass

    name = dns.name.from_text("example.com")
    k = DNSKEY(dns.rdataclass.IN, dns.rdatatype.DNSKEY, 257, 3, 8, b"x" * 32)
    rrset = dns.rrset.from_rdata_list(name, 3600, [k])
    q = dns.message.make_query("example.com", "DNSKEY")
    r = dns.message.make_response(q)
    r.answer.append(rrset)
    r.flags |= dns.flags.AA | dns.flags.RA
    return r


def _nxdomain_no_nsec() -> dns.message.Message:
    """NXDOMAIN without authority NSEC."""
    q = dns.message.make_query("nxtest.example.com", "A")
    r = dns.message.make_response(q)
    r.set_rcode(dns.rcode.NXDOMAIN)
    return r


def _simple_ns_msg() -> dns.message.Message:
    """NS response without RRSIG (for no_rrsig path)."""
    import dns.flags
    import dns.rdataclass
    from dns.rdtypes.ANY.NS import NS

    name = dns.name.from_text("example.com")
    ns = NS(dns.rdataclass.IN, dns.rdatatype.NS, dns.name.from_text("ns1.example.com"))
    rrset = dns.rrset.from_rdata_list(name, 3600, [ns])
    q = dns.message.make_query("example.com", "NS")
    r = dns.message.make_response(q)
    r.answer.append(rrset)
    r.flags |= dns.flags.AA | dns.flags.RA
    return r


class TestDNSSECRegistry:
    def test_dnssec_registered(self) -> None:
        importlib.reload(dnsight.checks.dnssec)
        d = get_check_def("dnssec")
        assert d.name == "dnssec"
        assert Capability.CHECK in d.capabilities
        assert Capability.GENERATE not in d.capabilities


@pytest.mark.asyncio
async def test_require_ds_missing() -> None:
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/DNSKEY": [
                    {"flags": 257, "protocol": 3, "algorithm": 8, "key": b"y" * 32}
                ],
                "example.com/NS": ["ns1.example.com"],
            },
            dnssec_messages={
                "example.com/DNSKEY": _dnskey_msg_no_rrsig(),
                "example.com/NS": _simple_ns_msg(),
            },
        )
    )
    cfg = DnssecConfig(require_ds=True)
    result = await check_dnssec("example.com", config=cfg)
    assert result.status == Status.COMPLETED
    assert result.data is not None
    ids = {i.id for i in result.issues}
    assert DNSSECIssueId.DS_MISSING.value in ids


@pytest.mark.asyncio
async def test_dnskey_missing() -> None:
    set_resolver(FakeDNSResolver({}))
    result = await check_dnssec("example.com")
    assert result.status == Status.COMPLETED
    ids = {i.id for i in result.issues}
    assert DNSSECIssueId.DNSKEY_MISSING.value in ids


@pytest.mark.asyncio
async def test_no_rrsig_dnskey() -> None:
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/DS": [(12345, 8, 2, b"\x00" * 32)],
                "example.com/DNSKEY": [
                    {"flags": 257, "protocol": 3, "algorithm": 8, "key": b"x" * 32}
                ],
                "example.com/NS": ["ns1.example.com"],
            },
            dnssec_messages={
                "example.com/DNSKEY": _dnskey_msg_no_rrsig(),
                "example.com/NS": _simple_ns_msg(),
            },
        )
    )
    cfg = DnssecConfig(require_ds=False, validate_negative_responses=False)
    result = await check_dnssec("example.com", config=cfg)
    assert result.status == Status.COMPLETED
    ids = {i.id for i in result.issues}
    assert DNSSECIssueId.NO_RRSIG.value in ids


@pytest.mark.asyncio
async def test_negative_proof_unproven() -> None:
    """NXDOMAIN without NSEC in authority triggers negative proof issue."""
    dk = _dnskey_msg_no_rrsig()
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/DS": [(12345, 8, 2, b"\x00" * 32)],
                "example.com/DNSKEY": [
                    {"flags": 257, "protocol": 3, "algorithm": 8, "key": b"x" * 32}
                ],
                "example.com/NS": ["ns1.example.com"],
            },
            dnssec_messages={
                "example.com/DNSKEY": dk,
                "example.com/NS": _simple_ns_msg(),
                "nxtest.example.com/A": _nxdomain_no_nsec(),
            },
        )
    )
    cfg = DnssecConfig(
        require_ds=False,
        validate_negative_responses=True,
        nxdomain_probe_label="nxtest",
        validate_nodata_proofs=False,
    )
    result = await check_dnssec("example.com", config=cfg)
    assert result.status == Status.COMPLETED
    assert result.data is not None
    assert result.data.negative_attempt is not None
    assert result.data.negative_attempt.proof_ok is False
    ids = {i.id for i in result.issues}
    assert DNSSECIssueId.NEGATIVE_UNPROVEN.value in ids or any(
        "nxdomain" in i.title.lower() for i in result.issues
    )


@pytest.mark.asyncio
async def test_weak_algorithm_ds() -> None:
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/DS": [(12345, 1, 1, b"\xab" * 20)],
                "example.com/DNSKEY": [
                    {"flags": 257, "protocol": 3, "algorithm": 8, "key": b"x" * 32}
                ],
                "example.com/NS": ["ns1.example.com"],
            },
            dnssec_messages={
                "example.com/DNSKEY": _dnskey_msg_no_rrsig(),
                "example.com/NS": _simple_ns_msg(),
            },
        )
    )
    cfg = DnssecConfig(
        require_ds=False, disallowed_algorithms=["1"], validate_negative_responses=False
    )
    result = await check_dnssec("example.com", config=cfg)
    ids = {i.id for i in result.issues}
    assert DNSSECIssueId.ALGORITHM_WEAK.value in ids


@pytest.mark.asyncio
async def test_get_dnssec_data() -> None:
    set_resolver(
        FakeDNSResolver(
            {
                "example.com/DS": [(1, 8, 2, b"\x00" * 32)],
                "example.com/DNSKEY": [
                    {"flags": 256, "protocol": 3, "algorithm": 8, "key": b"z" * 32}
                ],
                "example.com/NS": ["ns.example.com"],
            },
            dnssec_messages={
                "example.com/DNSKEY": _dnskey_msg_no_rrsig(),
                "example.com/NS": _simple_ns_msg(),
            },
        )
    )
    data = await get_dnssec("example.com")
    assert len(data.ds_records) == 1
    assert len(data.dnskey_records) == 1
    assert data.ns_hostnames == ["ns.example.com"]
