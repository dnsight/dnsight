"""Tests for :mod:`dnsight.checks` — public exports and real API contracts."""

from __future__ import annotations

import asyncio
import inspect

import pytest

import dnsight.checks as checks_pkg
from dnsight.checks import (
    DMARCCheck,
    DMARCData,
    DMARCIssueId,
    DMARCRecommendationId,
    HeadersIssueId,
    check_dmarc,
    generate_dmarc,
    get_dmarc,
    headers_issue_descriptor,
)
from dnsight.checks.dmarc import DMARCGenerateParams
from dnsight.core.types import IssueDescriptor, RecordType
from dnsight.utils.dns import FakeDNSResolver, set_resolver


pytestmark = pytest.mark.registry_builtins

_DMARC_TXT = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"

# Subset of stable public names; catches accidental __all__ shrinkage.
_EXPECTED_EXPORTS = frozenset(
    {
        "DMARCCheck",
        "DMARCData",
        "DMARCIssueId",
        "DMARCRecommendationId",
        "check_dmarc",
        "generate_dmarc",
        "get_dmarc",
        "headers_issue_descriptor",
        "DNSSECCheck",
        "CAACheck",
        "HeadersCheck",
        "MXCheck",
        "SPFCheck",
        "DKIMCheck",
    }
)


def test_checks_package_all_includes_core_exports() -> None:
    assert frozenset(checks_pkg.__all__) >= _EXPECTED_EXPORTS
    for name in _EXPECTED_EXPORTS:
        assert getattr(checks_pkg, name) is not None


@pytest.mark.parametrize(
    "exported_type", [DMARCCheck, DMARCData, DMARCIssueId, DMARCRecommendationId]
)
def test_dmarc_exported_types_are_classes(exported_type: type) -> None:
    assert isinstance(exported_type, type)


def test_get_dmarc_returns_dmarc_data() -> None:
    set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
    data = asyncio.run(get_dmarc("example.com"))
    assert isinstance(data, DMARCData)


def test_check_dmarc_is_async() -> None:
    assert inspect.iscoroutinefunction(check_dmarc)


def test_generate_dmarc_returns_txt_record() -> None:
    rec = generate_dmarc(
        params=DMARCGenerateParams(
            policy="reject",
            percentage=100,
            subdomain_policy=None,
            alignment_dkim="r",
            alignment_spf="r",
            rua=["mailto:a@example.com"],
            ruf=[],
        )
    )
    assert rec.record_type == RecordType.TXT
    assert rec.host == "_dmarc"
    assert "v=DMARC1" in rec.value


def test_headers_issue_descriptor_returns_descriptor() -> None:
    d = headers_issue_descriptor(HeadersIssueId.HSTS_MISSING)
    assert isinstance(d, IssueDescriptor)
