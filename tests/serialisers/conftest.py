"""Shared fixtures for serialiser tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dnsight.core.models import CheckResult, Issue
from dnsight.core.types import Severity, Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult


@pytest.fixture
def sample_issue() -> Issue:
    return Issue(
        id="test.issue",
        severity=Severity.HIGH,
        title="Test issue",
        description="Description",
        remediation="Fix it",
    )


@pytest.fixture
def spf_like_data() -> dict[str, object]:
    return {
        "raw_record": "v=spf1 include:_spf.example.com ~all",
        "flattened": {
            "effective_lookup_count": 3,
            "ip4_ranges": ["1.1.1.0/24"],
            "ip6_ranges": [],
        },
        "suggested_record": "v=spf1 ip4:203.0.113.0/24 -all",
    }


@pytest.fixture
def domain_result_nested(
    spf_like_data: dict[str, object], sample_issue: Issue
) -> DomainResult:
    child = ZoneResult(
        zone="sub.example.com",
        parent="example.com",
        results={
            "spf": CheckResult[object](
                status=Status.FAILED, error="DNS timeout", issues=[]
            )
        },
    )
    root_zone = ZoneResult(
        zone="example.com",
        results={
            "dmarc": CheckResult[object](
                status=Status.COMPLETED, issues=[sample_issue]
            ),
            "spf": CheckResult[object](
                status=Status.COMPLETED, data=spf_like_data, issues=[]
            ),
        },
        children=[child],
    )
    return DomainResult(
        domain="example.com",
        target="example.com",
        timestamp=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
        config_version=1,
        zones=[root_zone],
        partial=True,
    )
