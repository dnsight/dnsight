"""Tests for :mod:`dnsight.sdk.audit.models`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dnsight.core.models import CheckResult, Issue
from dnsight.core.types import Severity, Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult


def _make_issue(severity: Severity = Severity.HIGH, id: str = "test.issue") -> Issue:
    return Issue(
        id=id,
        severity=severity,
        title="Test issue",
        description="A test issue",
        remediation="Fix it",
    )


class TestZoneResult:
    def test_partial_false_when_all_completed(self) -> None:
        zr = ZoneResult(
            zone="example.com",
            results={"dmarc": CheckResult[str](status=Status.COMPLETED)},
        )
        assert zr.partial is False

    def test_partial_true_when_check_partial(self) -> None:
        zr = ZoneResult(
            zone="example.com",
            results={"dmarc": CheckResult[str](status=Status.PARTIAL)},
        )
        assert zr.partial is True

    def test_partial_true_when_check_failed(self) -> None:
        zr = ZoneResult(
            zone="example.com",
            results={"dmarc": CheckResult[str](status=Status.FAILED)},
        )
        assert zr.partial is True

    def test_partial_true_from_child(self) -> None:
        child = ZoneResult(
            zone="sub.example.com",
            results={"dmarc": CheckResult[str](status=Status.FAILED)},
        )
        parent = ZoneResult(
            zone="example.com",
            results={"dmarc": CheckResult[str](status=Status.COMPLETED)},
            children=[child],
        )
        assert parent.partial is True

    def test_issue_count(self) -> None:
        zr = ZoneResult(
            zone="example.com",
            results={
                "dmarc": CheckResult[str](
                    status=Status.COMPLETED, issues=[_make_issue(), _make_issue()]
                ),
                "spf": CheckResult[str](
                    status=Status.COMPLETED, issues=[_make_issue()]
                ),
            },
        )
        assert zr.issue_count == 3

    def test_issue_count_excludes_children(self) -> None:
        child = ZoneResult(
            zone="sub.example.com",
            results={
                "dmarc": CheckResult[str](
                    status=Status.COMPLETED, issues=[_make_issue()]
                )
            },
        )
        parent = ZoneResult(zone="example.com", children=[child])
        assert parent.issue_count == 0


class TestDomainResult:
    def _make_domain_result(self) -> DomainResult:
        child = ZoneResult(
            zone="sub.example.com",
            results={
                "spf": CheckResult[str](
                    status=Status.COMPLETED,
                    issues=[_make_issue(severity=Severity.CRITICAL, id="crit.1")],
                )
            },
        )
        root_zone = ZoneResult(
            zone="example.com",
            results={
                "dmarc": CheckResult[str](
                    status=Status.COMPLETED,
                    issues=[_make_issue(severity=Severity.HIGH, id="high.1")],
                )
            },
            children=[child],
        )
        return DomainResult(
            domain="example.com",
            target="example.com",
            timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            config_version=1,
            zones=[root_zone],
            partial=False,
        )

    def test_root(self) -> None:
        dr = self._make_domain_result()
        assert dr.root.zone == "example.com"

    def test_all_issues_includes_children(self) -> None:
        dr = self._make_domain_result()
        issues = dr.all_issues
        zones = [zone for zone, _ in issues]
        ids = [issue.id for _, issue in issues]
        assert "example.com" in zones
        assert "sub.example.com" in zones
        assert "high.1" in ids
        assert "crit.1" in ids

    def test_critical_count(self) -> None:
        dr = self._make_domain_result()
        assert dr.critical_count == 1

    def test_partial_field(self) -> None:
        dr = self._make_domain_result()
        assert dr.partial is False

    def test_root_empty_raises(self) -> None:
        dr = DomainResult(
            domain="example.com",
            target="example.com",
            timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            config_version=1,
            zones=[],
            partial=False,
        )
        with pytest.raises(ValueError, match="no zones"):
            _ = dr.root


class TestCoreModelsLazyReexport:
    """``dnsight.core.models.DomainResult`` resolves to audit models."""

    def test_domain_result_same_class(self) -> None:
        from dnsight.core import models as cm

        assert cm.DomainResult is DomainResult
