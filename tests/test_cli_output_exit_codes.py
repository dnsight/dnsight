"""CLI exit-code helpers: map :class:`~dnsight.core.models` outcomes to 0/1/2."""

from __future__ import annotations

from datetime import UTC, datetime

from dnsight.cli.output import (
    exit_code_for_check_result,
    exit_code_for_domain_result,
    exit_code_for_domain_results,
)
from dnsight.core.models import CheckResult, DomainResult, Issue, ZoneResult
from dnsight.core.types import Severity, Status


def _issue() -> Issue:
    return Issue(
        id="t.example",
        severity=Severity.MEDIUM,
        title="t",
        description="d",
        remediation="r",
    )


def test_exit_code_domain_result_clean() -> None:
    z = ZoneResult(zone="example.com", results={})
    dr = DomainResult(
        domain="example.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z],
        partial=False,
    )
    assert exit_code_for_domain_result(dr) == 0


def test_exit_code_domain_result_partial() -> None:
    z = ZoneResult(zone="example.com", results={})
    dr = DomainResult(
        domain="example.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z],
        partial=True,
    )
    assert exit_code_for_domain_result(dr) == 2


def test_exit_code_domain_result_has_issues() -> None:
    z = ZoneResult(
        zone="example.com",
        results={
            "dmarc": CheckResult(status=Status.COMPLETED, data=None, issues=[_issue()])
        },
    )
    dr = DomainResult(
        domain="example.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z],
        partial=False,
    )
    assert exit_code_for_domain_result(dr) == 1


def test_exit_code_domain_results_worst_wins() -> None:
    z_clean = ZoneResult(zone="a.com", results={})
    z_issues = ZoneResult(
        zone="b.com",
        results={
            "dmarc": CheckResult(status=Status.COMPLETED, data=None, issues=[_issue()])
        },
    )
    d0 = DomainResult(
        domain="a.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z_clean],
        partial=False,
    )
    d1 = DomainResult(
        domain="b.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z_issues],
        partial=False,
    )
    assert exit_code_for_domain_results([d0, d1]) == 1
    assert exit_code_for_domain_results([]) == 0


def test_exit_code_check_result_failed_and_partial() -> None:
    failed = CheckResult(status=Status.FAILED, data=None, error="x")
    assert exit_code_for_check_result(failed) == 2
    partial = CheckResult(status=Status.PARTIAL, data=None)
    assert exit_code_for_check_result(partial) == 2


def test_exit_code_check_result_issues_only() -> None:
    cr = CheckResult(status=Status.COMPLETED, data=None, issues=[_issue()])
    assert exit_code_for_check_result(cr) == 1


def test_exit_code_check_result_clean() -> None:
    cr = CheckResult(status=Status.COMPLETED, data=None, issues=[])
    assert exit_code_for_check_result(cr) == 0
