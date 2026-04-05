"""Tests for core models."""

from __future__ import annotations

from pydantic import ValidationError
import pytest

from dnsight.core.models import CheckResult, GeneratedRecord, Issue, Recommendation
from dnsight.core.types import RecordType, Severity, Status


def _make_issue(severity: Severity = Severity.HIGH, id: str = "test.issue") -> Issue:
    return Issue(
        id=id,
        severity=severity,
        title="Test issue",
        description="A test issue",
        remediation="Fix it",
    )


def _make_recommendation(id: str = "test.rec") -> Recommendation:
    return Recommendation(
        id=id, title="Test recommendation", description="A test recommendation"
    )


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------


class TestIssue:
    def test_construction(self) -> None:
        issue = _make_issue()
        assert issue.id == "test.issue"
        assert issue.severity == Severity.HIGH
        assert issue.title == "Test issue"

    def test_frozen(self) -> None:
        issue = _make_issue()
        with pytest.raises(ValidationError):
            issue.id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Recommendation
# ---------------------------------------------------------------------------


class TestRecommendation:
    def test_construction(self) -> None:
        rec = _make_recommendation()
        assert rec.id == "test.rec"
        assert rec.title == "Test recommendation"

    def test_frozen(self) -> None:
        rec = _make_recommendation()
        with pytest.raises(ValidationError):
            rec.title = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------


class TestCheckResult:
    def test_passed_true(self) -> None:
        result = CheckResult[str](status=Status.COMPLETED, data="ok")
        assert result.passed is True

    def test_passed_false_with_issues(self) -> None:
        result = CheckResult[str](status=Status.COMPLETED, issues=[_make_issue()])
        assert result.passed is False

    def test_passed_false_wrong_status(self) -> None:
        result = CheckResult[str](status=Status.FAILED)
        assert result.passed is False

    def test_failed(self) -> None:
        assert CheckResult[str](status=Status.FAILED).failed is True
        assert CheckResult[str](status=Status.COMPLETED).failed is False

    def test_skipped(self) -> None:
        assert CheckResult[str](status=Status.SKIPPED).skipped is True
        assert CheckResult[str](status=Status.COMPLETED).skipped is False

    def test_partial(self) -> None:
        assert CheckResult[str](status=Status.PARTIAL).partial is True
        assert CheckResult[str](status=Status.COMPLETED).partial is False

    def test_has_critical_true(self) -> None:
        result = CheckResult[str](
            status=Status.COMPLETED, issues=[_make_issue(severity=Severity.CRITICAL)]
        )
        assert result.has_critical is True

    def test_has_critical_false(self) -> None:
        result = CheckResult[str](
            status=Status.COMPLETED, issues=[_make_issue(severity=Severity.LOW)]
        )
        assert result.has_critical is False

    @pytest.mark.parametrize("severity", list(Severity))
    def test_has_severity(self, severity: Severity) -> None:
        result = CheckResult[str](
            status=Status.COMPLETED, issues=[_make_issue(severity=severity)]
        )
        assert result.has_severity(severity) is True
        other = Severity.INFO if severity != Severity.INFO else Severity.HIGH
        assert result.has_severity(other) is (other == severity)

    def test_defaults(self) -> None:
        result = CheckResult[str](status=Status.COMPLETED)
        assert result.data is None
        assert result.raw is None
        assert result.issues == []
        assert result.recommendations == []
        assert result.error is None

    def test_frozen(self) -> None:
        result = CheckResult[str](status=Status.COMPLETED)
        with pytest.raises(ValidationError):
            result.status = Status.FAILED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# GeneratedRecord
# ---------------------------------------------------------------------------


class TestGeneratedRecord:
    def test_construction(self) -> None:
        rec = GeneratedRecord(
            record_type=RecordType.TXT, host="_dmarc", value="v=DMARC1; p=reject"
        )
        assert rec.record_type == RecordType.TXT
        assert rec.host == "_dmarc"
        assert rec.value == "v=DMARC1; p=reject"

    def test_http_header_record_type(self) -> None:
        rec = GeneratedRecord(
            record_type=RecordType.HTTP_HEADER,
            host="",
            value="Strict-Transport-Security: max-age=31536000",
        )
        assert rec.record_type == RecordType.HTTP_HEADER
        assert rec.host == ""

    def test_default_ttl(self) -> None:
        rec = GeneratedRecord(record_type=RecordType.TXT, host="@", value="v=spf1")
        assert rec.ttl == 3600

    def test_custom_ttl(self) -> None:
        rec = GeneratedRecord(
            record_type=RecordType.TXT, host="@", value="v=spf1", ttl=300
        )
        assert rec.ttl == 300

    def test_frozen(self) -> None:
        rec = GeneratedRecord(record_type=RecordType.TXT, host="@", value="v=spf1")
        with pytest.raises(ValidationError):
            rec.host = "changed"  # type: ignore[misc]
