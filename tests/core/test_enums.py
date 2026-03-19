"""Tests for core enums."""

from __future__ import annotations

from enum import StrEnum

import pytest

from dnsight.core.types import (
    Capability,
    DNSProvider,
    IssueId,
    OutputFormat,
    RecommendationId,
    Severity,
    Status,
)


class TestSeverity:
    def test_members(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_member_count(self) -> None:
        assert len(Severity) == 5

    def test_str_coercion(self) -> None:
        assert str(Severity.CRITICAL) == "critical"

    def test_is_ranked_enum(self) -> None:
        from dnsight.core.types import RankedEnum

        assert issubclass(Severity, RankedEnum)
        assert issubclass(Severity, str)


class TestStatus:
    def test_members(self) -> None:
        assert Status.COMPLETED == "completed"
        assert Status.PARTIAL == "partial"
        assert Status.FAILED == "failed"
        assert Status.SKIPPED == "skipped"

    def test_member_count(self) -> None:
        assert len(Status) == 4


class TestCapability:
    def test_members(self) -> None:
        assert Capability.CHECK == "check"
        assert Capability.GENERATE == "generate"

    def test_member_count(self) -> None:
        assert len(Capability) == 2


class TestOutputFormat:
    def test_members(self) -> None:
        assert OutputFormat.RICH == "rich"
        assert OutputFormat.JSON == "json"
        assert OutputFormat.SARIF == "sarif"
        assert OutputFormat.MARKDOWN == "markdown"

    def test_member_count(self) -> None:
        assert len(OutputFormat) == 4


class TestDNSProvider:
    def test_members(self) -> None:
        assert DNSProvider.SYSTEM == "system"
        assert DNSProvider.GOOGLE == "google"
        assert DNSProvider.CLOUDFLARE == "cloudflare"
        assert DNSProvider.QUAD9 == "quad9"
        assert DNSProvider.OPENDNS == "opendns"

    def test_member_count(self) -> None:
        assert len(DNSProvider) == 5


class TestBaseEnumSubclassing:
    def test_issue_id_enum_subclass(self) -> None:
        class MyIssueId(IssueId):
            FOO = "foo-bar"

        assert isinstance(MyIssueId.FOO, IssueId)
        assert MyIssueId.FOO == "foo-bar"

    def test_recommendation_id_enum_subclass(self) -> None:
        class MyRecId(RecommendationId):
            BAZ = "baz-qux"

        assert isinstance(MyRecId.BAZ, RecommendationId)
        assert MyRecId.BAZ == "baz-qux"

    def test_base_enums_are_empty(self) -> None:
        assert len(IssueId) == 0
        assert len(RecommendationId) == 0


@pytest.mark.parametrize("enum_cls", [Status, Capability, OutputFormat, DNSProvider])
def test_str_enums_are_str_subclass(enum_cls: type[StrEnum]) -> None:
    assert issubclass(enum_cls, StrEnum)
    for member in enum_cls:
        assert isinstance(member, str)


def test_severity_is_str_subclass() -> None:
    """Severity is RankedEnum (str, Enum), not StrEnum, but still str-like."""
    for member in Severity:
        assert isinstance(member, str)
        assert str(member) == member.value


class TestRankedEnumOrdering:
    def test_ordering(self) -> None:
        assert (
            Severity.INFO
            < Severity.LOW
            < Severity.MEDIUM
            < Severity.HIGH
            < Severity.CRITICAL
        )

    def test_le_and_ge(self) -> None:
        assert Severity.LOW <= Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.LOW

    def test_eq_same_type(self) -> None:
        assert Severity.HIGH == Severity.HIGH
        assert Severity.HIGH != Severity.LOW

    def test_eq_and_ne_str(self) -> None:
        assert Severity.HIGH == "high"
        assert Severity.HIGH != "low"

    def test_compare_wrong_type_raises(self) -> None:
        from dnsight.core.types import Priority

        with pytest.raises(TypeError):
            _ = Severity.HIGH < Priority.HIGH  # type: ignore[operator]
