"""Tests for :mod:`dnsight.serialisers._finding_format`."""

from __future__ import annotations

from dnsight.core.models import Issue
from dnsight.core.types import Severity
from dnsight.serialisers._finding_format import (
    group_consecutive_issues_by_id,
    issue_groups_for_display,
    raw_redundant_with_record_line,
    truncate_finding_text,
)


def test_truncate_finding_text_respects_full_flag() -> None:
    s = "a" * 50
    assert len(truncate_finding_text(s, max_len=10, full=False)) == 10
    assert truncate_finding_text(s, max_len=10, full=True) == s


def test_raw_redundant_with_record_line_prefix_match() -> None:
    raw = "v=DMARC1; p=none"
    lines = ["Record: v=DMARC1; p=none"]
    assert raw_redundant_with_record_line(raw, lines) is True


def test_raw_redundant_with_truncated_record_suffix() -> None:
    raw = "v=DMARC1; p=none; long=value"
    lines = ["Record: v=DMARC1; p=none; long=val…"]
    assert raw_redundant_with_record_line(raw, lines) is True


def test_raw_not_redundant_when_no_record_line() -> None:
    assert (
        raw_redundant_with_record_line("x", ["Flattened: 1 lookups, 0 IP ranges"])
        is False
    )


def test_group_consecutive_issues_by_id_splits_on_change() -> None:
    issues = [
        Issue(
            id="a", severity=Severity.HIGH, title="t", description="1", remediation="r"
        ),
        Issue(
            id="a", severity=Severity.HIGH, title="t", description="2", remediation="r"
        ),
        Issue(
            id="b", severity=Severity.LOW, title="u", description="3", remediation="r"
        ),
    ]
    groups = group_consecutive_issues_by_id(issues)
    assert [g[0] for g in groups] == ["a", "b"]
    assert len(groups[0][1]) == 2
    assert len(groups[1][1]) == 1


def test_issue_groups_for_display_wraps_lists() -> None:
    i = Issue(
        id="x", severity=Severity.INFO, title="t", description="d", remediation="r"
    )
    groups = issue_groups_for_display([i])
    assert len(groups) == 1
    assert groups[0].count == 1
    assert groups[0].primary.id == "x"
