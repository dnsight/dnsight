"""Shared formatting for :class:`~dnsight.core.models.Issue` / ``Recommendation`` in human serialisers."""

from __future__ import annotations

from collections.abc import Sequence

from dnsight.core.models import Issue
from dnsight.core.types import Severity


__all__ = [
    "DEFAULT_DESCRIPTION_MAX",
    "group_consecutive_issues_by_id",
    "issue_groups_for_display",
    "raw_redundant_with_record_line",
    "truncate_finding_text",
]

DEFAULT_DESCRIPTION_MAX = 200


def truncate_finding_text(text: str, *, max_len: int, full: bool) -> str:
    """Return *text* as one line, optionally truncated (unless *full*)."""
    single = " ".join(text.splitlines())
    if full or len(single) <= max_len:
        return single
    return f"{single[: max_len - 1]}…"


def _norm_compact(value: str) -> str:
    return " ".join(value.split())


def raw_redundant_with_record_line(
    raw: str | None, summary_lines: Sequence[str]
) -> bool:
    """True when ``cr.raw`` duplicates the first ``Record:`` line from data summaries.

    The summary line may be truncated with ``…``; we treat prefix match as equivalent.
    """
    if not raw or not raw.strip():
        return False
    r = _norm_compact(raw)
    for line in summary_lines:
        stripped = line.strip()
        if not stripped.startswith("Record:"):
            continue
        body = stripped[len("Record:") :].strip()
        b = _norm_compact(body)
        if b.endswith("…"):
            prefix = b[:-1].rstrip()
            if not prefix:
                continue
            return r.startswith(prefix)
        return r == b
    return False


def group_consecutive_issues_by_id(
    issues: Sequence[Issue],
) -> list[tuple[str, list[Issue]]]:
    """Group adjacent issues with the same stable ``id`` (order preserved)."""
    if not issues:
        return []
    groups: list[tuple[str, list[Issue]]] = []
    for iss in issues:
        if not groups or groups[-1][0] != iss.id:
            groups.append((iss.id, [iss]))
        else:
            groups[-1][1].append(iss)
    return groups


class _IssueDisplayGroup:
    """One visual group: single issue or multiple with same consecutive id."""

    __slots__ = ("issues",)

    def __init__(self, issues: list[Issue]) -> None:
        self.issues = issues

    @property
    def primary(self) -> Issue:
        return self.issues[0]

    @property
    def count(self) -> int:
        return len(self.issues)


def issue_groups_for_display(issues: Sequence[Issue]) -> list[_IssueDisplayGroup]:
    """Build display groups from consecutive same-id runs."""
    return [
        _IssueDisplayGroup(list(g)) for _, g in group_consecutive_issues_by_id(issues)
    ]


def severity_label(sev: Severity) -> str:
    return str(sev.value)
