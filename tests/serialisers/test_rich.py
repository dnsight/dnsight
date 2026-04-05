"""Tests for :class:`~dnsight.serialisers.rich.RichSerialiser`."""

from __future__ import annotations

from datetime import UTC, datetime
import re

from rich.console import Console

from dnsight.core.models import CheckResult, Issue, Recommendation
from dnsight.core.types import Severity, Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers.base import SerialiserOptions
from dnsight.serialisers.rich import RichSerialiser


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;:]*m", "", s)


def test_rich_serialise_contains_domain(domain_result_nested) -> None:
    out = RichSerialiser().serialise(domain_result_nested)
    plain = _strip_ansi(out)
    assert "example.com" in plain
    assert "sub.example.com" in plain
    assert "Description" in plain


def test_rich_serialise_live_with_record_console(domain_result_nested) -> None:
    console = Console(record=True, width=120)
    RichSerialiser().serialise_live(domain_result_nested, console=console)
    plain = _strip_ansi(console.export_text(clear=False))
    assert "example.com" in plain


def test_rich_single_audit_shows_target_row_when_not_apex_only() -> None:
    z = ZoneResult(
        zone="example.com",
        results={"dmarc": CheckResult[object](status=Status.COMPLETED)},
    )
    dr = DomainResult(
        domain="example.com",
        target="example.com/app",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=1,
        zones=[z],
        partial=False,
    )
    out = RichSerialiser().serialise(dr)
    plain = _strip_ansi(out)
    assert "Target" in plain
    assert "example.com/app" in plain


def test_rich_batch_groups_same_apex_under_one_header() -> None:
    ts = datetime(2025, 1, 1, tzinfo=UTC)
    z = ZoneResult(
        zone="example.com",
        results={"dmarc": CheckResult[object](status=Status.COMPLETED)},
    )
    root = DomainResult(
        domain="example.com",
        target="example.com",
        timestamp=ts,
        config_version=1,
        zones=[z],
        partial=False,
    )
    app = DomainResult(
        domain="example.com",
        target="example.com/app",
        timestamp=ts,
        config_version=1,
        zones=[z],
        partial=True,
    )
    out = RichSerialiser().serialise([root, app])
    plain = _strip_ansi(out)
    assert plain.count("dnsight audit") == 1
    assert "example.com" in plain
    assert "example.com/app" in plain
    assert re.search(r"(?m)^example.com$\n\n^example.com$", plain) is None


def test_rich_omits_raw_when_same_as_record_summary() -> None:
    record = "v=DMARC1; p=reject"
    z = ZoneResult(
        zone="d.test",
        results={
            "dmarc": CheckResult[object](
                status=Status.COMPLETED, raw=record, data={"raw_record": record}
            )
        },
    )
    dr = DomainResult(
        domain="d.test",
        target="d.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    plain = _strip_ansi(RichSerialiser().serialise(dr))
    assert "Record:" in plain or "v=DMARC1" in plain
    assert plain.count("v=DMARC1; p=reject") == 1


def test_rich_recommendation_shows_id() -> None:
    rec = Recommendation(
        id="dnssec.enable", title="Enable DNSSEC", description="Turn it on."
    )
    z = ZoneResult(
        zone="e.test",
        results={
            "dnssec": CheckResult[object](
                status=Status.COMPLETED, recommendations=[rec]
            )
        },
    )
    dr = DomainResult(
        domain="e.test",
        target="e.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    plain = _strip_ansi(RichSerialiser().serialise(dr))
    assert "dnssec.enable" in plain
    assert "Turn it on." in plain


def test_rich_issue_group_shows_count() -> None:
    issues = [
        Issue(
            id="dup.id",
            severity=Severity.MEDIUM,
            title="Same",
            description="First",
            remediation="r",
        ),
        Issue(
            id="dup.id",
            severity=Severity.MEDIUM,
            title="Same",
            description="Second",
            remediation="r",
        ),
    ]
    z = ZoneResult(
        zone="c.test",
        results={"x": CheckResult[object](status=Status.COMPLETED, issues=issues)},
    )
    dr = DomainResult(
        domain="c.test",
        target="c.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    plain = _strip_ansi(RichSerialiser().serialise(dr))
    assert "×2" in plain
    assert "First" in plain
    assert "Second" in plain


def test_rich_human_finding_detail_shows_remediation() -> None:
    issue = Issue(
        id="i",
        severity=Severity.LOW,
        title="T",
        description="D",
        remediation="Fix this way.",
    )
    z = ZoneResult(
        zone="f.test",
        results={"y": CheckResult[object](status=Status.COMPLETED, issues=[issue])},
    )
    dr = DomainResult(
        domain="f.test",
        target="f.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    short = _strip_ansi(
        RichSerialiser().serialise(
            dr, options=SerialiserOptions(human_finding_detail=False)
        )
    )
    long = _strip_ansi(
        RichSerialiser().serialise(
            dr, options=SerialiserOptions(human_finding_detail=True)
        )
    )
    assert "Remediation:" not in short
    assert "Remediation: Fix this way." in long


def test_rich_completed_clean_check_shows_no_findings_line() -> None:
    z = ZoneResult(
        zone="clean.test",
        results={"headers": CheckResult[object](status=Status.COMPLETED)},
    )
    dr = DomainResult(
        domain="clean.test",
        target="clean.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    plain = _strip_ansi(RichSerialiser().serialise(dr))
    assert "No issues or recommendations." in plain


def test_rich_long_summary_line_folds_when_console_narrow() -> None:
    long_txt = "x" * 200
    z = ZoneResult(
        zone="wrap.test",
        results={
            "dmarc": CheckResult[object](
                status=Status.COMPLETED, data={"raw_record": long_txt}
            )
        },
    )
    dr = DomainResult(
        domain="wrap.test",
        target="wrap.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    plain = _strip_ansi(RichSerialiser().serialise(dr))
    assert "Record:" in plain
    assert plain.count("\n") >= 3


def test_rich_inserts_space_between_issues_and_recommendations() -> None:
    issue = Issue(
        id="i.one",
        severity=Severity.MEDIUM,
        title="Problem",
        description="Details.",
        remediation="Fix.",
    )
    rec = Recommendation(id="r.one", title="Hint", description="Do more.")
    z = ZoneResult(
        zone="gap.test",
        results={
            "c": CheckResult[object](
                status=Status.COMPLETED, issues=[issue], recommendations=[rec]
            )
        },
    )
    dr = DomainResult(
        domain="gap.test",
        target="gap.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    plain = _strip_ansi(RichSerialiser().serialise(dr))
    idx_problem = plain.find("Problem")
    idx_arrow = plain.find("↳")
    assert idx_problem != -1 and idx_arrow != -1
    gap = plain[idx_problem:idx_arrow]
    assert gap.count("\n") >= 3
