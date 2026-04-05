"""Tests for :class:`~dnsight.serialisers.markdown.MarkdownSerialiser`."""

from __future__ import annotations

from datetime import UTC, datetime

from dnsight.core.models import CheckResult, Issue, Recommendation
from dnsight.core.types import Severity, Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers.base import SerialiserOptions
from dnsight.serialisers.markdown import MarkdownSerialiser


def test_markdown_zones_and_data_summary(domain_result_nested) -> None:
    md = MarkdownSerialiser().serialise(domain_result_nested)
    assert "# Audit: example.com" in md
    assert "## `example.com`" in md
    assert "## `sub.example.com`" in md
    assert "**Partial:** yes" in md
    assert "| Check | Status | Summary |" in md
    assert "### `spf`" in md
    assert "**Data**" in md
    assert "Record:" in md
    assert "Flattened:" in md
    assert "| `dmarc` |" in md
    assert "**Issues**" in md
    assert "test.issue" in md
    assert "Description" in md
    assert "**Error**" in md
    assert "DNS timeout" in md


def test_markdown_shows_target_when_not_apex_only() -> None:
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
    md = MarkdownSerialiser().serialise(dr)
    assert "# Audit: example.com" in md
    assert "**Target:** example.com/app" in md
    assert "(target `example.com/app`)" in md


def test_markdown_summary_cell_shows_error_and_severity_counts() -> None:
    z = ZoneResult(
        zone="x.test",
        results={
            "mx": CheckResult[object](
                status=Status.FAILED,
                error="PTR missing",
                issues=[
                    Issue(
                        id="mx.ptr",
                        severity=Severity.MEDIUM,
                        title="PTR",
                        description="d",
                        remediation="r",
                    )
                ],
            )
        },
    )
    dr = DomainResult(
        domain="x.test",
        target="x.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=True,
    )
    md = MarkdownSerialiser().serialise(dr)
    assert "Error: PTR missing" in md
    assert "`medium`×1" in md
    assert "```text" in md
    assert "PTR missing" in md


def test_markdown_groups_consecutive_same_issue_id() -> None:
    z = ZoneResult(
        zone="d.test",
        results={
            "dkim": CheckResult[object](
                status=Status.COMPLETED,
                issues=[
                    Issue(
                        id="dkim.selector.not_found",
                        severity=Severity.MEDIUM,
                        title="DKIM TXT not found",
                        description="No TXT at s1._domainkey.d.test (selector 's1').",
                        remediation="Publish",
                    ),
                    Issue(
                        id="dkim.selector.not_found",
                        severity=Severity.MEDIUM,
                        title="DKIM TXT not found",
                        description="No TXT at s2._domainkey.d.test (selector 's2').",
                        remediation="Publish",
                    ),
                ],
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
    md = MarkdownSerialiser().serialise(dr)
    assert "(×2)" in md
    assert "s1._domainkey" in md
    assert "s2._domainkey" in md


def test_markdown_output_detail_shows_remediation() -> None:
    issue = Issue(
        id="x.y",
        severity=Severity.LOW,
        title="T",
        description="Long description here.",
        remediation="Do the thing.",
    )
    z = ZoneResult(
        zone="z.test",
        results={"c": CheckResult[object](status=Status.COMPLETED, issues=[issue])},
    )
    dr = DomainResult(
        domain="z.test",
        target="z.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    md_short = MarkdownSerialiser().serialise(
        dr, options=SerialiserOptions(human_finding_detail=False)
    )
    md_long = MarkdownSerialiser().serialise(
        dr, options=SerialiserOptions(human_finding_detail=True)
    )
    assert "Remediation:" not in md_short
    assert "Remediation: Do the thing." in md_long


def test_markdown_recommendation_section() -> None:
    rec = Recommendation(id="rec.sample", title="Improve", description="More detail.")
    z = ZoneResult(
        zone="r.test",
        results={
            "hdr": CheckResult[object](status=Status.COMPLETED, recommendations=[rec])
        },
    )
    dr = DomainResult(
        domain="r.test",
        target="r.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    md = MarkdownSerialiser().serialise(dr)
    assert "**Recommendations**" in md
    assert "rec.sample" in md
    assert "More detail." in md


def test_markdown_generic_data_preview_when_no_typed_summary() -> None:
    z = ZoneResult(
        zone="g.test",
        results={
            "probe": CheckResult[object](
                status=Status.COMPLETED, data={"foo": 1, "bar": "hello"}
            )
        },
    )
    dr = DomainResult(
        domain="g.test",
        target="g.test",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=0,
        zones=[z],
        partial=False,
    )
    md_on = MarkdownSerialiser().serialise(
        dr, options=SerialiserOptions(human_data_preview=True)
    )
    md_off = MarkdownSerialiser().serialise(
        dr, options=SerialiserOptions(human_data_preview=False)
    )
    assert "foo:" in md_on
    assert "bar:" in md_on
    assert "foo:" not in md_off
