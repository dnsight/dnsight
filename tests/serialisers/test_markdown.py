"""Tests for :class:`~dnsight.serialisers.markdown.MarkdownSerialiser`."""

from __future__ import annotations

from datetime import UTC, datetime

from dnsight.core.models import CheckResult
from dnsight.core.types import Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers.markdown import MarkdownSerialiser


def test_markdown_zones_and_data_summary(domain_result_nested) -> None:
    md = MarkdownSerialiser().serialise(domain_result_nested)
    assert "# Audit: example.com" in md
    assert "## `example.com`" in md
    assert "## `sub.example.com`" in md
    assert "**Partial:** yes" in md
    assert "**spf** (data)" in md
    assert "Record:" in md
    assert "Flattened:" in md
    assert "| `dmarc` |" in md


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
