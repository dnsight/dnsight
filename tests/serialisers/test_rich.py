"""Tests for :class:`~dnsight.serialisers.rich.RichSerialiser`."""

from __future__ import annotations

from datetime import UTC, datetime
import re

from rich.console import Console

from dnsight.core.models import CheckResult
from dnsight.core.types import Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers.rich import RichSerialiser


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;:]*m", "", s)


def test_rich_serialise_contains_domain(domain_result_nested) -> None:
    out = RichSerialiser().serialise(domain_result_nested)
    plain = _strip_ansi(out)
    assert "example.com" in plain
    assert "sub.example.com" in plain


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
    # No duplicate apex zone line after path subtitle (both were "example.com").
    assert re.search(r"(?m)^example.com$\n\n^example.com$", plain) is None
