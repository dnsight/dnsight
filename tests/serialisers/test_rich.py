"""Tests for :class:`~dnsight.serialisers.rich.RichSerialiser`."""

from __future__ import annotations

import re

from rich.console import Console

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
