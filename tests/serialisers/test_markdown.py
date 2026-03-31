"""Tests for :class:`~dnsight.serialisers.markdown.MarkdownSerialiser`."""

from __future__ import annotations

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
