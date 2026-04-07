"""Tests for :mod:`dnsight.cli._completion_common`."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from dnsight.cli._completion_common import (
    complete_config_discovery_paths,
    complete_output_format,
    complete_with_csv_suffix,
    current_csv_token,
    prefix_choices,
)
from dnsight.core.config import defaults
from dnsight.core.schema.dkim import DkimSchema
from dnsight.core.schema.dnssec import DnssecSchema


def test_current_csv_token() -> None:
    assert current_csv_token("dmarc, s") == "s"
    assert current_csv_token("  foo  ") == "foo"
    assert current_csv_token("") == ""


def test_prefix_choices_case_insensitive() -> None:
    assert prefix_choices("j", ("json", "junk")) == ["json", "junk"]
    assert prefix_choices("J", ("json",)) == ["json"]
    assert prefix_choices("", ("a", "b")) == ["a", "b"]


def test_complete_with_csv_suffix() -> None:
    assert complete_with_csv_suffix("dmarc,", ("spf",)) == ["dmarc,spf"]
    out = complete_with_csv_suffix("d", ("dmarc", "dnssec"))
    assert out == ["dmarc", "dnssec"]


def test_dkim_common_selector_suggestions_match_defaults() -> None:
    assert (
        DkimSchema.COMMON_SELECTOR_SUGGESTIONS == defaults.DEFAULT_DKIM_COMMON_SELECTORS
    )


def test_dkim_weak_algorithm_csv_completion() -> None:
    out = complete_with_csv_suffix("sha", DkimSchema.WEAK_ALGORITHM_COMPLETION_HINTS)
    assert "sha1" in out


def test_dnssec_weak_algorithm_hints_cover_numbers_and_names() -> None:
    hints = DnssecSchema.WEAK_ALGORITHM_COMPLETION_HINTS
    assert "1" in hints and "RSAMD5" in hints
    out = complete_with_csv_suffix("RSA", hints)
    assert any("RSA" in x for x in out)


def test_complete_output_format() -> None:
    assert "json" in complete_output_format(Mock(), "j")


def test_complete_config_discovery_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "proj"
    sub = root / "pkg"
    sub.mkdir(parents=True)
    (root / "dnsight.yaml").write_text("version: 1\n", encoding="utf-8")
    monkeypatch.chdir(sub)
    got = complete_config_discovery_paths(Mock(), str(root.resolve()))
    assert got
    assert any("dnsight.yaml" in p for p in got)
