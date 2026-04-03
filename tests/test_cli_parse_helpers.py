"""CLI CSV parsing and small helpers in :mod:`dnsight.cli.helpers` / :mod:`dnsight.cli._parse`."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from dnsight.cli._parse import parse_csv_option
from dnsight.cli.helpers import (
    checks_and_exclude_options,
    config_path_for_sdk,
    require_targets_or_domains,
    worst_exit_code,
)
from dnsight.cli.state import GlobalState
from dnsight.core.types import OutputFormat


def test_parse_csv_option_whitespace_only_is_none() -> None:
    assert parse_csv_option("   \t  ") is None


def test_parse_csv_option_strips_parts() -> None:
    assert parse_csv_option(" a , , b ") == ["a", "b"]


def test_worst_exit_code_empty_tuple() -> None:
    assert worst_exit_code() == 0


def test_checks_and_exclude_options_delegates_to_csv() -> None:
    assert checks_and_exclude_options("a,b", None) == (["a", "b"], None)
    assert checks_and_exclude_options(None, "x") == (None, ["x"])


def test_config_path_for_sdk_reads_state() -> None:
    p = Path("/tmp/x.yaml")
    st = GlobalState(
        config_path=p,
        output_format=OutputFormat.JSON,
        output_path=None,
        quiet=True,
        verbose=False,
    )
    assert config_path_for_sdk(st) == p


def test_require_targets_or_domains_exits_when_both_empty() -> None:
    with pytest.raises(typer.Exit) as excinfo:
        require_targets_or_domains([], [], hint="nothing to do")
    assert excinfo.value.exit_code == 3
