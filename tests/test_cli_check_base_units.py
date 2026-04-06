"""Direct tests for :mod:`dnsight.cli.commands._check_base` helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from dnsight.cli.commands import _check_base as cb
from dnsight.cli.helpers import DomainsArg
from dnsight.cli.state import GlobalState
from dnsight.core.exceptions import ConfigError
from dnsight.core.types import OutputFormat


def test_make_check_typer_custom_help() -> None:
    t = cb.make_check_typer("probe", help_text="custom probe help")
    assert t.info.name == "probe"
    assert "custom probe help" in (t.info.help or "")


def test_make_check_typer_dispatches_named_subcommand_before_variadic_domains() -> None:
    """Regression: variadic domains on the group callback must not eat subcommands."""
    t = cb.make_check_typer("probe")

    @t.callback(invoke_without_command=True)
    def _cb(ctx: typer.Context, domains: DomainsArg = None) -> None:
        if ctx.invoked_subcommand is not None:
            return
        raise AssertionError(f"expected subcommand, got domains={domains!r}")

    @t.command("generate", no_args_is_help=True)
    def _gen() -> None:
        typer.echo("gen-ok")

    r = CliRunner().invoke(t, ["generate"], catch_exceptions=False)
    assert r.exit_code == 0
    assert "gen-ok" in r.stdout

    r2 = CliRunner().invoke(
        t, ["--help"], catch_exceptions=False
    )  # group help, not AssertionError
    assert r2.exit_code == 0


def test_effective_cli_config_path_override_wins() -> None:
    ctx = MagicMock(spec=typer.Context)
    override = Path("/override.yaml")
    assert cb.effective_cli_config_path(ctx, override) == override


def test_effective_cli_config_path_falls_back_to_global_state() -> None:
    st = GlobalState(
        config_path=Path("/global.yaml"),
        output_format=OutputFormat.JSON,
        output_path=None,
        quiet=True,
        verbose=False,
        output_detail=False,
        markdown_data_preview=False,
    )
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = st
    ctx.parent = None
    assert cb.effective_cli_config_path(ctx, None) == Path("/global.yaml")


def test_run_check_sequence_config_error_is_fatal() -> None:
    ctx = MagicMock(spec=typer.Context)
    st = GlobalState(
        config_path=None,
        output_format=OutputFormat.JSON,
        output_path=None,
        quiet=True,
        verbose=False,
        output_detail=False,
        markdown_data_preview=False,
    )
    ctx.obj = st
    ctx.parent = None
    with (
        patch.object(cb, "run_check_sync", side_effect=ConfigError("bad yaml")),
        pytest.raises(typer.Exit) as ei,
    ):
        cb.run_check_sequence(
            ctx, "dmarc", ["example.com"], config_path=None, program_config=None
        )
    assert ei.value.exit_code == 3
