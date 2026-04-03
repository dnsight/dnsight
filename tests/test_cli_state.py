"""CLI :class:`GlobalState` resolution from Typer context."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

from dnsight.cli.state import GlobalState, get_cli_state
from dnsight.core.types import OutputFormat


def test_get_cli_state_raises_when_never_set() -> None:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = None
    ctx.parent = None
    with pytest.raises(typer.Exit) as excinfo:
        get_cli_state(ctx)
    assert excinfo.value.exit_code == 3


def test_get_cli_state_walks_parent_chain() -> None:
    st = GlobalState(
        config_path=Path("/x.yaml"),
        output_format=OutputFormat.RICH,
        output_path=None,
        quiet=False,
        verbose=False,
    )
    root = MagicMock(spec=typer.Context)
    root.obj = st
    root.parent = None
    child = MagicMock(spec=typer.Context)
    child.obj = None
    child.parent = root
    assert get_cli_state(child) is st
