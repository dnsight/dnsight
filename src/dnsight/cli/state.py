"""Shared CLI context (global options, shared state)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import typer

from dnsight.core.types import OutputFormat


__all__ = ["GlobalState", "get_cli_state"]


@dataclass(frozen=True)
class GlobalState:
    """Options from the root ``dnsight`` callback, available to subcommands."""

    config_path: Path | None
    output_format: OutputFormat
    output_path: Path | None
    quiet: bool
    verbose: bool


def get_cli_state(ctx: typer.Context) -> GlobalState:
    """Return :class:`GlobalState` from the nearest context that set ``obj``."""
    c: typer.Context | None = ctx
    while c is not None:
        if isinstance(c.obj, GlobalState):
            return c.obj
        c = cast(typer.Context | None, c.parent)
    typer.echo(
        "Error: CLI state was not initialised (missing root callback?).", err=True
    )
    raise typer.Exit(3)
