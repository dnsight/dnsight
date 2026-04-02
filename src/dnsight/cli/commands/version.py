"""``dnsight version`` command."""

from __future__ import annotations

import typer

import dnsight


__all__ = ["register_version", "version_cmd"]


def version_cmd() -> None:
    """Print the package version."""
    typer.echo(f"dnsight {dnsight.__version__}")
    raise typer.Exit(0)


def register_version(app: typer.Typer) -> None:
    """Attach the ``version`` command to *app*."""

    @app.command("version", help="Show the dnsight version and exit.")
    def _version_cmd() -> None:
        version_cmd()
