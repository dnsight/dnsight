"""``dnsight docs`` command."""

from __future__ import annotations

import typer

from dnsight.cli.urls import DOCUMENTATION_SITE_URL


__all__ = ["register_docs"]


def register_docs(app: typer.Typer) -> None:
    """Attach the ``docs`` command to *app*."""

    @app.command(
        "docs", help="Print the documentation site URL (MkDocs / GitHub Pages)."
    )
    def _docs_cmd() -> None:
        typer.echo(DOCUMENTATION_SITE_URL)
