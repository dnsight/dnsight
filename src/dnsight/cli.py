"""CLI entrypoint for dnsight."""

from rich.console import Console
import typer

from dnsight import __version__


__all__ = ["app", "main"]


app = typer.Typer(
    name="dnsight",
    help="DNS, email, and web security hygiene toolkit.",
    no_args_is_help=True,
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"dnsight version: {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    # This uses callback pattern
    pass
