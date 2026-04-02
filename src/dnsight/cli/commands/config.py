"""``dnsight config`` command group."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml

import dnsight
from dnsight.cli.helpers import (
    ConfigSourceArg,
    ResolveTargetsOpt,
    cli_exit_fatal,
    config_path_for_sdk,
)
from dnsight.cli.state import get_cli_state
from dnsight.core.config import (
    config_manager_from_file,
    config_manager_from_mapping,
    discover_config_path,
)
from dnsight.core.exceptions import ConfigError


__all__ = ["register_config"]


_EXAMPLES_PATH = (
    Path(dnsight.__file__).resolve().parent
    / "core"
    / "config"
    / "parser"
    / "versions"
    / "examples"
)


def _example_v1_path() -> Path:
    return _EXAMPLES_PATH / "v1.yaml"


def _resolve_config_source(ctx: typer.Context, source: str | None) -> Path | None:
    """Return a file path to load, or ``None`` if stdin (``-``)."""
    if source is not None:
        stripped = source.strip()
        if stripped == "-":
            return None
        if stripped:
            return Path(stripped)
    state = get_cli_state(ctx)
    path = config_path_for_sdk(state)
    if path is not None:
        return Path(path)
    return discover_config_path()


def register_config(app: typer.Typer) -> None:
    """Attach the ``config`` command group to *app*."""
    t = typer.Typer(
        name="config",
        help="Inspect and validate dnsight configuration.",
        no_args_is_help=True,
    )

    @t.command("validate", help="Validate a dnsight configuration file.")
    def validate_cmd(
        ctx: typer.Context,
        source: ConfigSourceArg = None,
        *,
        resolve_targets: ResolveTargetsOpt = False,
    ) -> None:
        """Load and validate dnsight YAML (same rules as the SDK)."""
        stdin_mode = source is not None and source.strip() == "-"
        path = None if stdin_mode else _resolve_config_source(ctx, source)

        try:
            if stdin_mode:
                raw = typer.get_text_stream("stdin").read()
                data = yaml.safe_load(raw)
                mgr = config_manager_from_mapping(data)
            else:
                if path is None:
                    cli_exit_fatal(
                        "no config path (pass a file, '-' for stdin, "
                        "or use global --config / dnsight.yaml discovery)."
                    )
                mgr = config_manager_from_file(path)
        except yaml.YAMLError as e:
            cli_exit_fatal(f"invalid YAML ({e}).")
        except ConfigError as e:
            cli_exit_fatal(str(e))

        if resolve_targets:
            for t in mgr.targets:
                mgr.resolve(mgr.target_string(t))

        typer.echo("Config validated successfully.")
        raise typer.Exit(0)

    @t.command("example", help="Print a sample dnsight configuration file.")
    def example_cmd() -> None:
        """Print a sample dnsight configuration file. Currently only v1."""
        p = _example_v1_path()
        typer.echo(p.read_text(encoding="utf-8"))
        raise typer.Exit(0)

    @t.command(
        "migrate", help="Migrate a dnsight configuration file to the latest version."
    )
    def migrate_cmd() -> None:
        """Reserved for future config version migrations."""
        typer.echo("No migrations are available.", err=True)
        raise typer.Exit(0)

    app.add_typer(t)
