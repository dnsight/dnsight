"""DNSight CLI entrypoint."""

from __future__ import annotations

import logging
from pathlib import Path

import click.exceptions
import typer

from dnsight.cli._completion_common import (
    complete_config_discovery_paths,
    complete_output_format,
)
from dnsight.cli.commands import register_commands, version_cmd
from dnsight.cli.state import GlobalState
from dnsight.core.logger import configure
from dnsight.core.types import OutputFormat


__all__ = ["app"]

# This line modifies the exit code for Click's NoArgsIsHelpError when "no_args_is_help=True" is active.
click.exceptions.NoArgsIsHelpError.exit_code = 0


_CONFIG_CLI = typer.Option(
    None,
    "--config",
    help="Path to dnsight.yaml (default: discover from CWD).",
    exists=True,
    file_okay=True,
    dir_okay=False,
    resolve_path=True,
    autocompletion=complete_config_discovery_paths,
)

_FORMAT_CLI = typer.Option(
    OutputFormat.RICH,
    "--format",
    "-f",
    help="Output format: rich, json, sarif, markdown.",
    case_sensitive=False,
    autocompletion=complete_output_format,
)

_OUTPUT_CLI = typer.Option(
    None,
    "--output",
    "-o",
    help="Write serialised results to this file instead of stdout.",
    file_okay=True,
    dir_okay=False,
    resolve_path=True,
    writable=True,
)

_QUIET_CLI = typer.Option(
    False,
    "--quiet",
    "-q",
    help="Diagnostics only at ERROR on stderr (suppresses INFO/DEBUG). "
    "Audit output is unchanged. Wins over --verbose.",
)

_VERBOSE_CLI = typer.Option(
    False,
    "--verbose",
    "-v",
    help="DEBUG logging on stderr with source paths and Rich tracebacks. "
    "Ignored if --quiet is set.",
)


def _version_option_callback(value: bool) -> None:
    if value:
        version_cmd()


_VERSION_CLI = typer.Option(
    False,
    "--version",
    help="Show the dnsight version and exit.",
    callback=_version_option_callback,
    is_eager=True,
)

_APP_HELP = """\
Audit DNS, email authentication (SPF, DKIM, DMARC), and related security signals.
Run a full audit with the audit command, a single check (e.g. dmarc, spf), or
inspect configuration. Global options below apply before the subcommand.
Use dnsight COMMAND --help for command-specific options (domains, --config, etc.).
"""

app = typer.Typer(name="dnsight", help=_APP_HELP, no_args_is_help=True)


@app.callback()
def _main(
    ctx: typer.Context,
    *,
    config: Path | None = _CONFIG_CLI,
    output_format: OutputFormat = _FORMAT_CLI,
    output_path: Path | None = _OUTPUT_CLI,
    quiet: bool = _QUIET_CLI,
    verbose: bool = _VERBOSE_CLI,
    version: bool = _VERSION_CLI,
) -> None:
    _ = version
    if quiet:
        configure(
            logging.ERROR, use_rich=True, detailed_log=False, rich_tracebacks=False
        )
    elif verbose:
        configure(logging.DEBUG, use_rich=True, detailed_log=True, rich_tracebacks=True)
    else:
        configure(
            logging.INFO, use_rich=True, detailed_log=False, rich_tracebacks=False
        )
    ctx.obj = GlobalState(
        config_path=config,
        output_format=output_format,
        output_path=output_path,
        quiet=quiet,
        verbose=verbose,
    )


register_commands(app)
