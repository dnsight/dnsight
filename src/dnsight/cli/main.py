"""DNSight CLI entrypoint."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, TypeAlias

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


def _version_option_callback(value: bool) -> None:
    if value:
        version_cmd()


ConfigPathOpt: TypeAlias = Annotated[
    Path | None,
    typer.Option(
        "--config",
        help="Path to dnsight.yaml (default: discover from CWD).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        autocompletion=complete_config_discovery_paths,
    ),
]

OutputFormatOpt: TypeAlias = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        "-f",
        help="Output format: rich, json, sarif, markdown.",
        case_sensitive=False,
        autocompletion=complete_output_format,
    ),
]

OutputPathOpt: TypeAlias = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help="Write serialised results to this file instead of stdout.",
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        writable=True,
    ),
]

QuietOpt: TypeAlias = Annotated[
    bool,
    typer.Option(
        "--quiet",
        "-q",
        help="Diagnostics only at ERROR on stderr (suppresses INFO/DEBUG). "
        "Audit output is unchanged. Wins over --verbose.",
    ),
]

VerboseOpt: TypeAlias = Annotated[
    bool,
    typer.Option(
        "--verbose",
        "-v",
        help="DEBUG logging on stderr with source paths and Rich tracebacks. "
        "Ignored if --quiet is set.",
    ),
]

VersionOpt: TypeAlias = Annotated[
    bool,
    typer.Option(
        "--version",
        help="Show the dnsight version and exit.",
        callback=_version_option_callback,
        is_eager=True,
    ),
]

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
    config: ConfigPathOpt = None,
    output_format: OutputFormatOpt = OutputFormat.RICH,
    output_path: OutputPathOpt = None,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    version: VersionOpt = False,
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
