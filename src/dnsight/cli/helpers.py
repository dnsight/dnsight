"""Small CLI helpers: Typer Argument/Option factories and shared utilities.

**Normative CLI style:** Every Typer parameter uses :class:`typing.Annotated` with
``typer.Option`` / ``typer.Argument`` metadata (Typer ≥ 0.24). This module defines
factory functions that return ``ArgumentInfo`` / ``OptionInfo`` and ``TypeAlias``
names such as ``DomainsArg`` for use in command signatures. Prefer adding new
shared CLI shapes here (or re-exporting them from ``cli/annotations.py``) rather
than using ``name: T = typer.Option(...)`` as the parameter default.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Never, TypeAlias, cast

import typer
from typer.models import ArgumentInfo, OptionInfo

from dnsight.cli._completion_common import complete_config_discovery_paths
from dnsight.cli._parse import parse_csv_option
from dnsight.cli.state import GlobalState
from dnsight.sdk.audit.models import AuditResult, DomainResult


def domains_argument() -> ArgumentInfo:
    """Optional variadic domains (omit → manifest / discovery path for batch-style commands).

    Default is set on the command parameter (``= None``); do not pass a default into
    :func:`typer.Argument` when using :class:`typing.Annotated` (Typer ≥ 0.24).
    """
    return cast(
        ArgumentInfo,
        typer.Argument(
            show_default=False,
            help="One or more domains; omit to use config manifest targets.",
        ),
    )


DomainsArg: TypeAlias = Annotated[list[str] | None, domains_argument()]  # NOSONAR S6794


def recursive_option() -> OptionInfo:
    """``--recursive`` / ``-r`` (shared audit-style recursion flag).

    Use ``recursive: RecursiveOpt = False``; do not pass ``False`` into
    :func:`typer.Option` inside :class:`typing.Annotated` (Typer ≥ 0.24).
    """
    return cast(
        OptionInfo,
        typer.Option("--recursive", "-r", help="Recursively audit child zones."),
    )


RecursiveOpt: TypeAlias = Annotated[bool, recursive_option()]  # NOSONAR S6794


def depth_option() -> OptionInfo:
    """``--depth`` / ``-d`` (maximum recursion depth).

    Set the numeric default on the command (e.g. ``depth: DepthOpt = 3``).
    """
    return cast(
        OptionInfo,
        typer.Option("--depth", "-d", min=0, help="Maximum depth of recursive audit."),
    )


DepthOpt: TypeAlias = Annotated[int, depth_option()]  # NOSONAR S6794


def check_command_config_path_option() -> OptionInfo:
    """Per-check ``--config`` override (same path semantics as root ``--config``)."""
    return cast(
        OptionInfo,
        typer.Option(
            "--config",
            help="YAML path (overrides global --config for this command).",
            exists=False,
            file_okay=True,
            dir_okay=False,
            resolve_path=True,
            autocompletion=complete_config_discovery_paths,
        ),
    )


CheckCommandConfigPath: TypeAlias = Annotated[  # NOSONAR S6794
    Path | None, check_command_config_path_option()
]


def config_source_argument() -> ArgumentInfo:
    """Config file path, ``-`` for stdin, or omit for ``--config`` / discovery."""
    return cast(
        ArgumentInfo,
        typer.Argument(
            show_default=False,
            help="YAML file path, '-' for stdin, or omit for --config / discovery.",
            autocompletion=complete_config_discovery_paths,
        ),
    )


ConfigSourceArg: TypeAlias = Annotated[
    str | None, config_source_argument()
]  # NOSONAR S6794


def resolve_targets_option() -> OptionInfo:
    """``--resolve``: resolve each manifest target after load."""
    return cast(
        OptionInfo,
        typer.Option("--resolve", help="Resolve each manifest target after load."),
    )


ResolveTargetsOpt: TypeAlias = Annotated[
    bool, resolve_targets_option()
]  # NOSONAR S6794


def cli_exit_fatal(message: str, *, code: int = 3) -> Never:
    """Print *message* to stderr and exit with *code* (default fatal CLI code 3)."""
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code)


def domains_from_argument(domains: list[str] | None) -> list[str]:
    """Normalise optional variadic domains to a list (empty means manifest / discovery path)."""
    return domains or []


def checks_and_exclude_options(
    checks: str | None, exclude: str | None
) -> tuple[list[str] | None, list[str] | None]:
    """Parse ``--checks`` / ``--exclude`` comma strings for SDK kwargs."""
    return parse_csv_option(checks), parse_csv_option(exclude)


def config_path_for_sdk(state: GlobalState) -> Path | None:
    """``config_path=`` value for :mod:`dnsight.sdk.run` entrypoints."""
    return state.config_path


def worst_exit_code(*codes: int) -> int:
    """Return the highest exit code in ``{0,1,2}`` passed (empty → 0)."""
    if not codes:
        return 0
    return max(codes)


def require_targets_or_domains(
    domains: list[str], results: list[DomainResult] | AuditResult, *, hint: str
) -> None:
    """If there are no *domains* and *results* is empty, exit fatally with *hint*."""
    empty = (
        len(results.domains) == 0
        if isinstance(results, AuditResult)
        else len(results) == 0
    )
    if not domains and empty:
        cli_exit_fatal(hint)


__all__ = [
    "CheckCommandConfigPath",
    "ConfigSourceArg",
    "DepthOpt",
    "DomainsArg",
    "RecursiveOpt",
    "ResolveTargetsOpt",
    "check_command_config_path_option",
    "checks_and_exclude_options",
    "cli_exit_fatal",
    "config_path_for_sdk",
    "config_source_argument",
    "depth_option",
    "domains_argument",
    "domains_from_argument",
    "recursive_option",
    "require_targets_or_domains",
    "resolve_targets_option",
    "worst_exit_code",
]
