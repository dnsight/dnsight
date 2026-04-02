"""Shared helpers for per-check Typer apps (multi-domain, manifest targets, config overlay)."""

from __future__ import annotations

from pathlib import Path

import typer

from dnsight.cli.helpers import (
    cli_exit_fatal,
    config_path_for_sdk,
    domains_from_argument,
    worst_exit_code,
)
from dnsight.cli.output import emit_check_result
from dnsight.cli.state import get_cli_state
from dnsight.core.config import Config, config_manager_from_file, discover_config_path
from dnsight.core.exceptions import ConfigError
from dnsight.sdk.run import run_check_sync
from dnsight.serialisers import SerialiserOptions


def make_check_typer(check_name: str, *, help_text: str | None = None) -> typer.Typer:
    """Return the sub-app mounted at ``dnsight <check_name> ...``."""
    return typer.Typer(
        name=check_name,
        help=help_text or f"Run the {check_name} check.",
        no_args_is_help=True,
    )


def effective_cli_config_path(ctx: typer.Context, override: Path | None) -> Path | None:
    """Per-command ``--config`` wins; else root :class:`GlobalState` ``config_path``."""
    if override is not None:
        return override
    return config_path_for_sdk(get_cli_state(ctx))


def resolve_target_domain_strings(
    ctx: typer.Context, domains: list[str] | None, config_path: Path | None
) -> list[str]:
    """Explicit domains, or manifest targets from YAML when *domains* is omitted."""
    domain_list = domains_from_argument(domains)
    if domain_list:
        return domain_list
    path = config_path
    if path is None:
        discovered = discover_config_path()
        path = discovered
    if path is None:
        cli_exit_fatal(
            "no domains given and no config file (pass domain(s) and/or use "
            "--config / global --config / dnsight.yaml discovery for manifest mode)."
        )
    mgr = config_manager_from_file(path)
    if not mgr.targets:
        cli_exit_fatal(
            "no domains given and config has no targets (pass domain(s) or add "
            "`targets` to dnsight.yaml)."
        )
    return [mgr.target_string(t) for t in mgr.targets]


def run_check_sequence(
    ctx: typer.Context,
    check_name: str,
    targets: list[str],
    *,
    config_path: Path | None,
    program_config: Config | None,
    serialiser_options: SerialiserOptions | None = None,
) -> None:
    """Run one check per target; emit results; exit with the worst outcome code."""
    state = get_cli_state(ctx)
    opts = serialiser_options or SerialiserOptions()
    codes: list[int] = []
    for domain in targets:
        try:
            result = run_check_sync(
                check_name, domain, config_path=config_path, config=program_config
            )
        except ConfigError as e:
            cli_exit_fatal(str(e))
        codes.append(
            emit_check_result(
                state,
                result,
                domain=domain,
                check_name=check_name,
                serialiser_options=opts,
            )
        )
    raise typer.Exit(worst_exit_code(*codes))


__all__ = [
    "effective_cli_config_path",
    "make_check_typer",
    "resolve_target_domain_strings",
    "run_check_sequence",
]
