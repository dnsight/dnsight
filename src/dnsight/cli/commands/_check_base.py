"""Shared helpers for per-check Typer apps (multi-domain, manifest targets, config overlay)."""

from __future__ import annotations

from pathlib import Path

import click
from click.parser import _OptionParser
import typer
from typer.core import TyperGroup

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


def _make_options_only_parser(
    command: click.Command, ctx: click.Context
) -> _OptionParser:
    """Parser with the same options as *command*, but no positional arguments."""
    from click.core import Option

    p = _OptionParser(ctx)
    for param in command.get_params(ctx):
        if isinstance(param, Option):
            param.add_to_parser(p, ctx)
    return p


def _find_subcommand_split_index(
    command: click.Command,
    ctx: click.Context,
    args: list[str],
    cmd_names: frozenset[str],
) -> int | None:
    """Return *args* index of a registered subcommand, after group-only options."""
    from click.exceptions import UsageError

    for split in range(len(args) + 1):
        pre, post = args[:split], args[split:]
        if not post or post[0] not in cmd_names:
            continue
        parser = _make_options_only_parser(command, ctx)
        try:
            _opts, largs, _order = parser.parse_args(list(pre))
        except UsageError:
            continue
        if largs:
            continue
        return split
    return None


class _SubcommandsBeforeVariadicGroup(TyperGroup):
    """Resolve subcommands before variadic callback arguments.

    Click parses the group callback's variadic :class:`~click.Argument` in the
    same pass as options, so tokens such as ``generate`` are consumed as domains
    and never reach :attr:`click.Context.invoked_subcommand`. We split argv when
    the first positional (after options) matches a registered subcommand name.
    """

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        from click.core import Command, Option
        from click.exceptions import NoArgsIsHelpError

        if not args and self.no_args_is_help and not ctx.resilient_parsing:
            raise NoArgsIsHelpError(ctx)

        cmd_names = frozenset(self.list_commands(ctx))
        if ctx.resilient_parsing or not cmd_names:
            return super().parse_args(ctx, args)

        split = _find_subcommand_split_index(self, ctx, args, cmd_names)
        if split is None:
            return super().parse_args(ctx, args)

        pre, post = args[:split], args[split:]
        saved = self.params
        saved_naih = self.no_args_is_help
        try:
            self.params = [p for p in saved if isinstance(p, Option)]
            if not pre:
                # ``Command.parse_args([], ...)`` would raise *NoArgsIsHelpError* while
                # ``no_args_is_help`` is true even though a subcommand follows in *post*.
                self.no_args_is_help = False
            Command.parse_args(self, ctx, list(pre))
        finally:
            self.no_args_is_help = saved_naih
            self.params = saved

        if self.chain:
            ctx._protected_args = post
            ctx.args = []
        else:
            ctx._protected_args, ctx.args = post[:1], post[1:]
        return ctx.args


def make_check_typer(check_name: str, *, help_text: str | None = None) -> typer.Typer:
    """Return the sub-app mounted at ``dnsight <check_name> ...``."""
    return typer.Typer(
        name=check_name,
        help=help_text or f"Run the {check_name} check.",
        no_args_is_help=True,
        cls=_SubcommandsBeforeVariadicGroup,
        context_settings={"allow_interspersed_args": True},
    )


def effective_cli_config_path(ctx: typer.Context, override: Path | None) -> Path | None:
    """Per-command ``--config`` wins; else root :class:`GlobalState` ``config_path``."""
    if override is not None:
        return override
    return config_path_for_sdk(get_cli_state(ctx))


def resolve_target_domain_strings(
    _ctx: typer.Context, domains: list[str] | None, config_path: Path | None
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
