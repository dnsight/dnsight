"""``dnsight dkim`` — DKIM check."""

from __future__ import annotations

from typing import Annotated, TypeAlias

import typer

from dnsight.cli._completion_common import complete_with_csv_suffix
from dnsight.cli._parse import parse_csv_option
from dnsight.cli.commands._check_base import (
    effective_cli_config_path,
    make_check_typer,
    resolve_target_domain_strings,
    run_check_sequence,
)
from dnsight.cli.helpers import CheckCommandConfigPath, DomainsArg
from dnsight.core.config import Config, DkimConfig
from dnsight.core.schema.dkim import DkimSchema


__all__ = ["register_dkim"]


def _complete_dkim_selectors(ctx: typer.Context, incomplete: str | None) -> list[str]:
    _ = ctx
    return complete_with_csv_suffix(incomplete, DkimSchema.COMMON_SELECTOR_SUGGESTIONS)


def _complete_dkim_disallowed(ctx: typer.Context, incomplete: str | None) -> list[str]:
    _ = ctx
    return complete_with_csv_suffix(
        incomplete, DkimSchema.WEAK_ALGORITHM_COMPLETION_HINTS
    )


DkimSelectorsOpt: TypeAlias = Annotated[
    str | None,
    typer.Option(
        "--selectors",
        help="Comma-separated DKIM selectors to try first.",
        autocompletion=_complete_dkim_selectors,
    ),
]

DkimDisallowedAlgorithmsOpt: TypeAlias = Annotated[
    str | None,
    typer.Option(
        "--disallowed-algorithms",
        help="Comma-separated weak algorithm tokens (tab suggests common weak values).",
        autocompletion=_complete_dkim_disallowed,
    ),
]


def _build_dkim_overlay(
    *,
    selectors: str | None,
    min_key_bits: int | None,
    disallowed_algorithms: str | None,
) -> Config | None:
    kwargs: dict[str, object] = {}
    s = parse_csv_option(selectors)
    if s is not None:
        kwargs["selectors"] = s
    if min_key_bits is not None:
        kwargs["min_key_bits"] = min_key_bits
    d = parse_csv_option(disallowed_algorithms)
    if d is not None:
        kwargs["disallowed_algorithms"] = d
    if not kwargs:
        return None
    return Config(dkim=DkimConfig.model_construct(**kwargs))  # type: ignore[arg-type]


def register_dkim(app: typer.Typer) -> None:
    t = make_check_typer("dkim", help_text="DKIM DNS record check.")

    @t.callback(invoke_without_command=True)
    def dkim_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        selectors: DkimSelectorsOpt = None,
        min_key_bits: Annotated[
            int | None,
            typer.Option("--min-key-bits", help="Minimum RSA key size in bits.", min=0),
        ] = None,
        disallowed_algorithms: DkimDisallowedAlgorithmsOpt = None,
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_dkim_overlay(
            selectors=selectors,
            min_key_bits=min_key_bits,
            disallowed_algorithms=disallowed_algorithms,
        )
        run_check_sequence(
            ctx, "dkim", targets, config_path=path, program_config=overlay
        )

    app.add_typer(t, name="dkim")
