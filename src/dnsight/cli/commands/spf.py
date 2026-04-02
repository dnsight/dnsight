"""``dnsight spf`` — SPF check and TXT generation."""

from __future__ import annotations

import typer

from dnsight.cli._parse import parse_csv_option
from dnsight.cli.commands._check_base import (
    effective_cli_config_path,
    make_check_typer,
    resolve_target_domain_strings,
    run_check_sequence,
)
from dnsight.cli.helpers import CheckCommandConfigPath, DomainsArg
from dnsight.cli.output import emit_generated_record
from dnsight.core.config import Config, SpfConfig
from dnsight.sdk import SPFGenerateParams, generate_spf
from dnsight.serialisers import SerialiserOptions


__all__ = ["register_spf"]


def _build_spf_overlay(
    *,
    required_disposition: str | None,
    lookup_limit: int | None,
    max_includes: int | None,
    allow_redirect: bool | None,
) -> Config | None:
    kwargs: dict[str, object] = {}
    if required_disposition is not None:
        kwargs["required_disposition"] = required_disposition
    if lookup_limit is not None:
        kwargs["lookup_limit"] = lookup_limit
    if max_includes is not None:
        kwargs["max_includes"] = max_includes
    if allow_redirect is not None:
        kwargs["allow_redirect"] = allow_redirect
    if not kwargs:
        return None
    return Config(spf=SpfConfig.model_construct(**kwargs))  # type: ignore[arg-type]


def register_spf(app: typer.Typer) -> None:
    t = make_check_typer("spf", help_text="SPF check and suggested TXT generation.")

    @t.callback(invoke_without_command=True)
    def spf_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        required_disposition: str | None = typer.Option(
            None,
            "--required-disposition",
            help="Required terminal SPF mechanism (e.g. -all, ~all).",
        ),
        lookup_limit: int | None = typer.Option(
            None, "--lookup-limit", help="Max DNS lookups during SPF evaluation.", min=0
        ),
        max_includes: int | None = typer.Option(
            None, "--max-includes", help="Cap on include traversals (optional)."
        ),
        allow_redirect: bool | None = typer.Option(
            None,
            "--allow-redirect/--no-allow-redirect",
            help="Allow redirect= mechanism.",
        ),
        flatten: bool = typer.Option(
            False,
            "--flatten/--no-flatten",
            help=(
                "Expand flattened SPF view in Rich/Markdown-style output "
                "(JSON/SARIF already include full data)."
            ),
        ),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_spf_overlay(
            required_disposition=required_disposition,
            lookup_limit=lookup_limit,
            max_includes=max_includes,
            allow_redirect=allow_redirect,
        )
        run_check_sequence(
            ctx,
            "spf",
            targets,
            config_path=path,
            program_config=overlay,
            serialiser_options=(
                SerialiserOptions(spf_flatten_detail=True) if flatten else None
            ),
        )

    @t.command("generate", help="Print a minimal SPF TXT record.")
    def generate_cmd(
        *,
        include: str | None = typer.Option(
            None,
            "--include",
            help="Comma-separated include: domains for generated record.",
        ),
        disposition: str = typer.Option(
            "-all", "--disposition", help="Terminal disposition."
        ),
    ) -> None:
        inc = list(parse_csv_option(include) or [])
        params = SPFGenerateParams(includes=inc, disposition=disposition)
        record = generate_spf(params=params)
        emit_generated_record(record)
        raise typer.Exit(0)

    app.add_typer(t, name="spf")
