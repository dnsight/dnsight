"""``dnsight headers`` — HTTP security headers check; CSP / HSTS generation."""

from __future__ import annotations

import json

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
from dnsight.cli.output import emit_generated_record
from dnsight.core.config import Config, HeadersConfig
from dnsight.core.schema.headers import HeadersSchema
from dnsight.sdk import CspGenerateParams, HstsGenerateParams, generate_headers


__all__ = ["register_headers"]


def _complete_headers_require(ctx: typer.Context, incomplete: str | None) -> list[str]:
    _ = ctx
    return complete_with_csv_suffix(incomplete, HeadersSchema.REQUIRE_TOKEN_LABELS)


def _build_headers_overlay(
    *, require: str | None, urls: str | None, strict_recommendations: bool | None
) -> Config | None:
    h_kwargs: dict[str, object] = {}
    r = parse_csv_option(require)
    if r is not None:
        h_kwargs["require"] = r
    u = parse_csv_option(urls)
    if u is not None:
        h_kwargs["urls"] = u
    cfg_kwargs: dict[str, object] = {}
    if h_kwargs:
        cfg_kwargs["headers"] = HeadersConfig.model_construct(**h_kwargs)  # type: ignore[arg-type]
    if strict_recommendations is not None:
        cfg_kwargs["strict_recommendations"] = strict_recommendations
    if not cfg_kwargs:
        return None
    return Config.model_construct(**cfg_kwargs)  # type: ignore[arg-type]


def register_headers(app: typer.Typer) -> None:
    t = make_check_typer(
        "headers",
        help_text="HTTP security headers check; generate CSP or HSTS snippets.",
    )

    @t.callback(invoke_without_command=True)
    def headers_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        require: str | None = typer.Option(
            None,
            "--require",
            help="Comma-separated required header tokens (HSTS, CSP, etc.).",
            autocompletion=_complete_headers_require,
        ),
        urls: str | None = typer.Option(
            None,
            "--urls",
            help="Comma-separated URLs to GET (when empty, https://domain and www).",
        ),
        strict_recommendations: bool | None = typer.Option(
            None,
            "--strict-recommendations/--no-strict-recommendations",
            help="Recommend strictest best practice.",
        ),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_headers_overlay(
            require=require, urls=urls, strict_recommendations=strict_recommendations
        )
        run_check_sequence(
            ctx, "headers", targets, config_path=path, program_config=overlay
        )

    gen_app = typer.Typer(help="Generate CSP or HSTS header line.")

    @gen_app.command("csp")
    def gen_csp(
        *,
        sources_json: str = typer.Option(
            "{}",
            "--sources-json",
            help='JSON object mapping CSP directive names to string lists, e.g. \'{"default-src":["self"]}\'',
        ),
    ) -> None:
        try:
            raw = json.loads(sources_json)
        except json.JSONDecodeError as e:
            typer.echo(f"Error: invalid JSON for --sources-json ({e}).", err=True)
            raise typer.Exit(3) from e
        if not isinstance(raw, dict):
            typer.echo("Error: --sources-json must be a JSON object.", err=True)
            raise typer.Exit(3)
        sources: dict[str, list[str]] = {}
        for k, v in raw.items():
            if isinstance(v, list) and all(isinstance(x, str) for x in v):
                sources[str(k)] = list(v)
            elif isinstance(v, str):
                sources[str(k)] = [v]
            else:
                typer.echo(
                    f"Error: directive {k!r} must map to a string list.", err=True
                )
                raise typer.Exit(3)
        params = CspGenerateParams(sources=sources)
        record = generate_headers(params=params)
        emit_generated_record(record)
        raise typer.Exit(0)

    @gen_app.command("hsts")
    def gen_hsts(
        *,
        max_age: int = typer.Option(
            31536000, "--max-age", help="max-age in seconds.", min=0
        ),
        include_subdomains: bool = typer.Option(
            True, "--include-subdomains/--no-include-subdomains"
        ),
        preload: bool = typer.Option(False, "--preload/--no-preload"),
    ) -> None:
        params = HstsGenerateParams(
            max_age=max_age, include_subdomains=include_subdomains, preload=preload
        )
        record = generate_headers(params=params)
        emit_generated_record(record)
        raise typer.Exit(0)

    t.add_typer(gen_app, name="generate")
    app.add_typer(t, name="headers")
