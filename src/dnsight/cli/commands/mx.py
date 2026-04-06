"""``dnsight mx`` — MX check and RDATA generation."""

from __future__ import annotations

from typing import Annotated

import typer

from dnsight.cli.commands._check_base import (
    effective_cli_config_path,
    make_check_typer,
    resolve_target_domain_strings,
    run_check_sequence,
)
from dnsight.cli.helpers import CheckCommandConfigPath, DomainsArg
from dnsight.cli.output import emit_generated_record
from dnsight.core.config import Config, MxConfig
from dnsight.sdk import MXGenerateParams, MXGenerateTarget, generate_mx


__all__ = ["register_mx"]


def _build_mx_overlay(
    *,
    check_ptr: bool | None,
    check_starttls: bool | None,
    starttls_timeout_seconds: int | None,
) -> Config | None:
    kwargs: dict[str, object] = {}
    if check_ptr is not None:
        kwargs["check_ptr"] = check_ptr
    if check_starttls is not None:
        kwargs["check_starttls"] = check_starttls
    if starttls_timeout_seconds is not None:
        kwargs["starttls_timeout_seconds"] = starttls_timeout_seconds
    if not kwargs:
        return None
    return Config(mx=MxConfig.model_construct(**kwargs))  # type: ignore[arg-type]


def _parse_mx_targets(s: str) -> list[MXGenerateTarget]:
    """Parse ``10:mail.example.com,20:mx2.example`` into :class:`MXGenerateTarget` list."""
    out: list[MXGenerateTarget] = []
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        pref_s, _, host = chunk.partition(":")
        try:
            priority = int(pref_s.strip())
        except ValueError:
            continue
        out.append(MXGenerateTarget(priority=priority, hostname=host.strip()))
    return out


def register_mx(app: typer.Typer) -> None:
    t = make_check_typer(
        "mx", help_text="MX resolution and optional PTR/STARTTLS; generate MX lines."
    )

    @t.callback(invoke_without_command=True)
    def mx_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        check_ptr: Annotated[
            bool | None,
            typer.Option(
                "--check-ptr/--no-check-ptr", help="Resolve PTR for MX hostnames."
            ),
        ] = None,
        check_starttls: Annotated[
            bool | None,
            typer.Option(
                "--check-starttls/--no-check-starttls",
                help="Probe STARTTLS on port 25.",
            ),
        ] = None,
        starttls_timeout_seconds: Annotated[
            int | None,
            typer.Option(
                "--starttls-timeout-seconds",
                help="TCP/SMTP timeout for STARTTLS probe.",
                min=0,
            ),
        ] = None,
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_mx_overlay(
            check_ptr=check_ptr,
            check_starttls=check_starttls,
            starttls_timeout_seconds=starttls_timeout_seconds,
        )
        run_check_sequence(ctx, "mx", targets, config_path=path, program_config=overlay)

    @t.command(
        "generate",
        help="Print MX RDATA lines from pref:host rows.",
        no_args_is_help=True,
    )
    def generate_cmd(
        *,
        mx: Annotated[
            str,
            typer.Option(
                "--mx",
                help='Comma-separated pref:host rows (e.g. "10:mail.example.com,20:mx2.example.com").',
            ),
        ],
    ) -> None:
        targets = _parse_mx_targets(mx)
        if not targets:
            typer.echo(
                "Error: no valid --mx rows (use 10:mail.example.com,...)", err=True
            )
            raise typer.Exit(3)
        record = generate_mx(params=MXGenerateParams(targets=targets))
        emit_generated_record(record)
        raise typer.Exit(0)

    app.add_typer(t, name="mx")
