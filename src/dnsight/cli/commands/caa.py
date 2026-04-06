"""``dnsight caa`` — CAA check and record generation."""

from __future__ import annotations

from typing import Annotated

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
from dnsight.core.config import CaaConfig, Config
from dnsight.sdk import CaaGenerateParams, generate_caa


__all__ = ["register_caa"]


def _build_caa_overlay(
    *,
    require_caa: bool | None,
    required_issuers: str | None,
    check_issuewild: bool | None,
    restrict_wildcard_issuance: bool | None,
    cross_reference_crt_sh: bool | None,
    names: str | None,
    enumerate_names: bool | None,
    max_enumeration_depth: int | None,
    max_names: int | None,
    include_www: bool | None,
    include_mx_targets: bool | None,
    include_srv_targets: bool | None,
    enumerate_dname: bool | None,
    reporting_email: str | None,
) -> Config | None:
    kwargs: dict[str, object] = {}
    if require_caa is not None:
        kwargs["require_caa"] = require_caa
    ri = parse_csv_option(required_issuers)
    if ri is not None:
        kwargs["required_issuers"] = ri
    if check_issuewild is not None:
        kwargs["check_issuewild"] = check_issuewild
    if restrict_wildcard_issuance is not None:
        kwargs["restrict_wildcard_issuance"] = restrict_wildcard_issuance
    if cross_reference_crt_sh is not None:
        kwargs["cross_reference_crt_sh"] = cross_reference_crt_sh
    n = parse_csv_option(names)
    if n is not None:
        kwargs["names"] = n
    if enumerate_names is not None:
        kwargs["enumerate_names"] = enumerate_names
    if max_enumeration_depth is not None:
        kwargs["max_enumeration_depth"] = max_enumeration_depth
    if max_names is not None:
        kwargs["max_names"] = max_names
    if include_www is not None:
        kwargs["include_www"] = include_www
    if include_mx_targets is not None:
        kwargs["include_mx_targets"] = include_mx_targets
    if include_srv_targets is not None:
        kwargs["include_srv_targets"] = include_srv_targets
    if enumerate_dname is not None:
        kwargs["enumerate_dname"] = enumerate_dname
    if reporting_email is not None:
        kwargs["reporting_email"] = reporting_email
    if not kwargs:
        return None
    return Config(
        caa=CaaConfig.model_construct(**kwargs)  # type: ignore[arg-type]
    )


def register_caa(app: typer.Typer) -> None:
    t = make_check_typer(
        "caa", help_text="CAA inventory and policy check; generate CAA lines."
    )

    @t.callback(invoke_without_command=True)
    def caa_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        require_caa: Annotated[
            bool | None,
            typer.Option(
                "--require-caa/--no-require-caa",
                help="Require effective CAA with issue tags.",
            ),
        ] = None,
        required_issuers: Annotated[
            str | None,
            typer.Option(
                "--required-issuers",
                help="Comma-separated CA issuer domains required in issue tags.",
            ),
        ] = None,
        check_issuewild: Annotated[
            bool | None,
            typer.Option(
                "--check-issuewild/--no-check-issuewild",
                help="Validate issuewild vs issue consistency.",
            ),
        ] = None,
        restrict_wildcard_issuance: Annotated[
            bool | None,
            typer.Option(
                "--restrict-wildcard-issuance/--no-restrict-wildcard-issuance",
                help="Wildcard issuance must be restricted via issuewild.",
            ),
        ] = None,
        cross_reference_crt_sh: Annotated[
            bool | None,
            typer.Option(
                "--cross-reference-crt-sh/--no-cross-reference-crt-sh",
                help="Query crt.sh and compare issuers to CAA.",
            ),
        ] = None,
        names: Annotated[
            str | None,
            typer.Option(
                "--names", help="Comma-separated extra hostnames (under zone) to check."
            ),
        ] = None,
        enumerate_names: Annotated[
            bool | None,
            typer.Option(
                "--enumerate-names/--no-enumerate-names",
                help="Discover names via DNS walk.",
            ),
        ] = None,
        max_enumeration_depth: Annotated[
            int | None,
            typer.Option(
                "--max-enumeration-depth", help="Max CNAME/DNAME depth.", min=0
            ),
        ] = None,
        max_names: Annotated[
            int | None,
            typer.Option("--max-names", help="Max distinct names to enumerate.", min=0),
        ] = None,
        include_www: Annotated[
            bool | None,
            typer.Option("--include-www/--no-include-www", help="Seed www.<zone>."),
        ] = None,
        include_mx_targets: Annotated[
            bool | None,
            typer.Option(
                "--include-mx-targets/--no-include-mx-targets",
                help="Include MX exchange hostnames in discovery.",
            ),
        ] = None,
        include_srv_targets: Annotated[
            bool | None,
            typer.Option(
                "--include-srv-targets/--no-include-srv-targets",
                help="Include SRV targets in discovery.",
            ),
        ] = None,
        enumerate_dname: Annotated[
            bool | None,
            typer.Option(
                "--enumerate-dname/--no-enumerate-dname",
                help="Follow DNAME during walk.",
            ),
        ] = None,
        reporting_email: Annotated[
            str | None,
            typer.Option(
                "--reporting-email",
                help="Email for iodef mailto in GENERATE (optional).",
            ),
        ] = None,
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_caa_overlay(
            require_caa=require_caa,
            required_issuers=required_issuers,
            check_issuewild=check_issuewild,
            restrict_wildcard_issuance=restrict_wildcard_issuance,
            cross_reference_crt_sh=cross_reference_crt_sh,
            names=names,
            enumerate_names=enumerate_names,
            max_enumeration_depth=max_enumeration_depth,
            max_names=max_names,
            include_www=include_www,
            include_mx_targets=include_mx_targets,
            include_srv_targets=include_srv_targets,
            enumerate_dname=enumerate_dname,
            reporting_email=reporting_email,
        )
        run_check_sequence(
            ctx, "caa", targets, config_path=path, program_config=overlay
        )

    @t.command("generate", help="Print suggested CAA records.", no_args_is_help=True)
    def generate_cmd(
        *,
        issuers: Annotated[
            str | None,
            typer.Option(
                "--issuers", help="Comma-separated CA domains for 0 issue lines."
            ),
        ] = None,
        emit_issuewild: Annotated[
            bool,
            typer.Option(
                "--emit-issuewild/--no-emit-issuewild",
                help="Emit issuewild lines matching issuers.",
            ),
        ] = False,
        iodef_mailto: Annotated[
            str | None,
            typer.Option(
                "--iodef-mailto", help="mailto address for 0 iodef line (optional)."
            ),
        ] = None,
    ) -> None:
        params = CaaGenerateParams(
            issuers=list(parse_csv_option(issuers) or []),
            emit_issuewild=emit_issuewild,
            iodef_mailto=iodef_mailto,
        )
        record = generate_caa(params=params)
        emit_generated_record(record)
        raise typer.Exit(0)

    app.add_typer(t, name="caa")
