"""``dnsight dmarc`` — DMARC check and TXT generation."""

from __future__ import annotations

from typing import Annotated, TypeAlias

import typer

from dnsight.cli._completion_common import prefix_choices
from dnsight.cli._parse import parse_csv_option
from dnsight.cli.commands._check_base import (
    effective_cli_config_path,
    make_check_typer,
    resolve_target_domain_strings,
    run_check_sequence,
)
from dnsight.cli.helpers import CheckCommandConfigPath, DomainsArg
from dnsight.cli.output import emit_generated_record
from dnsight.core.config import Config, DmarcConfig
from dnsight.core.schema.dmarc import DmarcSchema
from dnsight.sdk import DMARCGenerateParams, generate_dmarc


__all__ = ["register_dmarc"]


def _complete_dmarc_policy(ctx: typer.Context, incomplete: str | None) -> list[str]:
    _ = ctx
    return prefix_choices(incomplete, DmarcSchema.POLICY_VALUES)


def _complete_dmarc_alignment(ctx: typer.Context, incomplete: str | None) -> list[str]:
    _ = ctx
    return prefix_choices(incomplete, DmarcSchema.ALIGNMENT_VALUES)


def _build_dmarc_overlay(
    *,
    policy: DmarcSchema.PolicyLiteral | None,
    target_policy: DmarcSchema.PolicyLiteral | None,
    rua_required: bool | None,
    ruf_required: bool | None,
    expected_rua: str | None,
    expected_ruf: str | None,
    minimum_pct: int | None,
    require_strict_alignment: bool | None,
    alignment_dkim: DmarcSchema.AlignmentLiteral | None,
    alignment_spf: DmarcSchema.AlignmentLiteral | None,
    subdomain_policy_minimum: str | None,
) -> Config | None:
    kwargs: dict[str, object] = {}
    if policy is not None:
        kwargs["policy"] = policy
    if target_policy is not None:
        kwargs["target_policy"] = target_policy
    if rua_required is not None:
        kwargs["rua_required"] = rua_required
    if ruf_required is not None:
        kwargs["ruf_required"] = ruf_required
    er = parse_csv_option(expected_rua)
    if er is not None:
        kwargs["expected_rua"] = er
    ef = parse_csv_option(expected_ruf)
    if ef is not None:
        kwargs["expected_ruf"] = ef
    if minimum_pct is not None:
        kwargs["minimum_pct"] = minimum_pct
    if require_strict_alignment is not None:
        kwargs["require_strict_alignment"] = require_strict_alignment
    if alignment_dkim is not None:
        kwargs["alignment_dkim"] = alignment_dkim
    if alignment_spf is not None:
        kwargs["alignment_spf"] = alignment_spf
    if subdomain_policy_minimum is not None:
        kwargs["subdomain_policy_minimum"] = (
            None if subdomain_policy_minimum == "" else subdomain_policy_minimum
        )
    if not kwargs:
        return None
    return Config(
        dmarc=DmarcConfig.model_construct(**kwargs)  # type: ignore[arg-type]
    )


DmarcCheckPolicyOpt: TypeAlias = Annotated[
    DmarcSchema.PolicyLiteral | None,
    typer.Option(
        "--policy",
        "-p",
        help="Minimum required DMARC policy.",
        autocompletion=_complete_dmarc_policy,
        case_sensitive=False,
    ),
]

DmarcTargetPolicyOpt: TypeAlias = Annotated[
    DmarcSchema.PolicyLiteral | None,
    typer.Option(
        "--target-policy",
        help="Target policy for recommendations when not strict.",
        autocompletion=_complete_dmarc_policy,
        case_sensitive=False,
    ),
]

DmarcAdkimCheckOpt: TypeAlias = Annotated[
    DmarcSchema.AlignmentLiteral | None,
    typer.Option(
        "--adkim",
        help="adkim= alignment: r or s.",
        autocompletion=_complete_dmarc_alignment,
        case_sensitive=False,
    ),
]

DmarcAspfCheckOpt: TypeAlias = Annotated[
    DmarcSchema.AlignmentLiteral | None,
    typer.Option(
        "--aspf",
        help="aspf= alignment: r or s.",
        autocompletion=_complete_dmarc_alignment,
        case_sensitive=False,
    ),
]

DmarcSubdomainMinOpt: TypeAlias = Annotated[
    str | None,
    typer.Option(
        "--subdomain-policy-minimum",
        help=(
            "Minimum subdomain policy (sp); omit for YAML default; "
            "pass '' to disable sp enforcement."
        ),
        autocompletion=_complete_dmarc_policy,
    ),
]

DmarcGenPolicyOpt: TypeAlias = Annotated[
    DmarcSchema.PolicyLiteral,
    typer.Option(
        "--policy",
        "-p",
        help="Generated record p=.",
        autocompletion=_complete_dmarc_policy,
        case_sensitive=False,
    ),
]

DmarcGenSubdomainPolicyOpt: TypeAlias = Annotated[
    DmarcSchema.PolicyLiteral | None,
    typer.Option(
        "--subdomain-policy",
        help="Generated sp= (optional).",
        autocompletion=_complete_dmarc_policy,
        case_sensitive=False,
    ),
]

DmarcGenAdkimOpt: TypeAlias = Annotated[
    DmarcSchema.AlignmentLiteral,
    typer.Option(
        "--adkim",
        help="adkim= r|s.",
        autocompletion=_complete_dmarc_alignment,
        case_sensitive=False,
    ),
]

DmarcGenAspfOpt: TypeAlias = Annotated[
    DmarcSchema.AlignmentLiteral,
    typer.Option(
        "--aspf",
        help="aspf= r|s.",
        autocompletion=_complete_dmarc_alignment,
        case_sensitive=False,
    ),
]


def register_dmarc(app: typer.Typer) -> None:
    """Attach ``dnsight dmarc`` and ``dnsight dmarc generate``."""
    t = make_check_typer(
        "dmarc", help_text="DMARC check (multi-domain or manifest) and TXT generation."
    )

    @t.callback(invoke_without_command=True)
    def dmarc_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        policy: DmarcCheckPolicyOpt = None,
        target_policy: DmarcTargetPolicyOpt = None,
        rua_required: Annotated[
            bool | None,
            typer.Option(
                "--rua-required/--no-rua-required",
                help="Require aggregate reporting (rua).",
            ),
        ] = None,
        ruf_required: Annotated[
            bool | None,
            typer.Option(
                "--ruf-required/--no-ruf-required",
                help="Require forensic reporting (ruf).",
            ),
        ] = None,
        expected_rua: Annotated[
            str | None,
            typer.Option(
                "--expected-rua",
                help="Comma-separated rua URIs (exact set match when non-empty).",
            ),
        ] = None,
        expected_ruf: Annotated[
            str | None,
            typer.Option(
                "--expected-ruf",
                help="Comma-separated ruf URIs (exact set match when non-empty).",
            ),
        ] = None,
        minimum_pct: Annotated[
            int | None,
            typer.Option(
                "--minimum-pct", help="Minimum acceptable pct (0–100).", min=0, max=100
            ),
        ] = None,
        require_strict_alignment: Annotated[
            bool | None,
            typer.Option(
                "--require-strict-alignment/--no-require-strict-alignment",
                help="If true, issue when adkim or aspf is relaxed.",
            ),
        ] = None,
        adkim: DmarcAdkimCheckOpt = None,
        aspf: DmarcAspfCheckOpt = None,
        subdomain_policy_minimum: DmarcSubdomainMinOpt = None,
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_dmarc_overlay(
            policy=policy,
            target_policy=target_policy,
            rua_required=rua_required,
            ruf_required=ruf_required,
            expected_rua=expected_rua,
            expected_ruf=expected_ruf,
            minimum_pct=minimum_pct,
            require_strict_alignment=require_strict_alignment,
            alignment_dkim=adkim,
            alignment_spf=aspf,
            subdomain_policy_minimum=subdomain_policy_minimum,
        )
        run_check_sequence(
            ctx, "dmarc", targets, config_path=path, program_config=overlay
        )

    @t.command("generate", help="Print a suggested DMARC TXT record.")
    def generate_cmd(
        *,
        policy: DmarcGenPolicyOpt = "none",
        subdomain_policy: DmarcGenSubdomainPolicyOpt = None,
        pct: Annotated[
            int, typer.Option("--pct", help="pct= 0–100.", min=0, max=100)
        ] = 100,
        adkim: DmarcGenAdkimOpt = "r",
        aspf: DmarcGenAspfOpt = "r",
        rua: Annotated[
            str | None,
            typer.Option("--rua", help="Comma-separated rua= mailto or http URIs."),
        ] = None,
        ruf: Annotated[
            str | None,
            typer.Option("--ruf", help="Comma-separated ruf= mailto or http URIs."),
        ] = None,
    ) -> None:
        params = DMARCGenerateParams(
            policy=policy,
            subdomain_policy=subdomain_policy,
            percentage=pct,
            alignment_dkim=adkim,
            alignment_spf=aspf,
            rua=list(parse_csv_option(rua) or []),
            ruf=list(parse_csv_option(ruf) or []),
        )
        record = generate_dmarc(params=params)
        emit_generated_record(record)
        raise typer.Exit(0)

    app.add_typer(t, name="dmarc")
