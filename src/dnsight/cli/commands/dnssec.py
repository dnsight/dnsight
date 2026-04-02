"""``dnsight dnssec`` — DNSSEC check."""

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
from dnsight.core.config import Config, DnssecConfig


__all__ = ["register_dnssec"]


def _build_dnssec_overlay(
    *,
    require_ds: bool | None,
    signature_expiry_days_warning: int | None,
    disallowed_algorithms: str | None,
    validate_negative_responses: bool | None,
    validate_nodata_proofs: bool | None,
    nxdomain_probe_label: str | None,
    require_ns: bool | None,
    nodata_probe_name: str | None,
) -> Config | None:
    kwargs: dict[str, object] = {}
    if require_ds is not None:
        kwargs["require_ds"] = require_ds
    if signature_expiry_days_warning is not None:
        kwargs["signature_expiry_days_warning"] = signature_expiry_days_warning
    d = parse_csv_option(disallowed_algorithms)
    if d is not None:
        kwargs["disallowed_algorithms"] = d
    if validate_negative_responses is not None:
        kwargs["validate_negative_responses"] = validate_negative_responses
    if validate_nodata_proofs is not None:
        kwargs["validate_nodata_proofs"] = validate_nodata_proofs
    if nxdomain_probe_label is not None:
        kwargs["nxdomain_probe_label"] = nxdomain_probe_label
    if require_ns is not None:
        kwargs["require_ns"] = require_ns
    if nodata_probe_name is not None:
        kwargs["nodata_probe_name"] = nodata_probe_name
    if not kwargs:
        return None
    return Config(
        dnssec=DnssecConfig.model_construct(**kwargs)  # type: ignore[arg-type]
    )


def register_dnssec(app: typer.Typer) -> None:
    t = make_check_typer(
        "dnssec", help_text="DNSSEC chain and negative-response validation."
    )

    @t.callback(invoke_without_command=True)
    def dnssec_run(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        config_path: CheckCommandConfigPath = None,
        require_ds: bool | None = typer.Option(
            None,
            "--require-ds/--no-require-ds",
            help="Require DS at parent delegation.",
        ),
        signature_expiry_days_warning: int | None = typer.Option(
            None,
            "--signature-expiry-days-warning",
            help="Warn when RRSIG expires within this many days.",
            min=0,
        ),
        disallowed_algorithms: str | None = typer.Option(
            None,
            "--disallowed-algorithms",
            help="Comma-separated weak DNSSEC algorithms.",
        ),
        validate_negative_responses: bool | None = typer.Option(
            None,
            "--validate-negative-responses/--no-validate-negative-responses",
            help="Probe NXDOMAIN and verify NSEC/NSEC3.",
        ),
        validate_nodata_proofs: bool | None = typer.Option(
            None,
            "--validate-nodata-proofs/--no-validate-nodata-proofs",
            help="Probe NODATA and verify proofs.",
        ),
        nxdomain_probe_label: str | None = typer.Option(
            None,
            "--nxdomain-probe-label",
            help="Leftmost label for NXDOMAIN probe (optional).",
        ),
        require_ns: bool | None = typer.Option(
            None, "--require-ns/--no-require-ns", help="Require NS at zone apex."
        ),
        nodata_probe_name: str | None = typer.Option(
            None, "--nodata-probe-name", help="FQDN for NODATA proof probe (optional)."
        ),
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        path = effective_cli_config_path(ctx, config_path)
        targets = resolve_target_domain_strings(ctx, domains, path)
        overlay = _build_dnssec_overlay(
            require_ds=require_ds,
            signature_expiry_days_warning=signature_expiry_days_warning,
            disallowed_algorithms=disallowed_algorithms,
            validate_negative_responses=validate_negative_responses,
            validate_nodata_proofs=validate_nodata_proofs,
            nxdomain_probe_label=nxdomain_probe_label,
            require_ns=require_ns,
            nodata_probe_name=nodata_probe_name,
        )
        run_check_sequence(
            ctx, "dnssec", targets, config_path=path, program_config=overlay
        )

    app.add_typer(t, name="dnssec")
