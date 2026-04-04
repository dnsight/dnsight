"""``dnsight audit`` command."""

from __future__ import annotations

import typer

from dnsight.cli._completion_common import complete_with_csv_suffix
from dnsight.cli.helpers import (
    DepthOpt,
    DomainsArg,
    RecursiveOpt,
    checks_and_exclude_options,
    cli_exit_fatal,
    config_path_for_sdk,
    domains_from_argument,
    require_targets_or_domains,
)
from dnsight.cli.output import emit_audit_results
from dnsight.cli.state import get_cli_state
from dnsight.core.exceptions import ConfigError
from dnsight.core.registry import all_checks
from dnsight.sdk import run_domain_sync, run_targets_sync


__all__ = ["register_audit"]


def _registered_check_names() -> tuple[str, ...]:
    """Resolved at completion time so the registry is populated."""
    import dnsight.checks  # noqa: F401

    return tuple(sorted(d.name for d in all_checks()))


def _complete_audit_checks(ctx: typer.Context, incomplete: str | None) -> list[str]:
    _ = ctx
    return complete_with_csv_suffix(incomplete, _registered_check_names())


def _complete_audit_exclude(ctx: typer.Context, incomplete: str | None) -> list[str]:
    return _complete_audit_checks(ctx, incomplete)


def register_audit(app: typer.Typer) -> None:
    """Attach the ``audit`` command to *app*."""

    @app.command(
        "audit",
        help="Run a full audit for domain(s) or all manifest targets from config.",
    )
    def audit_cmd(
        ctx: typer.Context,
        domains: DomainsArg = None,
        *,
        recursive: RecursiveOpt = False,
        depth: DepthOpt = 3,
        checks: str | None = typer.Option(
            None,
            "--checks",
            "-c",
            help="Comma-separated list of checks to run.",
            autocompletion=_complete_audit_checks,
        ),
        exclude: str | None = typer.Option(
            None,
            "--exclude",
            "-e",
            help="Comma-separated list of checks to exclude.",
            autocompletion=_complete_audit_exclude,
        ),
    ) -> None:
        """Run a full audit for domain(s) or all manifest targets from config."""
        state = get_cli_state(ctx)
        check_list, exclude_list = checks_and_exclude_options(checks, exclude)
        domain_list = domains_from_argument(domains)

        try:
            results = (
                [
                    run_domain_sync(
                        domain,
                        checks=check_list,
                        exclude=exclude_list,
                        recursive=recursive,
                        depth=depth,
                    )
                    for domain in domain_list
                ]
                if domain_list
                else run_targets_sync(
                    config_path=config_path_for_sdk(state),
                    checks=check_list,
                    exclude=exclude_list,
                    recursive=recursive,
                    depth=depth,
                )
            )
        except ConfigError as e:
            cli_exit_fatal(str(e))

        require_targets_or_domains(
            domain_list,
            results,
            hint=(
                "no domains given and config has no targets "
                "(pass domain(s) or use a dnsight.yaml with `targets`)."
            ),
        )

        code = emit_audit_results(state, results)
        raise typer.Exit(code)
