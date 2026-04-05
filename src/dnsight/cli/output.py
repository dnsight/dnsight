"""Exit codes, format dispatch, and emitting audit output."""

from __future__ import annotations

from collections.abc import Sequence
import sys
from typing import TypeAlias

import typer

from dnsight.cli.state import GlobalState
from dnsight.core.models import CheckResultAny, GeneratedRecord
from dnsight.core.types import OutputFormat
from dnsight.sdk.audit.models import AuditResult, DomainResult
from dnsight.serialisers import (
    JsonSerialiser,
    MarkdownSerialiser,
    RichSerialiser,
    SarifSerialiser,
    SerialiserOptions,
    domain_result_from_check,
    write_serialiser,
)
from dnsight.serialisers.base import BaseDomainSerialiser


__all__ = [
    "emit_audit_results",
    "emit_check_result",
    "emit_generated_record",
    "serialiser_options_from_state",
    "exit_code_for_audit_result",
    "exit_code_for_check_result",
    "exit_code_for_domain_result",
    "exit_code_for_domain_results",
    "get_serialiser",
]

_Batch: TypeAlias = tuple[DomainResult, ...]
_EmitInput: TypeAlias = DomainResult | Sequence[DomainResult] | AuditResult


def serialiser_options_from_state(
    state: GlobalState, base: SerialiserOptions | None = None
) -> SerialiserOptions:
    """Merge CLI :class:`GlobalState` with per-call :class:`SerialiserOptions`."""
    b = base or SerialiserOptions()
    return SerialiserOptions(
        spf_flatten_detail=b.spf_flatten_detail,
        human_finding_detail=state.output_detail or b.human_finding_detail,
        human_data_preview=state.markdown_data_preview or b.human_data_preview,
    )


def get_serialiser(fmt: OutputFormat) -> BaseDomainSerialiser:
    """Return the serialiser for the given format."""
    match fmt:
        case OutputFormat.JSON:
            return JsonSerialiser()
        case OutputFormat.MARKDOWN:
            return MarkdownSerialiser()
        case OutputFormat.SARIF:
            return SarifSerialiser()
        case OutputFormat.RICH:
            return RichSerialiser()


def exit_code_for_domain_result(result: DomainResult) -> int:
    """0 = clean, 1 = completed with issues, 2 = partial or failed check run."""
    if result.partial:
        return 2
    if result.all_issues:
        return 1
    return 0


def exit_code_for_domain_results(results: Sequence[DomainResult]) -> int:
    """Worst exit code across audits (only 0–2; fatal errors use 3 elsewhere)."""
    if not results:
        return 0
    return max(exit_code_for_domain_result(r) for r in results)


def exit_code_for_audit_result(result: AuditResult) -> int:
    """Worst exit code across domains in a manifest batch."""
    return exit_code_for_domain_results(result.domains)


def exit_code_for_check_result(result: CheckResultAny) -> int:
    """0 / 1 / 2 for a single :class:`~dnsight.core.models.CheckResult`."""
    if result.failed or result.partial:
        return 2
    if result.issues:
        return 1
    return 0


def emit_generated_record(record: GeneratedRecord) -> None:
    """Print one generated record as a single tab-separated line."""
    typer.echo(f"{record.record_type}\t{record.host}\t{record.value}\t{record.ttl}")


def emit_check_result(
    state: GlobalState,
    result: CheckResultAny,
    *,
    domain: str,
    check_name: str,
    serialiser_options: SerialiserOptions | None = None,
) -> int:
    """Serialise one check; Rich + TTY uses a one-domain audit view."""
    code = exit_code_for_check_result(result)
    serialiser = get_serialiser(state.output_format)
    opts = serialiser_options_from_state(state, serialiser_options)
    if state.output_path is not None:
        write_serialiser(
            serialiser,
            result,
            state.output_path,
            domain=domain,
            check_name=check_name,
            options=opts,
        )
    if state.output_path is None:
        rich_tty = state.output_format == OutputFormat.RICH and sys.stdout.isatty()
        if rich_tty:
            dr = domain_result_from_check(
                domain=domain, check_name=check_name, result=result
            )
            RichSerialiser().serialise_live(dr, options=opts)
        else:
            typer.echo(
                serialiser.serialise(
                    result, domain=domain, check_name=check_name, options=opts
                )
            )
    return code


def _normalise_batch(results: _EmitInput) -> _Batch:
    if isinstance(results, AuditResult):
        return tuple(results.domains)
    if isinstance(results, DomainResult):
        return (results,)
    t = tuple(results)
    if not t:
        return ()
    return t


def emit_audit_results(state: GlobalState, results: _EmitInput) -> int:
    """Serialise to ``--output`` and/or stdout.

    Returns:
        Process exit code in ``{0, 1, 2}`` for the audit outcome.
    """
    batch = _normalise_batch(results)
    if not batch:
        return 0

    code = exit_code_for_domain_results(batch)
    serialiser = get_serialiser(state.output_format)
    opts = serialiser_options_from_state(state)

    if state.output_path is not None:
        payload: DomainResult | list[DomainResult] = (
            batch[0] if len(batch) == 1 else list(batch)
        )
        write_serialiser(serialiser, payload, state.output_path, options=opts)

    if state.output_path is None:
        rich_tty = (
            state.output_format == OutputFormat.RICH
            and sys.stdout.isatty()
            and len(batch) == 1
        )
        if rich_tty:
            RichSerialiser().serialise_live(batch[0], options=opts)
        else:
            out = (
                serialiser.serialise(batch[0], options=opts)
                if len(batch) == 1
                else serialiser.serialise(list(batch), options=opts)
            )
            typer.echo(out)

    return code
