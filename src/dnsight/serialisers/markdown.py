"""Markdown serialisation for :class:`~dnsight.sdk.audit.models.DomainResult`."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from dnsight.core.models import CheckResultAny, Issue, Recommendation
from dnsight.core.types import Severity
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers._data_summary import data_summary_lines
from dnsight.serialisers._finding_format import (
    DEFAULT_DESCRIPTION_MAX,
    issue_groups_for_display,
    severity_label,
    truncate_finding_text,
)
from dnsight.serialisers._generic_data import generic_data_preview_lines
from dnsight.serialisers._zone import iter_flat_zones
from dnsight.serialisers.base import BaseDomainSerialiser, SerialiserOptions


__all__ = ["MarkdownSerialiser"]


def _md_cell(text: str) -> str:
    """Escape pipe characters so table cells stay valid."""
    return text.replace("|", "\\|").replace("\n", " ")


def _md_inline(text: str) -> str:
    """Escape backticks for use inside Markdown prose."""
    return text.replace("`", "\\`")


def _summary_cell(cr: CheckResultAny) -> str:
    """Table cell: error hint (if any) plus severity counts when issues exist."""
    parts: list[str] = []
    if cr.error:
        err_one = " ".join(cr.error.splitlines())
        cap = 120
        if len(err_one) > cap:
            err_one = f"{err_one[: cap - 1]}…"
        parts.append(_md_cell(f"Error: {err_one}"))
    if cr.issues:
        by_sev: Counter[str] = Counter(i.severity.value for i in cr.issues)
        order = [s.value for s in Severity]
        sev_bits = [f"`{sev}`×{by_sev[sev]}" for sev in order if by_sev[sev]]
        if sev_bits:
            parts.append(", ".join(sev_bits))
    if not parts:
        return "-"
    return "; ".join(parts)


def _zone_heading(zone: str, *, manifest_target: str | None, apex: str) -> str:
    z = _md_cell(zone)
    if manifest_target and manifest_target != apex and zone == apex:
        t = _md_cell(manifest_target)
        return f"\n## `{z}` (target `{t}`)\n\n"
    return f"\n## `{z}`\n\n"


def _md_append_error(out: list[str], error: str) -> None:
    out.append("**Error**\n\n")
    out.append("```text\n")
    out.append(error)
    if not error.endswith("\n"):
        out.append("\n")
    out.append("```\n\n")


def _md_append_issues(
    out: list[str], issues: list[Issue], *, human_finding_detail: bool
) -> None:
    out.append("**Issues**\n\n")
    detail = human_finding_detail
    dmax = DEFAULT_DESCRIPTION_MAX if not detail else 10_000
    for group in issue_groups_for_display(issues):
        p = group.primary
        n = group.count
        sev = severity_label(p.severity)
        iid = _md_inline(p.id)
        title = _md_cell(p.title)
        if n == 1:
            out.append(f"- **{sev}** `{iid}` — {title}\n")
        else:
            out.append(f"- **{sev}** `{iid}` — {title} (×{n})\n")
        for iss in group.issues:
            desc = truncate_finding_text(iss.description, max_len=dmax, full=detail)
            if desc:
                out.append(f"  - {_md_cell(desc)}\n")
            if detail and iss.remediation.strip():
                out.append(f"  - Remediation: {_md_cell(iss.remediation)}\n")
    out.append("\n")


def _md_append_recommendations(
    out: list[str], recommendations: list[Recommendation], *, human_finding_detail: bool
) -> None:
    out.append("**Recommendations**\n\n")
    detail = human_finding_detail
    dmax = DEFAULT_DESCRIPTION_MAX if not detail else 10_000
    for rec in recommendations:
        iid = _md_inline(rec.id)
        title = _md_cell(rec.title)
        out.append(f"- `{iid}` — {title}\n")
        desc = truncate_finding_text(rec.description, max_len=dmax, full=detail)
        if desc:
            out.append(f"  - {_md_cell(desc)}\n")
    out.append("\n")


def _md_append_data_lines(
    out: list[str], summary: list[str], generic: list[str]
) -> None:
    out.append("**Data**\n\n")
    for line in summary:
        out.append(f"- {_md_cell(line)}\n")
    for line in generic:
        out.append(f"- {_md_cell(line)}\n")
    out.append("\n")


def _check_detail_section(
    name: str, cr: CheckResultAny, *, options: SerialiserOptions
) -> list[str]:
    """Per-check Markdown block: error, issues, recommendations, data."""
    summary = data_summary_lines(
        cr.data, flatten_detail=options.spf_flatten_detail and name == "spf"
    )
    generic: list[str] = []
    if options.human_data_preview and not summary and cr.data is not None:
        generic = generic_data_preview_lines(cr.data)

    if not (cr.error or cr.issues or cr.recommendations or summary or generic):
        return []

    out: list[str] = [f"\n### `{_md_inline(name)}`\n\n"]

    if cr.error:
        _md_append_error(out, cr.error)

    if cr.issues:
        _md_append_issues(
            out, cr.issues, human_finding_detail=options.human_finding_detail
        )

    if cr.recommendations:
        _md_append_recommendations(
            out, cr.recommendations, human_finding_detail=options.human_finding_detail
        )

    if summary or generic:
        _md_append_data_lines(out, summary, generic)

    return out


def _zone_section(
    zone: ZoneResult,
    *,
    options: SerialiserOptions,
    manifest_target: str | None,
    apex_domain: str,
) -> list[str]:
    out: list[str] = [
        _zone_heading(zone.zone, manifest_target=manifest_target, apex=apex_domain),
        "| Check | Status | Summary |\n",
        "| --- | --- | --- |\n",
    ]
    for name, cr in sorted(zone.results.items()):
        status = str(cr.status.value)
        summary = _summary_cell(cr)
        out.append(f"| `{_md_cell(name)}` | `{_md_cell(status)}` | {summary} |\n")
    if not zone.results:
        out.append("| — | — | — |\n")
    for name, cr in sorted(zone.results.items()):
        out.extend(_check_detail_section(name, cr, options=options))
    return out


def _single_domain_markdown(result: DomainResult, *, options: SerialiserOptions) -> str:
    """Markdown body for one :class:`~dnsight.sdk.audit.models.DomainResult`."""
    lines: list[str] = [
        f"# Audit: {_md_cell(result.domain)}\n",
        f"**Partial:** {'yes' if result.partial else 'no'}\n",
    ]
    if result.target != result.domain:
        lines.append(f"**Target:** {_md_cell(result.target)}\n")
    for zone in iter_flat_zones(result):
        lines.extend(
            _zone_section(
                zone,
                options=options,
                manifest_target=result.target,
                apex_domain=result.domain,
            )
        )
    return "".join(lines)


class MarkdownSerialiser(BaseDomainSerialiser):
    """Serialise one or more :class:`~dnsight.sdk.audit.models.DomainResult` to GitHub-friendly Markdown."""

    def _serialise_batch(
        self, results: Sequence[DomainResult], *, options: SerialiserOptions
    ) -> str:
        sep = "\n\n---\n\n"
        return sep.join(_single_domain_markdown(r, options=options) for r in results)
