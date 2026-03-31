"""Markdown serialisation for :class:`~dnsight.core.models.DomainResult`."""

from __future__ import annotations

from collections import Counter

from dnsight.core.models import CheckResultAny, DomainResult, ZoneResult
from dnsight.core.types import Severity
from dnsight.serialisers._data_summary import data_summary_lines
from dnsight.serialisers._zone import iter_flat_zones
from dnsight.serialisers.base import SerialiserProtocol


__all__ = ["MarkdownSerialiser"]


def _md_cell(text: str) -> str:
    """Escape pipe characters so table cells stay valid."""
    return text.replace("|", "\\|").replace("\n", " ")


def _issue_cell(cr: CheckResultAny) -> str:
    """Table cell for check result issues."""
    if cr.error and not cr.issues:
        return _md_cell(
            f"Error: {cr.error[:200]}{'…' if len(cr.error or '') > 200 else ''}"
        )
    if not cr.issues:
        return "-"
    by_sev: Counter[str] = Counter(i.severity.value for i in cr.issues)
    order = [s.value for s in Severity]
    parts = [f"`{sev}`x{by_sev[sev]}" for sev in order if by_sev[sev]]
    return ", ".join(parts) if parts else _md_cell(str(len(cr.issues)))


def _zone_section(zone: ZoneResult) -> list[str]:
    out: list[str] = [
        f"\n## `{_md_cell(zone.zone)}`\n\n",
        "| Check | Status | Issues |\n",
        "| --- | --- | --- |\n",
    ]
    for name, cr in sorted(zone.results.items()):
        status = str(cr.status.value)
        issues = _issue_cell(cr)
        out.append(f"| `{_md_cell(name)}` | `{_md_cell(status)}` | {issues} |\n")
    if not zone.results:
        out.append("| — | — | — |\n")
    for name, cr in sorted(zone.results.items()):
        summary = data_summary_lines(cr.data)
        if not summary:
            continue
        out.append(f"\n**{_md_cell(name)}** (data)\n\n")
        for line in summary:
            out.append(f"- {_md_cell(line)}\n")
    return out


class MarkdownSerialiser(SerialiserProtocol):
    """Serialise :class:`~dnsight.core.models.DomainResult` to GitHub-friendly Markdown."""

    def serialise(self, result: DomainResult) -> str:
        """Return the full formatted output for *result*."""
        lines: list[str] = [
            f"# Audit: {_md_cell(result.domain)}\n",
            f"**Partial:** {'yes' if result.partial else 'no'}\n",
        ]
        for zone in iter_flat_zones(result):
            lines.extend(_zone_section(zone))
        return "".join(lines)
