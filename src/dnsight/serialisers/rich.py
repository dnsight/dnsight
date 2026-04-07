"""Rich console serialisation for domain audits (single or batch)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
import textwrap

from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text

from dnsight.core.models import CheckResultAny, Issue
from dnsight.core.types import Severity, Status
from dnsight.sdk.audit.models import DomainResult
from dnsight.serialisers._data_summary import data_summary_lines
from dnsight.serialisers._finding_format import (
    DEFAULT_DESCRIPTION_MAX,
    issue_groups_for_display,
    raw_redundant_with_record_line,
    truncate_finding_text,
)
from dnsight.serialisers.base import BaseDomainSerialiser, SerialiserOptions
from dnsight.serialisers.tree import OutputNode, node_from_domain


__all__ = ["RichSerialiser"]

_RAW_MAX_LEN = 600

# --- Rich styles (single place for colours / emphasis used in this module) ---

_STYLE_BOLD_RED = Style(bold=True, color="red")
_STYLE_RED = Style(color="red")
_STYLE_YELLOW = Style(color="yellow")
_STYLE_GREEN = Style(color="green")
_STYLE_BLUE = Style(color="blue")
_STYLE_DIM = Style(dim=True)
_STYLE_DIM_CYAN = Style(dim=True, color="cyan")
_STYLE_ITALIC_CYAN = Style(italic=True, color="cyan")
_STYLE_BOLD = Style(bold=True)
_STYLE_BOLD_UNDERLINE = Style(bold=True, underline=True)
_STYLE_BORDER_CHECK_PANEL = Style(color="blue")
_STYLE_BORDER_HEADER_PANEL = Style(color="green")

_SEVERITY_STYLES: dict[str, Style] = {
    "critical": _STYLE_BOLD_RED,
    "high": _STYLE_RED,
    "medium": _STYLE_YELLOW,
    "low": _STYLE_BLUE,
    "info": _STYLE_DIM,
}

_STATUS_STYLES: dict[str, Style] = {
    "completed": _STYLE_GREEN,
    "partial": _STYLE_YELLOW,
    "failed": _STYLE_BOLD_RED,
    "skipped": _STYLE_DIM,
}


def _truncate(text: str | None, max_len: int = _RAW_MAX_LEN) -> str:
    if not text:
        return ""
    single = " ".join(text.splitlines())
    if len(single) <= max_len:
        return single
    return single[: max_len - 1] + "…"


def _severity_style(severity: Severity) -> Style:
    return _SEVERITY_STYLES[str(severity.value)]


def _status_style(status: Status) -> Style:
    return _STATUS_STYLES[str(status.value)]


def _foldable_line(content: str, *, style: str | Style, wrap_width: int | None) -> Text:
    """Rich text wrapped to the panel inner width when *wrap_width* is known."""
    if wrap_width is None or wrap_width < 28:
        return Text(content, style=style)
    inner = max(wrap_width - 6, 24)
    if len(content) <= inner:
        return Text(content, style=style)
    folded = "\n".join(
        textwrap.wrap(
            content, width=inner, break_long_words=True, break_on_hyphens=False
        )
    )
    return Text(folded, style=style)


def _rich_check_panel_status_and_data_lines(
    cr: CheckResultAny, *, flatten_detail: bool, wrap_width: int | None
) -> tuple[list[RenderableType], bool]:
    summary_lines = data_summary_lines(cr.data, flatten_detail=flatten_detail)
    show_raw = bool(cr.raw and cr.status is not Status.SKIPPED)
    if show_raw and raw_redundant_with_record_line(cr.raw, summary_lines):
        show_raw = False

    lines: list[RenderableType] = [
        Text.assemble("Status: ", (str(cr.status.value), _status_style(cr.status)))
    ]
    has_body = False
    if cr.error:
        has_body = True
        lines.append(
            _foldable_line(
                f"Error: {_truncate(cr.error, 500)}",
                style=_STYLE_BOLD_RED,
                wrap_width=wrap_width,
            )
        )
    if show_raw:
        has_body = True
        lines.append(
            _foldable_line(
                f"Raw: {_truncate(cr.raw)}", style=_STYLE_DIM, wrap_width=wrap_width
            )
        )
    for summary_line in summary_lines:
        has_body = True
        lines.append(
            _foldable_line(summary_line, style=_STYLE_DIM, wrap_width=wrap_width)
        )
    return lines, has_body


def _rich_append_issue_groups(
    lines: list[RenderableType],
    issues: Sequence[Issue],
    *,
    detail: bool,
    def_max: int,
    wrap_width: int | None,
) -> bool:
    added = False
    for group in issue_groups_for_display(issues):
        added = True
        p = group.primary
        n = group.count
        suffix = f" ({p.id})" if n == 1 else f" ({p.id}) ×{n}"
        lines.append(
            Text.assemble(
                "• ", (p.title, _severity_style(p.severity)), (suffix, _STYLE_DIM)
            )
        )
        for iss in group.issues:
            desc = truncate_finding_text(iss.description, max_len=def_max, full=detail)
            if desc:
                lines.append(
                    _foldable_line(
                        f"    {desc}", style=_STYLE_DIM, wrap_width=wrap_width
                    )
                )
            if detail and iss.remediation.strip():
                lines.append(
                    _foldable_line(
                        f"    Remediation: {iss.remediation}",
                        style=_STYLE_DIM_CYAN,
                        wrap_width=wrap_width,
                    )
                )
    return added


def _rich_append_recommendations(
    lines: list[RenderableType],
    cr: CheckResultAny,
    *,
    detail: bool,
    def_max: int,
    wrap_width: int | None,
) -> bool:
    added = False
    for rec in cr.recommendations:
        added = True
        lines.append(
            Text.assemble(
                "↳ ", (rec.title, _STYLE_ITALIC_CYAN), (f" ({rec.id})", _STYLE_DIM)
            )
        )
        desc = truncate_finding_text(rec.description, max_len=def_max, full=detail)
        if desc:
            lines.append(
                _foldable_line(f"    {desc}", style=_STYLE_DIM, wrap_width=wrap_width)
            )
    return added


def _check_panel(
    check_name: str,
    cr: CheckResultAny,
    *,
    options: SerialiserOptions,
    wrap_width: int | None = None,
) -> Panel:
    flatten_detail = options.spf_flatten_detail and check_name == "spf"
    lines, has_body = _rich_check_panel_status_and_data_lines(
        cr, flatten_detail=flatten_detail, wrap_width=wrap_width
    )

    detail = options.human_finding_detail
    def_max = DEFAULT_DESCRIPTION_MAX if not detail else 10_000

    if _rich_append_issue_groups(
        lines, cr.issues, detail=detail, def_max=def_max, wrap_width=wrap_width
    ):
        has_body = True

    if cr.issues and cr.recommendations:
        lines.append(Padding(Text(""), (1, 0, 0, 0)))

    if _rich_append_recommendations(
        lines, cr, detail=detail, def_max=def_max, wrap_width=wrap_width
    ):
        has_body = True

    if cr.status is Status.COMPLETED and not has_body:
        lines.append(Text("No issues or recommendations.", style=_STYLE_DIM))

    return Panel(
        Group(*lines),
        title=f"[bold]{check_name}[/bold]",
        border_style=_STYLE_BORDER_CHECK_PANEL,
    )


def _render_zone_checks(
    zone_node: OutputNode,
    console: Console,
    *,
    options: SerialiserOptions,
    skip_root_zone_headline: bool,
    apex: str | None,
) -> None:
    if not (skip_root_zone_headline and apex is not None and zone_node.title == apex):
        console.print()
        console.print(Text(zone_node.title, style=_STYLE_BOLD_UNDERLINE))
    if not zone_node.children:
        console.print(Text("  (no checks in this zone)", style=_STYLE_DIM))
        return
    ww = console.size.width
    wrap_width = ww if ww > 0 else None
    for ch in zone_node.children:
        if ch.kind != "check" or ch.payload is None:
            continue
        console.print(
            _check_panel(
                ch.check_name or ch.title,
                ch.payload,
                options=options,
                wrap_width=wrap_width,
            )
        )


def _render_header_panel(
    console: Console,
    *,
    domain: str,
    partial: bool,
    timestamp: datetime,
    manifest_target: str | None = None,
) -> None:
    """Print the green summary panel."""
    header = Table.grid(padding=(0, 2))
    header.add_column(style=_STYLE_BOLD)
    header.add_column()
    header.add_row("Domain", domain)
    if manifest_target is not None and manifest_target != domain:
        header.add_row("Target", manifest_target)
    header.add_row("Partial", "yes" if partial else "no")
    header.add_row("Timestamp", timestamp.isoformat())
    console.print(
        Panel(
            header,
            title="[bold]dnsight audit[/bold]",
            border_style=_STYLE_BORDER_HEADER_PANEL,
        )
    )


def _render_domain_body_from_node(
    node: OutputNode,
    console: Console,
    *,
    options: SerialiserOptions,
    skip_root_zone_headline: bool = False,
    apex_domain: str | None = None,
) -> None:
    """Print zone headings and check panels from a domain :class:`OutputNode`."""
    if node.kind != "domain":
        msg = "expected domain OutputNode"
        raise TypeError(msg)
    apex = apex_domain if apex_domain is not None else node.apex_domain
    for zone_node in node.children:
        if zone_node.kind != "zone":
            continue
        _render_zone_checks(
            zone_node,
            console,
            options=options,
            skip_root_zone_headline=skip_root_zone_headline,
            apex=apex,
        )


def _render_domain_full_from_node(
    node: OutputNode, console: Console, *, options: SerialiserOptions
) -> None:
    """Header + body for one domain tree."""
    if node.kind != "domain":
        msg = "expected domain OutputNode"
        raise TypeError(msg)
    if node.apex_domain is None or node.partial is None or node.timestamp is None:
        msg = "domain OutputNode missing metadata"
        raise ValueError(msg)
    _render_header_panel(
        console,
        domain=node.apex_domain,
        partial=node.partial,
        timestamp=node.timestamp,
        manifest_target=node.manifest_target,
    )
    _render_domain_body_from_node(
        node,
        console,
        options=options,
        skip_root_zone_headline=(node.manifest_target != node.apex_domain),
        apex_domain=node.apex_domain,
    )


def _group_results_by_apex(
    results: Sequence[DomainResult],
) -> tuple[list[str], dict[str, list[DomainResult]]]:
    """First-seen apex order with lists of results per apex domain."""
    order: list[str] = []
    groups: dict[str, list[DomainResult]] = {}
    for r in results:
        if r.domain not in groups:
            order.append(r.domain)
            groups[r.domain] = []
        groups[r.domain].append(r)
    return order, groups


class RichSerialiser(BaseDomainSerialiser):
    """Render one or more :class:`~dnsight.sdk.audit.models.DomainResult` with Rich."""

    def _serialise_batch(
        self, results: Sequence[DomainResult], *, options: SerialiserOptions
    ) -> str:
        """Return captured Rich output (ANSI when colours apply)."""
        console = Console(force_terminal=True, width=120)
        with console.capture() as capture:
            order, groups = _group_results_by_apex(results)
            first_apex = True
            for apex in order:
                grp = groups[apex]
                if not first_apex:
                    console.print()
                    console.print(Rule(style=_STYLE_DIM))
                    console.print()
                first_apex = False
                if len(grp) == 1:
                    _render_domain_full_from_node(
                        node_from_domain(grp[0]), console, options=options
                    )
                    continue
                combined_partial = any(r.partial for r in grp)
                _render_header_panel(
                    console,
                    domain=apex,
                    partial=combined_partial,
                    timestamp=grp[0].timestamp,
                    manifest_target=None,
                )
                for i, r in enumerate(grp):
                    if i:
                        console.print()
                    console.print(Text(r.target, style=_STYLE_BOLD_UNDERLINE))
                    dn = node_from_domain(r)
                    _render_domain_body_from_node(
                        dn,
                        console,
                        options=options,
                        skip_root_zone_headline=True,
                        apex_domain=r.domain,
                    )
        return capture.get()

    def serialise_live(
        self,
        result: DomainResult,
        console: Console | None = None,
        *,
        options: SerialiserOptions | None = None,
    ) -> None:
        """Print one domain audit to *console* (default: Rich stdout)."""
        opts = options or SerialiserOptions()
        _render_domain_full_from_node(
            node_from_domain(result), console or Console(), options=opts
        )
