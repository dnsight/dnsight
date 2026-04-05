"""Rich console serialisation for domain audits (single or batch)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from dnsight.core.models import CheckResultAny
from dnsight.core.types import Severity, Status
from dnsight.sdk.audit.models import DomainResult
from dnsight.serialisers._data_summary import data_summary_lines
from dnsight.serialisers.base import BaseDomainSerialiser, SerialiserOptions
from dnsight.serialisers.tree import OutputNode, node_from_domain


__all__ = ["RichSerialiser"]

_RAW_MAX_LEN = 600


def _truncate(text: str | None, max_len: int = _RAW_MAX_LEN) -> str:
    if not text:
        return ""
    single = " ".join(text.splitlines())
    if len(single) <= max_len:
        return single
    return single[: max_len - 1] + "…"


def _severity_style(severity: Severity) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }[str(severity.value)]


def _status_style(status: Status) -> str:
    return {
        "completed": "green",
        "partial": "yellow",
        "failed": "bold red",
        "skipped": "dim",
    }[str(status.value)]


def _check_panel(check_name: str, cr: CheckResultAny, *, flatten_detail: bool) -> Panel:
    lines: list[RenderableType] = [
        Text.assemble("Status: ", (str(cr.status.value), _status_style(cr.status)))
    ]
    if cr.error:
        lines.append(Text(f"Error: {_truncate(cr.error, 500)}", style="bold red"))
    if cr.raw and cr.status is not Status.SKIPPED:
        lines.append(Text(f"Raw: {_truncate(cr.raw)}", style="dim"))
    for summary_line in data_summary_lines(cr.data, flatten_detail=flatten_detail):
        lines.append(Text(summary_line, style="dim"))
    for issue in cr.issues:
        lines.append(
            Text.assemble(
                "• ",
                (issue.title, _severity_style(issue.severity)),
                (f" ({issue.id})", "dim"),
            )
        )
    for rec in cr.recommendations:
        lines.append(Text(f"↳ {rec.title}", style="italic cyan"))
    if not lines:
        lines.append(Text("---", style="dim"))
    return Panel(Group(*lines), title=f"[bold]{check_name}[/bold]", border_style="blue")


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
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Domain", domain)
    if manifest_target is not None and manifest_target != domain:
        header.add_row("Target", manifest_target)
    header.add_row("Partial", "yes" if partial else "no")
    header.add_row("Timestamp", timestamp.isoformat())
    console.print(
        Panel(header, title="[bold]dnsight audit[/bold]", border_style="green")
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
        if not (
            skip_root_zone_headline and apex is not None and zone_node.title == apex
        ):
            console.print()
            console.print(Text(zone_node.title, style="bold underline"))
        if not zone_node.children:
            console.print(Text("  (no checks in this zone)", style="dim"))
            continue
        for ch in zone_node.children:
            if ch.kind != "check" or ch.payload is None:
                continue
            fd = options.spf_flatten_detail and ch.check_name == "spf"
            console.print(
                _check_panel(ch.check_name or ch.title, ch.payload, flatten_detail=fd)
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
                    console.print(Rule(style="dim"))
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
                    console.print(Text(r.target, style="bold underline"))
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
