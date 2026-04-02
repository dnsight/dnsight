"""Rich console serialisation for :class:`~dnsight.core.models.DomainResult` (single or batch)."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from dnsight.core.models import CheckResultAny, DomainResult
from dnsight.core.types import Severity, Status
from dnsight.serialisers._data_summary import data_summary_lines
from dnsight.serialisers._zone import iter_flat_zones
from dnsight.serialisers.base import BaseDomainSerialiser, SerialiserOptions


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


def _render_audit(
    result: DomainResult, console: Console, *, options: SerialiserOptions
) -> None:
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Domain", result.domain)
    header.add_row("Partial", "yes" if result.partial else "no")
    header.add_row("Timestamp", result.timestamp.isoformat())
    console.print(
        Panel(header, title="[bold]dnsight audit[/bold]", border_style="green")
    )

    for zone in iter_flat_zones(result):
        console.print()
        console.print(Text(zone.zone, style="bold underline"))
        if not zone.results:
            console.print(Text("  (no checks in this zone)", style="dim"))
            continue
        for name, cr in sorted(zone.results.items()):
            fd = options.spf_flatten_detail and name == "spf"
            console.print(_check_panel(name, cr, flatten_detail=fd))


class RichSerialiser(BaseDomainSerialiser):
    """Render one or more :class:`~dnsight.core.models.DomainResult` with Rich."""

    def _serialise_batch(
        self, results: Sequence[DomainResult], *, options: SerialiserOptions
    ) -> str:
        """Return captured Rich output (ANSI when colours apply)."""
        console = Console(force_terminal=True, width=120)
        with console.capture() as capture:
            for i, r in enumerate(results):
                if i:
                    console.print()
                    console.print(Rule(style="dim"))
                    console.print()
                _render_audit(r, console, options=options)
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
        _render_audit(result, console or Console(), options=opts)
