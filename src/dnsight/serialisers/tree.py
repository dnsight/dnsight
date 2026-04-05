"""Hierarchical output tree for serialisers (check, zone, domain, audit)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from dnsight.core.models import CheckResultAny
from dnsight.sdk.audit.models import AuditResult, DomainResult, ZoneResult
from dnsight.serialisers._zone import iter_flat_zones


__all__ = [
    "OutputNode",
    "node_from_audit",
    "node_from_check",
    "node_from_domain",
    "node_from_domain_batch",
]

OutputKind = Literal["check", "zone", "domain", "audit"]


@dataclass(frozen=True, slots=True)
class OutputNode:
    """One node in a parent/child tree for format backends.

    * **check** — leaf with ``payload`` set.
    * **zone** — children are check nodes (and optionally nested structure via domain).
    * **domain** — metadata fields apply; children are zone nodes (flat DFS order).
    * **audit** — children are domain nodes.
    """

    kind: OutputKind
    title: str
    children: tuple[OutputNode, ...] = ()
    check_name: str | None = None
    payload: CheckResultAny | None = None
    partial: bool | None = None
    timestamp: datetime | None = None
    manifest_target: str | None = None
    apex_domain: str | None = None
    config_version: int | None = None


def node_from_check(
    *,
    domain: str,
    check_name: str,
    result: CheckResultAny,
    timestamp: datetime | None = None,
    config_version: int = 0,
) -> OutputNode:
    """Single-check CLI view: one domain-shaped root with one zone and one check."""
    d = DomainResult(
        domain=domain,
        target=domain,
        timestamp=timestamp or datetime.now(UTC),
        config_version=config_version,
        zones=[
            ZoneResult(
                zone=domain, parent=None, children=[], results={check_name: result}
            )
        ],
        partial=result.partial or result.failed,
    )
    return node_from_domain(d)


def node_from_domain(result: DomainResult) -> OutputNode:
    """One :class:`~dnsight.sdk.audit.models.DomainResult` as domain → zones → checks."""
    zone_nodes: list[OutputNode] = []
    for z in iter_flat_zones(result):
        check_children = tuple(
            OutputNode(
                kind="check", title=name, children=(), check_name=name, payload=cr
            )
            for name, cr in sorted(z.results.items())
        )
        zone_nodes.append(
            OutputNode(kind="zone", title=z.zone, children=check_children)
        )
    return OutputNode(
        kind="domain",
        title=result.target,
        children=tuple(zone_nodes),
        partial=result.partial,
        timestamp=result.timestamp,
        manifest_target=result.target,
        apex_domain=result.domain,
        config_version=result.config_version,
    )


def node_from_domain_batch(results: Sequence[DomainResult]) -> OutputNode:
    """Multiple domain audits under one audit root (manifest / multi-CLI domains)."""
    if not results:
        msg = "domain batch must not be empty"
        raise ValueError(msg)
    ts = results[0].timestamp
    cv = results[0].config_version
    return OutputNode(
        kind="audit",
        title="batch",
        children=tuple(node_from_domain(d) for d in results),
        partial=any(d.partial for d in results),
        timestamp=ts,
        config_version=cv,
    )


def node_from_audit(result: AuditResult) -> OutputNode:
    """Manifest batch as audit → domains → zones → checks."""
    return OutputNode(
        kind="audit",
        title="batch",
        children=tuple(node_from_domain(d) for d in result.domains),
        partial=result.partial,
        timestamp=result.timestamp,
        config_version=result.config_version,
    )
