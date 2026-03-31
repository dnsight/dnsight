"""Flat zone ordering for serialisers.

Serialisers walk the :class:`~dnsight.core.models.ZoneResult` tree in a single
canonical order so JSON, SARIF, Markdown, and Rich stay aligned.
"""

from __future__ import annotations

from collections.abc import Iterator

from dnsight.core.models import DomainResult, ZoneResult


__all__ = ["iter_flat_zones"]


def _iter_zone_subtree(zone: ZoneResult) -> Iterator[ZoneResult]:
    yield zone
    for child in zone.children:
        yield from _iter_zone_subtree(child)


def iter_flat_zones(result: DomainResult) -> Iterator[ZoneResult]:
    """Yield every zone in depth-first pre-order.
    For each top-level entry in ``result.zones`` (in list order, root first),
    yields that zone, then recursively yields each child in ``children`` order
    before continuing with the next sibling. Each node appears once; a node's
    :attr:`~dnsight.core.models.ZoneResult.results` apply only to that FQDN.
    Args:
        result: Audit result whose zone trees should be flattened.
    Yields:
        Each :class:`~dnsight.core.models.ZoneResult` in canonical DFS order.
    """

    for root in result.zones:
        yield from _iter_zone_subtree(root)
