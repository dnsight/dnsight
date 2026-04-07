"""Pure functions: assemble nested zone trees from flat DFS zone rows."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from dnsight.sdk.audit.models import ZoneResult


__all__ = ["nest_flat_zone_results"]


def nest_flat_zone_results(flat: Sequence[ZoneResult]) -> ZoneResult:
    """Build a nested :class:`ZoneResult` tree from DFS-preorder leaf rows.

    Each input row must have ``children == []`` and correct ``parent`` (``None``
    for the root). Order must match depth-first preorder (root first).
    """
    if not flat:
        msg = "flat zone list must not be empty"
        raise ValueError(msg)
    by_zone = {z.zone: z for z in flat}
    if len(by_zone) != len(flat):
        msg = "duplicate zone FQDN in flat zone list"
        raise ValueError(msg)

    children_order: dict[str | None, list[str]] = defaultdict(list)
    for z in flat:
        children_order[z.parent].append(z.zone)

    roots = children_order[None]
    if len(roots) != 1:
        msg = f"expected exactly one root zone, got {roots!r}"
        raise ValueError(msg)

    def build(name: str) -> ZoneResult:
        base = by_zone[name]
        child_names = children_order.get(name, [])
        built_children = [build(c) for c in child_names]
        return base.model_copy(update={"children": built_children})

    return build(roots[0])
