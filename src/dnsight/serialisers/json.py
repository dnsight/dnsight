"""JSON serialisation for :class:`~dnsight.core.models.DomainResult`."""

from __future__ import annotations

import json
from typing import Any

from dnsight.core.models import CheckResultAny, DomainResult, ZoneResult
from dnsight.serialisers._zone import iter_flat_zones
from dnsight.serialisers.base import SerialiserProtocol


__all__ = ["JsonSerialiser"]


def _check_to_dict(cr: CheckResultAny) -> dict[str, Any]:
    return cr.model_dump(mode="json")


def _zone_to_dict(zone: ZoneResult) -> dict[str, Any]:
    return {
        "zone": zone.zone,
        "parent": zone.parent,
        "results": {name: _check_to_dict(cr) for name, cr in zone.results.items()},
    }


def _domain_to_dict(result: DomainResult) -> dict[str, Any]:
    return {
        "domain": result.domain,
        "timestamp": result.timestamp.isoformat(),
        "config_version": result.config_version,
        "partial": result.partial,
        "zones": [_zone_to_dict(z) for z in iter_flat_zones(result)],
    }


class JsonSerialiser(SerialiserProtocol):
    """Serialise :class:`~dnsight.core.models.DomainResult` to JSON."""

    def serialise(self, result: DomainResult) -> str:
        """Return the full formatted output for *result*."""
        return json.dumps(_domain_to_dict(result), indent=2)
