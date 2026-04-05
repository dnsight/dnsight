"""JSON serialisation for :class:`~dnsight.sdk.audit.models.DomainResult` (single or batch)."""

from __future__ import annotations

from collections.abc import Sequence
import json
from typing import Any

from dnsight.core.models import CheckResultAny
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers._zone import iter_flat_zones
from dnsight.serialisers.base import BaseDomainSerialiser, SerialiserOptions


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
        "target": result.target,
        "timestamp": result.timestamp.isoformat(),
        "config_version": result.config_version,
        "partial": result.partial,
        "zones": [_zone_to_dict(z) for z in iter_flat_zones(result)],
    }


class JsonSerialiser(BaseDomainSerialiser):
    """Serialise one or more :class:`~dnsight.sdk.audit.models.DomainResult` to JSON."""

    def _serialise_batch(
        self, results: Sequence[DomainResult], *, options: SerialiserOptions
    ) -> str:
        _ = options
        doc = {"domains": [_domain_to_dict(d) for d in results]}
        return json.dumps(doc, indent=2)
