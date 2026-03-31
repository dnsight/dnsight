"""SARIF 2.1.0 serialisation for :class:`~dnsight.core.models.DomainResult`."""

from __future__ import annotations

import json
from typing import Any

from dnsight import __version__
from dnsight.core.models import DomainResult
from dnsight.core.types import Severity
from dnsight.serialisers._zone import iter_flat_zones
from dnsight.serialisers.base import SerialiserProtocol


__all__ = ["SarifSerialiser"]

_RECOMMENDATION_RULE_PREFIX = "dnsight.recommendation."
_FAILED_CHECK_RULE_ID = "dnsight.check.failed"


def _severity_to_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _location_artifact(zone_fqdn: str) -> dict[str, Any]:
    return {"physicalLocation": {"artifactLocation": {"uri": zone_fqdn}}}


def _issue_results(result: DomainResult) -> list[dict[str, Any]]:
    return [
        {
            "ruleId": issue.id,
            "level": _severity_to_level(issue.severity),
            "message": {"text": issue.title},
            "locations": [_location_artifact(zone_fqdn)],
        }
        for zone_fqdn, issue in result.all_issues
    ]


def _failed_check_results(result: DomainResult) -> list[dict[str, Any]]:
    return [
        {
            "ruleId": _FAILED_CHECK_RULE_ID,
            "level": "error",
            "message": {"text": cr.error},
            "locations": [_location_artifact(zone.zone)],
            "properties": {"check": check_name},
        }
        for zone in iter_flat_zones(result)
        for check_name, cr in zone.results.items()
        if cr.failed and cr.error
    ]


def _recommendation_results(result: DomainResult) -> list[dict[str, Any]]:
    return [
        {
            "ruleId": f"{_RECOMMENDATION_RULE_PREFIX}{rec.id}",
            "level": "note",
            "message": {"text": rec.title},
            "locations": [_location_artifact(zone.zone)],
            "properties": {"check": check_name, "description": rec.description},
        }
        for zone in iter_flat_zones(result)
        for check_name, cr in zone.results.items()
        for rec in cr.recommendations
    ]


def _sarif_document(result: DomainResult) -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dnsight",
                        "version": __version__,
                        "informationUri": "https://github.com/dnsight/dnsight",
                    }
                },
                "invocations": [{"executionSuccessful": not result.partial}],
                "results": _issue_results(result)
                + _failed_check_results(result)
                + _recommendation_results(result),
                "properties": {
                    "domain": result.domain,
                    "timestamp": result.timestamp.isoformat(),
                    "configVersion": result.config_version,
                },
            }
        ],
    }


class SarifSerialiser(SerialiserProtocol):
    """Serialise a :class:`~dnsight.core.models.DomainResult` as SARIF 2.1.0."""

    def serialise(self, result: DomainResult) -> str:
        """Return the full formatted output for *result*."""
        return json.dumps(_sarif_document(result), indent=2)
