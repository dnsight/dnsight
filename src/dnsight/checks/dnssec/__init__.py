"""DNSSEC check: chain of trust and negative proofs."""

from __future__ import annotations

from typing import Any

import dns.name

from dnsight.checks.base import BaseCheck, BaseGenerateParams
from dnsight.checks.dnssec.models import (
    DNSSECData,
    DNSSECIssueId,
    DNSSECRecommendationId,
    extract_dnssec_config,
    issue_descriptor,
    recommendation_descriptor,
)
from dnsight.checks.dnssec.rules import collect_dnssec_data, validate_dnssec_results
from dnsight.core.config.blocks import Config, DnssecConfig
from dnsight.core.models import CheckResult
from dnsight.core.registry import register
from dnsight.core.types import Capability, Status
from dnsight.utils.dns import get_resolver


__all__ = [
    "DNSSECCheck",
    "DNSSECData",
    "DNSSECIssueId",
    "DNSSECRecommendationId",
    "check_dnssec",
    "get_dnssec",
    "issue_descriptor",
    "recommendation_descriptor",
]


@register
class DNSSECCheck(BaseCheck[DNSSECData, BaseGenerateParams]):
    """DNSSEC check: delegation DS, DNSKEY/RRSIG, NS, NSEC/NSEC3 proofs."""

    name = "dnssec"
    capabilities = frozenset({Capability.CHECK})

    @staticmethod
    async def get_dnssec(
        domain: str, *, config: Config | DnssecConfig | None = None
    ) -> DNSSECData:
        """Fetch DS, DNSKEY, NS, and DNSSEC probe results for *domain*."""
        cfg = extract_dnssec_config(config)
        data, _dk, _ns, _nx = await collect_dnssec_data(domain, get_resolver(), cfg)
        return data

    @staticmethod
    async def check_dnssec(
        domain: str, *, config: Config | DnssecConfig | None = None
    ) -> CheckResult[DNSSECData]:
        """Run the full DNSSEC check for *domain*."""
        cfg = extract_dnssec_config(config)
        resolver = get_resolver()
        zone_name = dns.name.from_text(domain.strip().rstrip("."), dns.name.root)
        try:
            data, dk_msg, ns_msg, nx_msg = await collect_dnssec_data(
                domain, resolver, cfg
            )
            issues, recommendations = validate_dnssec_results(
                data, cfg, zone_name, dk_msg, ns_msg, nx_msg
            )
            return CheckResult(
                status=Status.COMPLETED,
                data=data,
                raw=None,
                issues=issues,
                recommendations=recommendations,
                error=None,
            )
        except Exception as exc:
            if isinstance(exc, BaseException) and not isinstance(exc, Exception):
                raise
            return CheckResult(
                status=Status.FAILED,
                data=None,
                raw=None,
                issues=[],
                recommendations=[],
                error=str(exc),
            )

    async def _get(self, domain: str, *, config: Any | None = None) -> DNSSECData:
        return await self.get_dnssec(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[DNSSECData]:
        return await self.check_dnssec(domain, config=config)


get_dnssec = DNSSECCheck.get_dnssec
check_dnssec = DNSSECCheck.check_dnssec
