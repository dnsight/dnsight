"""DKIM check: check class and public API."""

from __future__ import annotations

from typing import Any

from dnsight.checks.base import BaseCheck, BaseGenerateParams
from dnsight.checks.dkim.models import DKIMData, DKIMIssueId, DKIMRecommendationId
from dnsight.checks.dkim.rules import (
    collect_dkim_data,
    extract_dkim_config,
    normalise_config,
    validate_dkim_results,
)
from dnsight.core.config.blocks import Config, DkimConfig
from dnsight.core.models import CheckResult
from dnsight.core.registry import register
from dnsight.core.types import Capability, Status
from dnsight.utils.dns import get_resolver


__all__ = [
    "DKIMCheck",
    "DKIMData",
    "DKIMIssueId",
    "DKIMRecommendationId",
    "check_dkim",
    "get_dkim",
]


@register
class DKIMCheck(BaseCheck[DKIMData, BaseGenerateParams]):
    """DKIM check: CHECK only (TXT at selector._domainkey)."""

    name = "dkim"
    capabilities = frozenset({Capability.CHECK})

    @staticmethod
    async def get_dkim(
        domain: str, *, config: Config | DkimConfig | None = None
    ) -> DKIMData:
        """Fetch and parse DKIM records for each configured selector.

        Per-selector DNS failures (NODATA) are treated as missing records;
        they do not raise.

        Args:
            domain: Signing domain (e.g. ``"example.com"``).
            config: Optional full ``Config`` or ``DkimConfig`` slice.

        Returns:
            ``DKIMData`` with ``selectors_tried`` and ``selectors_found``.
        """
        dkim_cfg = extract_dkim_config(config)
        return await collect_dkim_data(domain, get_resolver(), dkim_cfg)

    @staticmethod
    async def check_dkim(
        domain: str, *, config: Config | DkimConfig | None = None
    ) -> CheckResult[DKIMData]:
        """Fetch, parse, and validate DKIM for *domain*."""
        dkim_cfg, strict = normalise_config(config)
        try:
            data = await collect_dkim_data(domain, get_resolver(), dkim_cfg)
            issues, recommendations = validate_dkim_results(
                data, domain, dkim_cfg, strict
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

    async def _get(self, domain: str, *, config: Any | None = None) -> DKIMData:
        return await self.get_dkim(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[DKIMData]:
        return await self.check_dkim(domain, config=config)


get_dkim = DKIMCheck.get_dkim
check_dkim = DKIMCheck.check_dkim
