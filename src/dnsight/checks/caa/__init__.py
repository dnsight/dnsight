"""CAA check: per-name CAA inventory, issuer policy, optional crt.sh, GENERATE."""

from __future__ import annotations

from typing import Any

from dnsight.checks.base import BaseCheck
from dnsight.checks.caa.models import (
    CAAData,
    CaaGenerateParams,
    CaaIssueId,
    CaaRecommendationId,
)
from dnsight.checks.caa.rules import (
    apply_caa_validation,
    build_generated_value,
    crt_sh_issues,
    gather_caa_data,
)
from dnsight.core.config.blocks import CaaConfig, Config
from dnsight.core.models import CheckResult, GeneratedRecord
from dnsight.core.registry import register
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.dns import get_resolver
from dnsight.utils.http import get_http_client


__all__ = [
    "CAACheck",
    "CAAData",
    "CaaGenerateParams",
    "CaaIssueId",
    "CaaRecommendationId",
    "check_caa",
    "generate_caa",
    "get_caa",
]


def _normalise_config(config: Config | CaaConfig | None) -> tuple[CaaConfig, bool]:
    """Return CaaConfig and strict_recommendations from root Config when present."""
    if config is None:
        return CaaConfig(), False
    if isinstance(config, Config):
        return config.caa, config.strict_recommendations
    return config, False


@register
class CAACheck(BaseCheck[CAAData, CaaGenerateParams]):
    """CAA check: CHECK + GENERATE."""

    name = "caa"
    capabilities = frozenset({Capability.CHECK, Capability.GENERATE})

    @staticmethod
    async def get_caa(
        domain: str, *, config: Config | CaaConfig | None = None
    ) -> CAAData:
        """Fetch CAA inventory for *domain* (zone apex) without policy validation."""
        cfg, _ = _normalise_config(config)
        data, _issues = await gather_caa_data(domain, cfg, get_resolver())
        return data

    @staticmethod
    async def check_caa(
        domain: str, *, config: Config | CaaConfig | None = None
    ) -> CheckResult[CAAData]:
        """Fetch, validate CAA policy for discovered names, optional crt.sh."""
        cfg, strict = _normalise_config(config)
        try:
            data, gather_issues = await gather_caa_data(domain, cfg, get_resolver())
            val_issues, recs = apply_caa_validation(
                data, cfg, strict_recommendations=strict
            )
            issues = list(gather_issues) + list(val_issues)
            if cfg.cross_reference_crt_sh:
                issues.extend(
                    await crt_sh_issues(
                        domain, data.names_checked, cfg, get_http_client()
                    )
                )
            return CheckResult(
                status=Status.COMPLETED,
                data=data,
                raw=None,
                issues=issues,
                recommendations=recs,
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

    @staticmethod
    def generate_caa(*, params: CaaGenerateParams) -> GeneratedRecord:
        """Generate newline-separated CAA RDATA for a zone file."""
        value = build_generated_value(params)
        return GeneratedRecord(record_type=RecordType.CAA, host="@", value=value)

    async def _get(self, domain: str, *, config: Any | None = None) -> CAAData:
        return await self.get_caa(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[CAAData]:
        return await self.check_caa(domain, config=config)

    def _generate(self, *, params: CaaGenerateParams) -> GeneratedRecord:
        return self.generate_caa(params=params)


get_caa = CAACheck.get_caa
check_caa = CAACheck.check_caa
generate_caa = CAACheck.generate_caa
