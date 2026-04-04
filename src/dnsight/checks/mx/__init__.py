"""MX check: check class and public API."""

from __future__ import annotations

from typing import Any

from dnsight.checks.base import BaseCheck
from dnsight.checks.mx.models import (
    MXData,
    MXGenerateParams,
    MXGenerateTarget,
    MXIssueId,
    MXRecommendationId,
)
from dnsight.checks.mx.rules import (
    build_mx_generated_value,
    collect_mx_data,
    extract_mx_config,
    normalise_config,
    validate_mx_results,
)
from dnsight.core.config.blocks import Config, MxConfig
from dnsight.core.models import CheckResult, GeneratedRecord
from dnsight.core.registry import register
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.dns import get_resolver
from dnsight.utils.smtp import get_starttls_probe


__all__ = [
    "MXCheck",
    "MXData",
    "MXGenerateParams",
    "MXGenerateTarget",
    "MXIssueId",
    "MXRecommendationId",
    "check_mx",
    "generate_mx",
    "get_mx",
]


@register
class MXCheck(BaseCheck[MXData, MXGenerateParams]):
    """MX check: MX resolution and optional PTR/STARTTLS; GENERATE for suggested MX lines."""

    name = "mx"
    capabilities = frozenset({Capability.CHECK, Capability.GENERATE})

    @staticmethod
    async def get_mx(domain: str, *, config: Config | MxConfig | None = None) -> MXData:
        """Resolve MX (and optional PTR / STARTTLS) for *domain*."""
        mx_cfg = extract_mx_config(config)
        return await collect_mx_data(
            domain, get_resolver(), get_starttls_probe(), mx_cfg
        )

    @staticmethod
    async def check_mx(
        domain: str, *, config: Config | MxConfig | None = None
    ) -> CheckResult[MXData]:
        """Fetch, parse, and validate MX for *domain*."""
        mx_cfg, _ = normalise_config(config)
        try:
            data = await collect_mx_data(
                domain, get_resolver(), get_starttls_probe(), mx_cfg
            )
            issues, recommendations = validate_mx_results(data, domain, mx_cfg)
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

    @staticmethod
    def generate_mx(
        *,
        params: MXGenerateParams | None = None,
        config: Config | MxConfig | None = None,
    ) -> GeneratedRecord:
        """Generate apex MX RDATA lines (preference and exchange per line).

        If *params* is omitted and *config* is set, builds params via
        :meth:`MXGenerateParams.from_config` (empty targets unless you pass *params*).
        At least one target is required.
        """
        if params is None and config is not None:
            params = MXGenerateParams.from_config(extract_mx_config(config))
        p = params or MXGenerateParams()
        value = build_mx_generated_value(p)
        return GeneratedRecord(record_type=RecordType.MX, host="@", value=value)

    async def _get(self, domain: str, *, config: Any | None = None) -> MXData:
        return await self.get_mx(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[MXData]:
        return await self.check_mx(domain, config=config)

    def _generate(self, *, params: MXGenerateParams) -> GeneratedRecord:
        return self.generate_mx(params=params)


get_mx = MXCheck.get_mx
check_mx = MXCheck.check_mx
generate_mx = MXCheck.generate_mx
