"""HTTP security headers check: check class and public API."""

from __future__ import annotations

from typing import Any

from dnsight.checks.base import BaseCheck
from dnsight.checks.headers.models import (
    CspGenerateParams,
    GenerateKind,
    HeaderResult,
    HeadersData,
    HeadersGenerateParams,
    HeadersIssueId,
    HeadersRecommendationId,
    HstsGenerateParams,
    issue_descriptor,
)
from dnsight.checks.headers.rules import (
    extract_headers_config,
    fetch_headers_data,
    generate_header_record_value,
    normalise_config,
    validate_headers,
)
from dnsight.core.config.blocks import Config, HeadersConfig
from dnsight.core.models import CheckResult, GeneratedRecord
from dnsight.core.registry import register
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.http import get_http_client


__all__ = [
    "HeadersCheck",
    "HeadersData",
    "CspGenerateParams",
    "GenerateKind",
    "HeaderResult",
    "HeadersGenerateParams",
    "HeadersIssueId",
    "HeadersRecommendationId",
    "HstsGenerateParams",
    "issue_descriptor",
    "check_headers",
    "generate_headers",
    "get_headers",
]


@register
class HeadersCheck(BaseCheck[HeadersData, HeadersGenerateParams]):
    """HTTP security headers check: CHECK + GENERATE (CSP / HSTS lines)."""

    name = "headers"
    capabilities = frozenset({Capability.CHECK, Capability.GENERATE})

    @staticmethod
    async def get_headers(
        domain: str, *, config: Config | HeadersConfig | None = None
    ) -> HeadersData:
        """Fetch response headers from the first successful probe URL."""
        cfg = extract_headers_config(config)
        client = get_http_client()
        return await fetch_headers_data(domain, cfg, client)

    @staticmethod
    async def check_headers(
        domain: str, *, config: Config | HeadersConfig | None = None
    ) -> CheckResult[HeadersData]:
        """Probe HTTP(S), validate required security headers, return issues."""
        cfg, strict = normalise_config(config)
        client = get_http_client()
        try:
            data = await fetch_headers_data(domain, cfg, client)
            issues, recommendations = validate_headers(
                data, cfg, strict_recommendations=strict
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

    @staticmethod
    def generate_headers(
        *, params: HeadersGenerateParams | None = None
    ) -> GeneratedRecord:
        """Generate a ``Content-Security-Policy`` or ``Strict-Transport-Security`` line.

        Args:
            params: CSP or HSTS params. Defaults to a sensible HSTS line when
                omitted.
        """
        p: HeadersGenerateParams = params or HstsGenerateParams()
        return GeneratedRecord(
            record_type=RecordType.HTTP_HEADER,
            host="",
            value=generate_header_record_value(p),
        )

    async def _get(self, domain: str, *, config: Any | None = None) -> HeadersData:
        return await self.get_headers(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[HeadersData]:
        return await self.check_headers(domain, config=config)

    def _generate(self, *, params: HeadersGenerateParams) -> GeneratedRecord:
        return self.generate_headers(params=params)


get_headers = HeadersCheck.get_headers
check_headers = HeadersCheck.check_headers
generate_headers = HeadersCheck.generate_headers
