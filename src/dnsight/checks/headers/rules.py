"""Headers check: URL probing, header extraction, validation, and generation."""

from __future__ import annotations

import re

from dnsight.checks.headers.models import (
    CspGenerateParams,
    HeaderResult,
    HeadersData,
    HeadersIssueId,
    HeadersRecommendationId,
    HstsGenerateParams,
    issue_descriptor,
)
from dnsight.core.config.blocks import Config, HeadersConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.models import Issue, Recommendation
from dnsight.core.schema.headers import HeadersSchema
from dnsight.utils.http import HTTPClient, HTTPResponse


__all__ = [
    "build_csp_header_value",
    "build_hsts_header_value",
    "extract_headers_config",
    "fetch_headers_data",
    "normalise_config",
    "probe_urls",
    "validate_headers",
    "generate_header_record_value",
]


def extract_headers_config(config: Config | HeadersConfig | None) -> HeadersConfig:
    """Return ``HeadersConfig`` from a full config or a headers slice."""
    if config is None:
        return HeadersConfig()
    if isinstance(config, HeadersConfig):
        return config
    return config.headers


def normalise_config(
    config: Config | HeadersConfig | None,
) -> tuple[HeadersConfig, bool]:
    """Return headers config and ``strict_recommendations`` from root config."""
    if config is None:
        return HeadersConfig(), False
    if isinstance(config, HeadersConfig):
        return config, False
    return config.headers, config.strict_recommendations


def probe_urls(domain: str, cfg: HeadersConfig) -> list[str]:
    """URLs to GET, in order."""
    if cfg.urls:
        return list(cfg.urls)
    d = domain.strip().rstrip(".")
    return [f"https://{d}", f"https://www.{d}"]


def _norm_require_token(raw: str) -> str:
    return raw.strip().upper().replace(" ", "_").replace("-", "_")


def _header_lookup(response_headers: dict[str, str], canonical_name: str) -> str | None:
    lower = canonical_name.lower()
    for k, v in response_headers.items():
        if k.lower() == lower:
            return v
    return None


def _hsts_max_age_ok(value: str) -> bool:
    """True if Strict-Transport-Security has a positive max-age."""
    for part in value.split(";"):
        part = part.strip()
        m = re.match(r"^max-age\s*=\s*(\d+)\s*$", part, re.IGNORECASE)
        if m:
            return int(m.group(1)) > 0
    return False


def _hsts_has_include_subdomains(value: str) -> bool:
    return any(part.strip().lower() == "includesubdomains" for part in value.split(";"))


def _issue_for_missing_token(norm: str) -> HeadersIssueId | None:
    return {
        "HSTS": HeadersIssueId.HSTS_MISSING,
        "CSP": HeadersIssueId.CSP_MISSING,
        "X_FRAME_OPTIONS": HeadersIssueId.X_FRAME_OPTIONS_MISSING,
        "PERMISSIONS_POLICY": HeadersIssueId.PERMISSIONS_POLICY_MISSING,
        "X_CONTENT_TYPE_OPTIONS": HeadersIssueId.X_CONTENT_TYPE_OPTIONS_MISSING,
    }.get(norm)


def build_header_results(
    response_headers: dict[str, str], require: list[str]
) -> list[HeaderResult]:
    """Build ``HeaderResult`` rows for each required token."""
    out: list[HeaderResult] = []
    for raw in require:
        norm = _norm_require_token(raw)
        name = HeadersSchema.REQUIRE_TOKEN_TO_HEADER_NAME.get(norm, raw.strip())
        val = _header_lookup(response_headers, name)
        out.append(HeaderResult(name=name, present=val is not None, value=val))
    return out


async def fetch_headers_data(
    domain: str, cfg: HeadersConfig, client: HTTPClient
) -> HeadersData:
    """Probe URLs in order; use the first successful GET response.

    Raises:
        CheckError: If there are no URLs to probe (empty domain and empty urls).
    """
    urls = probe_urls(domain, cfg)
    if not urls:
        return HeadersData(url="", headers=[], fetch_error="No URLs to probe.")

    last_err = ""
    for url in urls:
        try:
            resp = await client.get(url)
            return _data_from_response(url, resp, cfg)
        except CheckError as exc:
            last_err = str(exc)
            continue

    return HeadersData(
        url=urls[0],
        headers=build_header_results({}, cfg.require),
        fetch_error=last_err or "All HTTP requests failed.",
    )


def _data_from_response(
    url: str, resp: HTTPResponse, cfg: HeadersConfig
) -> HeadersData:
    return HeadersData(
        url=url,
        headers=build_header_results(resp.headers, cfg.require),
        fetch_error=None,
    )


def validate_headers(
    data: HeadersData, cfg: HeadersConfig, *, strict_recommendations: bool = False
) -> tuple[list[Issue], list[Recommendation]]:
    """Validate fetched header rows against policy.

    Args:
        data: Parsed probe data.
        cfg: Headers config (required tokens).
        strict_recommendations: Ignored for now; reserved for alignment with
            other checks.
    """
    del strict_recommendations
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []

    if data.fetch_error:
        d = issue_descriptor(HeadersIssueId.FETCH_FAILED)
        issues.append(
            Issue(
                id=HeadersIssueId.FETCH_FAILED,
                severity=d.severity,
                title="HTTP fetch failed",
                description=(
                    "Could not retrieve any configured URL to inspect response headers. "
                    f"Last error: {data.fetch_error}"
                ),
                remediation=(
                    "Ensure the site is reachable over HTTPS and URLs in "
                    "config are correct."
                ),
            )
        )
        return issues, recommendations

    for i, raw in enumerate(cfg.require):
        if i >= len(data.headers):
            break
        hr = data.headers[i]
        norm = _norm_require_token(raw)
        missing_issue = _issue_for_missing_token(norm)

        if norm == "HSTS":
            if not hr.present:
                di = issue_descriptor(HeadersIssueId.HSTS_MISSING)
                issues.append(
                    Issue(
                        id=HeadersIssueId.HSTS_MISSING,
                        severity=di.severity,
                        title="Strict-Transport-Security missing",
                        description="The response did not include an HSTS header.",
                        remediation="Send a Strict-Transport-Security header on HTTPS responses.",
                    )
                )
                recommendations.append(
                    Recommendation(
                        id=HeadersRecommendationId.ADD_HSTS,
                        title="Add HSTS",
                        description=(
                            "Send a Strict-Transport-Security header with a long "
                            "max-age on HTTPS responses."
                        ),
                    )
                )
            elif hr.value is not None and not _hsts_max_age_ok(hr.value):
                di = issue_descriptor(HeadersIssueId.HSTS_NOT_SECURE)
                issues.append(
                    Issue(
                        id=HeadersIssueId.HSTS_NOT_SECURE,
                        severity=di.severity,
                        title="HSTS max-age is weak or absent",
                        description=(
                            "Strict-Transport-Security must include max-age with a "
                            "positive value."
                        ),
                        remediation="Set max-age to at least one year for production sites.",
                    )
                )
            elif (
                hr.present
                and hr.value is not None
                and _hsts_max_age_ok(hr.value)
                and not _hsts_has_include_subdomains(hr.value)
            ):
                recommendations.append(
                    Recommendation(
                        id=HeadersRecommendationId.INCLUDE_SUBDOMAINS_HSTS,
                        title="Include subdomains in HSTS",
                        description=(
                            "Consider adding includeSubDomains so browsers apply "
                            "HSTS to all subdomains."
                        ),
                    )
                )
            continue

        if not hr.present and missing_issue is not None:
            di = issue_descriptor(missing_issue)
            title = f"{hr.name} missing"
            issues.append(
                Issue(
                    id=missing_issue,
                    severity=di.severity,
                    title=title,
                    description=f"The response did not include the {hr.name} header.",
                    remediation=f"Configure your web server to send the {hr.name} header.",
                )
            )
            if missing_issue == HeadersIssueId.CSP_MISSING:
                recommendations.append(
                    Recommendation(
                        id=HeadersRecommendationId.ADD_CSP,
                        title="Add Content-Security-Policy",
                        description=(
                            "Publish a Content-Security-Policy that restricts script "
                            "and resource origins for your app."
                        ),
                    )
                )

    return issues, recommendations


def build_csp_header_value(params: CspGenerateParams) -> str:
    """Serialize CSP directives into a header value (no header name)."""
    parts: list[str] = []
    for directive, values in params.sources.items():
        parts.append(f"{directive} {' '.join(values)}")
    return "; ".join(parts)


def build_hsts_header_value(params: HstsGenerateParams) -> str:
    """Serialize HSTS directives into a header value (no header name)."""
    parts = [f"max-age={params.max_age}"]
    if params.include_subdomains:
        parts.append("includeSubDomains")
    if params.preload:
        parts.append("preload")
    return "; ".join(parts)


def generate_header_record_value(params: CspGenerateParams | HstsGenerateParams) -> str:
    """Full ``Header-Name: value`` line for ``GeneratedRecord.value``."""
    if isinstance(params, CspGenerateParams):
        return f"Content-Security-Policy: {build_csp_header_value(params)}"
    return f"Strict-Transport-Security: {build_hsts_header_value(params)}"
