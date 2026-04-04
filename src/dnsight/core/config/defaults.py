"""Defaults for dnsight config."""

from __future__ import annotations

from typing import Final, Literal


__all__ = [
    # Global
    "DEFAULT_DNS_PROVIDER",
    "DEFAULT_GLOBAL_CONCURRENCY_LIMIT",
    "DEFAULT_GLOBAL_MAX_RPS",
    "DEFAULT_STRICT_RECOMMENDATIONS",
    "DNS_PROVIDER_NAMESERVERS",
    # DMARC
    "DEFAULT_DMARC_MINIMUM_PCT",
    "DEFAULT_DMARC_POLICY",
    "DEFAULT_DMARC_REQUIRE_STRICT_ALIGNMENT",
    "DEFAULT_DMARC_RUA_REQUIRED",
    "DEFAULT_DMARC_RUF_REQUIRED",
    "DEFAULT_DMARC_TARGET_POLICY",
    # SPF
    "DEFAULT_SPF_ALLOW_REDIRECT",
    "DEFAULT_SPF_LOOKUP_LIMIT",
    "DEFAULT_SPF_MAX_INCLUDES",
    "DEFAULT_SPF_REQUIRED_DISPOSITION",
    # DKIM
    "DEFAULT_DKIM_COMMON_SELECTORS",
    "DEFAULT_DKIM_MIN_KEY_BITS",
    # MX
    "DEFAULT_MX_CHECK_PTR",
    "DEFAULT_MX_CHECK_STARTTLS",
    "DEFAULT_MX_STARTTLS_TIMEOUT_SECONDS",
    # Headers
    "DEFAULT_HEADERS_REQUIRE",
    # CAA
    "DEFAULT_CAA_CHECK_ISSUEWILD",
    "DEFAULT_CAA_CROSS_REFERENCE_CRT_SH",
    "DEFAULT_CAA_ENUMERATE_NAMES",
    "DEFAULT_CAA_INCLUDE_MX_TARGETS",
    "DEFAULT_CAA_INCLUDE_SRV_TARGETS",
    "DEFAULT_CAA_INCLUDE_WWW",
    "DEFAULT_CAA_MAX_ENUMERATION_DEPTH",
    "DEFAULT_CAA_MAX_NAMES",
    "DEFAULT_CAA_REQUIRE_CAA",
    "DEFAULT_CAA_RESTRICT_WILDCARD_ISSUANCE",
    "DEFAULT_CAA_ENUMERATE_DNAME",
    # DNSSEC
    "DEFAULT_DNSSEC_REQUIRE_DS",
    "DEFAULT_DNSSEC_SIGNATURE_EXPIRY_DAYS_WARNING",
    "DEFAULT_DNSSEC_VALIDATE_NEGATIVE",
    "DEFAULT_DNSSEC_VALIDATE_NODATA",
    "DEFAULT_DNSSEC_REQUIRE_NS",
]


# ===== Default Constants =====

# DNS resolver
DEFAULT_DNS_PROVIDER: Final[str] = "system"

DNS_PROVIDER_NAMESERVERS: Final[dict[str, list[str]]] = {
    "google": ["8.8.8.8", "8.8.4.4"],
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
    "opendns": ["208.67.222.222", "208.67.220.220"],
}

# Throttle
DEFAULT_GLOBAL_MAX_RPS: Final[float] = 50.0
# Concurrency
DEFAULT_GLOBAL_CONCURRENCY_LIMIT: Final[int] = 10
# Recommendations: if true recommend strictest; if false recommend alignment to config
DEFAULT_STRICT_RECOMMENDATIONS: Final[bool] = False
# DMARC (secure defaults)
DEFAULT_DMARC_POLICY: Final[Literal["reject"]] = "reject"  # minimum required policy
DEFAULT_DMARC_TARGET_POLICY: Final[Literal["none", "quarantine", "reject"] | None] = (
    None  # if set, recommend moving to this; None = only check minimum
)
DEFAULT_DMARC_RUA_REQUIRED: Final[bool] = True
DEFAULT_DMARC_RUF_REQUIRED: Final[bool] = False
DEFAULT_DMARC_MINIMUM_PCT: Final[int] = 100
DEFAULT_DMARC_REQUIRE_STRICT_ALIGNMENT: Final[bool] = False
# SPF
DEFAULT_SPF_REQUIRED_DISPOSITION: Final[Literal["-all"]] = "-all"
DEFAULT_SPF_LOOKUP_LIMIT: Final[int] = 10
DEFAULT_SPF_MAX_INCLUDES: Final[int | None] = None
DEFAULT_SPF_ALLOW_REDIRECT: Final[bool] = True
# DKIM
DEFAULT_DKIM_MIN_KEY_BITS: Final[int] = 2048
DEFAULT_DKIM_COMMON_SELECTORS: Final[tuple[str, ...]] = (
    "default",
    "google",
    "selector1",
    "k1",
)
# MX (optional probes; off by default to limit latency unless enabled)
DEFAULT_MX_CHECK_PTR: Final[bool] = False
DEFAULT_MX_CHECK_STARTTLS: Final[bool] = False
DEFAULT_MX_STARTTLS_TIMEOUT_SECONDS: Final[float] = 10.0
# Security headers (short tokens; mapped to real header names in the check)
DEFAULT_HEADERS_REQUIRE: Final[tuple[str, ...]] = ("HSTS", "CSP", "X-Frame-Options")
# CAA
DEFAULT_CAA_REQUIRE_CAA: Final[bool] = False
DEFAULT_CAA_CHECK_ISSUEWILD: Final[bool] = True
DEFAULT_CAA_RESTRICT_WILDCARD_ISSUANCE: Final[bool] = False
DEFAULT_CAA_CROSS_REFERENCE_CRT_SH: Final[bool] = False
DEFAULT_CAA_ENUMERATE_NAMES: Final[bool] = False
DEFAULT_CAA_MAX_ENUMERATION_DEPTH: Final[int] = 10
DEFAULT_CAA_MAX_NAMES: Final[int] = 100
DEFAULT_CAA_INCLUDE_WWW: Final[bool] = True
DEFAULT_CAA_INCLUDE_MX_TARGETS: Final[bool] = False
DEFAULT_CAA_INCLUDE_SRV_TARGETS: Final[bool] = False
DEFAULT_CAA_ENUMERATE_DNAME: Final[bool] = False
# DNSSEC
DEFAULT_DNSSEC_REQUIRE_DS: Final[bool] = False
DEFAULT_DNSSEC_SIGNATURE_EXPIRY_DAYS_WARNING: Final[int] = 7
DEFAULT_DNSSEC_VALIDATE_NEGATIVE: Final[bool] = True
DEFAULT_DNSSEC_VALIDATE_NODATA: Final[bool] = True
DEFAULT_DNSSEC_REQUIRE_NS: Final[bool] = False
