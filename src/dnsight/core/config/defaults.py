"""Defaults for dnsight config."""

from __future__ import annotations

from typing import Final


__all__ = [
    "DEFAULT_DNS_PROVIDER",
    "DEFAULT_DMARC_MINIMUM_PCT",
    "DEFAULT_DMARC_POLICY",
    "DEFAULT_DMARC_REQUIRE_STRICT_ALIGNMENT",
    "DEFAULT_DMARC_RUA_REQUIRED",
    "DEFAULT_DMARC_RUF_REQUIRED",
    "DEFAULT_DMARC_TARGET_POLICY",
    "DEFAULT_GLOBAL_CONCURRENCY_LIMIT",
    "DEFAULT_GLOBAL_MAX_RPS",
    "DEFAULT_STRICT_RECOMMENDATIONS",
    "DNS_PROVIDER_NAMESERVERS",
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
# DMARC (secure defaults)
DEFAULT_DMARC_POLICY: Final[str] = "reject"  # minimum required policy
DEFAULT_DMARC_TARGET_POLICY: Final[str | None] = (
    None  # if set, recommend moving to this; None = only check minimum
)
DEFAULT_DMARC_RUA_REQUIRED: Final[bool] = True
DEFAULT_DMARC_RUF_REQUIRED: Final[bool] = False
DEFAULT_DMARC_MINIMUM_PCT: Final[int] = 100
DEFAULT_DMARC_REQUIRE_STRICT_ALIGNMENT: Final[bool] = False
# Recommendations: if true recommend strictest; if false recommend alignment to config
DEFAULT_STRICT_RECOMMENDATIONS: Final[bool] = False
