"""Check implementations. Currently: DMARC."""

from dnsight.checks.dmarc import (
    DMARCCheck,
    DMARCData,
    DMARCIssueId,
    DMARCRecommendationId,
    check_dmarc,
    generate_dmarc,
    get_dmarc,
)


__all__ = [
    # DMARC
    "DMARCCheck",
    "DMARCData",
    "DMARCIssueId",
    "DMARCRecommendationId",
    "check_dmarc",
    "generate_dmarc",
    "get_dmarc",
]
