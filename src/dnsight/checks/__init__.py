"""Check implementations: CAA, DKIM, DMARC, DNSSEC, headers, MX, and SPF.

The package root re-exports check classes, ``get_*`` / ``check_*`` / ``generate_*``
entry points, and a few **prefixed** descriptor helpers (e.g.
``headers_issue_descriptor``, ``dnssec_issue_descriptor``). Import per-check
``issue_descriptor`` from ``dnsight.checks.<name>`` — the name is reused in each
submodule and is not re-exported without a prefix here.
"""

from dnsight.checks.caa import (
    CAACheck,
    CAAData,
    CaaGenerateParams,
    CaaIssueId,
    CaaRecommendationId,
    check_caa,
    generate_caa,
    get_caa,
)
from dnsight.checks.dkim import (
    DKIMCheck,
    DKIMData,
    DKIMIssueId,
    DKIMRecommendationId,
    check_dkim,
    get_dkim,
)
from dnsight.checks.dmarc import (
    DMARCCheck,
    DMARCData,
    DMARCIssueId,
    DMARCRecommendationId,
    check_dmarc,
    generate_dmarc,
    get_dmarc,
)
from dnsight.checks.dnssec import (
    DNSSECCheck,
    DNSSECData,
    DNSSECIssueId,
    DNSSECRecommendationId,
    check_dnssec,
    get_dnssec,
)
from dnsight.checks.dnssec import issue_descriptor as dnssec_issue_descriptor
from dnsight.checks.dnssec import (
    recommendation_descriptor as dnssec_recommendation_descriptor,
)
from dnsight.checks.headers import (
    CspGenerateParams,
    GenerateKind,
    HeaderResult,
    HeadersCheck,
    HeadersData,
    HeadersGenerateParams,
    HeadersIssueId,
    HeadersRecommendationId,
    HstsGenerateParams,
    check_headers,
    generate_headers,
    get_headers,
)
from dnsight.checks.headers import issue_descriptor as headers_issue_descriptor
from dnsight.checks.mx import (
    MXCheck,
    MXData,
    MXGenerateParams,
    MXGenerateTarget,
    MXIssueId,
    MXRecommendationId,
    check_mx,
    generate_mx,
    get_mx,
)
from dnsight.checks.spf import (
    FlattenOutcome,
    SPFCheck,
    SPFData,
    SPFGenerateParams,
    SPFIssueId,
    SPFRecommendationId,
    check_spf,
    flatten_spf,
    generate_spf,
    get_spf,
)


__all__ = [
    # DNSSEC
    "DNSSECCheck",
    "DNSSECData",
    "DNSSECIssueId",
    "DNSSECRecommendationId",
    "check_dnssec",
    "dnssec_issue_descriptor",
    "dnssec_recommendation_descriptor",
    "get_dnssec",
    # CAA
    "CAACheck",
    "CAAData",
    "CaaGenerateParams",
    "CaaIssueId",
    "CaaRecommendationId",
    "check_caa",
    "generate_caa",
    "get_caa",
    # Headers
    "CspGenerateParams",
    "GenerateKind",
    "HeaderResult",
    "HeadersCheck",
    "HeadersData",
    "HeadersGenerateParams",
    "HeadersIssueId",
    "HeadersRecommendationId",
    "HstsGenerateParams",
    "check_headers",
    "generate_headers",
    "get_headers",
    "headers_issue_descriptor",
    # MX
    "MXCheck",
    "MXData",
    "MXGenerateParams",
    "MXGenerateTarget",
    "MXIssueId",
    "MXRecommendationId",
    "check_mx",
    "generate_mx",
    "get_mx",
    # DKIM
    "DKIMCheck",
    "DKIMData",
    "DKIMIssueId",
    "DKIMRecommendationId",
    "check_dkim",
    "get_dkim",
    # DMARC
    "DMARCCheck",
    "DMARCData",
    "DMARCIssueId",
    "DMARCRecommendationId",
    "check_dmarc",
    "generate_dmarc",
    "get_dmarc",
    # SPF
    "FlattenOutcome",
    "SPFCheck",
    "SPFData",
    "SPFGenerateParams",
    "SPFIssueId",
    "SPFRecommendationId",
    "check_spf",
    "flatten_spf",
    "generate_spf",
    "get_spf",
]
