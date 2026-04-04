"""DMARC check: issue/rec IDs, descriptors, and data models."""

from __future__ import annotations

from typing import Self

from pydantic import Field

from dnsight.checks.base import BaseCheckData, BaseGenerateParams
from dnsight.core.config.blocks import DmarcConfig
import dnsight.core.config.defaults as defaults
from dnsight.core.schema import DmarcSchema
from dnsight.core.types import (
    IssueDescriptor,
    IssueId,
    RecommendationDescriptor,
    RecommendationId,
    Severity,
)


__all__ = [
    "DMARCData",
    "DMARCGenerateParams",
    "DMARCIssueId",
    "DMARCRecommendationId",
    "issue_descriptor",
    "recommendation_descriptor",
]


# ---------------------------------------------------------------------------
# Issue and recommendation ID enums
# ---------------------------------------------------------------------------


class DMARCIssueId(IssueId):
    """Issue IDs for the DMARC check."""

    POLICY_MISSING = "dmarc.policy.missing"
    POLICY_WEAK = "dmarc.policy.weak"
    POLICY_NONE = "dmarc.policy.none"
    SUBDOMAIN_POLICY_WEAK = "dmarc.subdomain_policy.weak"
    RUA_MISSING = "dmarc.rua.missing"
    RUA_MISMATCH = "dmarc.rua.mismatch"
    RUF_MISSING = "dmarc.ruf.missing"
    RUF_MISMATCH = "dmarc.ruf.mismatch"
    PCT_NOT_100 = "dmarc.pct.not_100"
    PCT_NOT_MIN = "dmarc.pct.not_min"
    MULTIPLE_RECORDS = "dmarc.multiple_records"
    INVALID_TAG = "dmarc.invalid_tag"
    ALIGNMENT_RELAXED = "dmarc.alignment.relaxed"


class DMARCRecommendationId(RecommendationId):
    """Recommendation IDs for the DMARC check."""

    ENABLE_REJECT = "dmarc.enable.reject"
    ADD_RUA = "dmarc.add.rua"
    ADD_RUF = "dmarc.add.ruf"
    SET_PCT_100 = "dmarc.set_pct_100"
    STRICT_ALIGNMENT = "dmarc.strict_alignment"


# ---------------------------------------------------------------------------
# Descriptor maps — severity (issues) and priority (recommendations) for lookups
# ---------------------------------------------------------------------------

_DMARC_ISSUE_DESCRIPTORS: dict[DMARCIssueId, IssueDescriptor] = {
    DMARCIssueId.POLICY_MISSING: IssueDescriptor(
        DMARCIssueId.POLICY_MISSING, Severity.CRITICAL
    ),
    DMARCIssueId.POLICY_WEAK: IssueDescriptor(DMARCIssueId.POLICY_WEAK, Severity.HIGH),
    DMARCIssueId.POLICY_NONE: IssueDescriptor(
        DMARCIssueId.POLICY_NONE, Severity.CRITICAL
    ),
    DMARCIssueId.SUBDOMAIN_POLICY_WEAK: IssueDescriptor(
        DMARCIssueId.SUBDOMAIN_POLICY_WEAK, Severity.MEDIUM
    ),
    DMARCIssueId.RUA_MISSING: IssueDescriptor(
        DMARCIssueId.RUA_MISSING, Severity.MEDIUM
    ),
    DMARCIssueId.RUA_MISMATCH: IssueDescriptor(
        DMARCIssueId.RUA_MISMATCH, Severity.MEDIUM
    ),
    DMARCIssueId.RUF_MISSING: IssueDescriptor(DMARCIssueId.RUF_MISSING, Severity.LOW),
    DMARCIssueId.RUF_MISMATCH: IssueDescriptor(
        DMARCIssueId.RUF_MISMATCH, Severity.MEDIUM
    ),
    DMARCIssueId.PCT_NOT_100: IssueDescriptor(DMARCIssueId.PCT_NOT_100, Severity.LOW),
    DMARCIssueId.PCT_NOT_MIN: IssueDescriptor(
        DMARCIssueId.PCT_NOT_MIN, Severity.MEDIUM
    ),
    DMARCIssueId.MULTIPLE_RECORDS: IssueDescriptor(
        DMARCIssueId.MULTIPLE_RECORDS, Severity.HIGH
    ),
    DMARCIssueId.INVALID_TAG: IssueDescriptor(
        DMARCIssueId.INVALID_TAG, Severity.MEDIUM
    ),
    DMARCIssueId.ALIGNMENT_RELAXED: IssueDescriptor(
        DMARCIssueId.ALIGNMENT_RELAXED, Severity.LOW
    ),
}

_DMARC_REC_DESCRIPTORS: dict[DMARCRecommendationId, RecommendationDescriptor] = {
    DMARCRecommendationId.ENABLE_REJECT: RecommendationDescriptor(
        DMARCRecommendationId.ENABLE_REJECT
    ),
    DMARCRecommendationId.ADD_RUA: RecommendationDescriptor(
        DMARCRecommendationId.ADD_RUA
    ),
    DMARCRecommendationId.ADD_RUF: RecommendationDescriptor(
        DMARCRecommendationId.ADD_RUF
    ),
    DMARCRecommendationId.SET_PCT_100: RecommendationDescriptor(
        DMARCRecommendationId.SET_PCT_100
    ),
    DMARCRecommendationId.STRICT_ALIGNMENT: RecommendationDescriptor(
        DMARCRecommendationId.STRICT_ALIGNMENT
    ),
}


def issue_descriptor(member: DMARCIssueId) -> IssueDescriptor:
    """Return the descriptor for a DMARC issue enum member."""
    return _DMARC_ISSUE_DESCRIPTORS[member]


def recommendation_descriptor(
    member: DMARCRecommendationId,
) -> RecommendationDescriptor:
    """Return the descriptor for a DMARC recommendation enum member."""
    return _DMARC_REC_DESCRIPTORS[member]


# ---------------------------------------------------------------------------
# Data model and params
# ---------------------------------------------------------------------------


class DMARCData(BaseCheckData):
    """Parsed and validated DMARC record data for a domain."""

    policy: DmarcSchema.PolicyStr = Field(...)
    subdomain_policy: DmarcSchema.SubdomainPolicyStr = Field(None)
    percentage: DmarcSchema.PercentageInt = Field(...)
    alignment_dkim: DmarcSchema.AlignmentStr = Field(...)
    alignment_spf: DmarcSchema.AlignmentStr = Field(...)
    rua: DmarcSchema.ReportingURIsList = Field(
        default_factory=list, description="rua= mailto or http URIs"
    )
    ruf: DmarcSchema.ReportingURIsList = Field(
        default_factory=list, description="ruf= mailto or http URIs"
    )
    raw_record: str = Field(..., description="Original TXT record string")


class DMARCGenerateParams(BaseGenerateParams):
    """Generation parameters for the DMARC TXT record.

    Can be built from a DmarcConfig via ``from_config()``, or constructed
    directly with optional overrides (defaults from defaults.py).
    """

    policy: DmarcSchema.PolicyStr = Field(default=defaults.DEFAULT_DMARC_POLICY)
    subdomain_policy: DmarcSchema.SubdomainPolicyStr = Field(None)
    percentage: DmarcSchema.PercentageInt = Field(
        default=defaults.DEFAULT_DMARC_MINIMUM_PCT, description="pct= value, 0-100"
    )
    alignment_dkim: DmarcSchema.AlignmentStr = Field(
        default="r", description="adkim= value: r or s"
    )
    alignment_spf: DmarcSchema.AlignmentStr = Field(
        default="r", description="aspf= value: r or s"
    )
    rua: list[str] = Field(default_factory=list, description="rua= mailto or http URIs")
    ruf: list[str] = Field(default_factory=list, description="ruf= mailto or http URIs")

    @classmethod
    def from_config(cls, config: DmarcConfig) -> Self:
        """Build params from DmarcConfig for generation."""
        align: DmarcSchema.AlignmentLiteral = (
            "s" if config.require_strict_alignment else "r"
        )
        if config.expected_rua:
            rua = list(config.expected_rua)
        elif config.rua_required:
            rua = ["mailto:dmarc@example.com"]
        else:
            rua = []
        if config.expected_ruf:
            ruf = list(config.expected_ruf)
        elif config.ruf_required:
            ruf = ["mailto:dmarc@example.com"]
        else:
            ruf = []
        return cls(
            policy=config.policy,
            subdomain_policy=config.subdomain_policy_minimum,
            percentage=config.minimum_pct,
            alignment_dkim=align,
            alignment_spf=align,
            rua=rua,
            ruf=ruf,
        )
