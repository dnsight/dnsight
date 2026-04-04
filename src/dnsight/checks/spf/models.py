"""SPF check: issue/rec IDs, descriptors, and data models."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field

from dnsight.checks.base import BaseCheckData, BaseGenerateParams
from dnsight.core.config.blocks import SpfConfig
from dnsight.core.schema import SpfSchema
from dnsight.core.types import (
    IssueDescriptor,
    IssueId,
    Priority,
    RecommendationDescriptor,
    RecommendationId,
    Severity,
)


__all__ = [
    "FlattenedSPF",
    "SPFData",
    "SPFGenerateParams",
    "SPFIssueId",
    "SPFRecommendationId",
]


# ---------------------------------------------------------------------------
# Issue and recommendation ID enums
# ---------------------------------------------------------------------------


class SPFIssueId(IssueId):
    """Issue IDs for the SPF check."""

    RECORD_MISSING = "spf.record.missing"
    MULTIPLE_RECORDS = "spf.multiple_records"
    LOOKUP_LIMIT_EXCEEDED = "spf.lookup.limit_exceeded"
    DISPOSITION_PASS_ALL = "spf.disposition.pass_all"
    DISPOSITION_NEUTRAL = "spf.disposition.neutral"
    DISPOSITION_SOFTFAIL = "spf.disposition.softfail"
    SYNTAX_INVALID = "spf.syntax.invalid"
    REDIRECT_NOT_ALLOWED = "spf.redirect.not_allowed"


class SPFRecommendationId(RecommendationId):
    """Recommendation IDs for the SPF check."""

    USE_DASH_ALL = "spf.use_dash_all"
    REDUCE_LOOKUPS = "spf.reduce_lookups"


# ---------------------------------------------------------------------------
# Descriptor maps
# ---------------------------------------------------------------------------

_SPF_ISSUE_DESCRIPTORS: dict[SPFIssueId, IssueDescriptor] = {
    SPFIssueId.RECORD_MISSING: IssueDescriptor(
        SPFIssueId.RECORD_MISSING, Severity.CRITICAL
    ),
    SPFIssueId.MULTIPLE_RECORDS: IssueDescriptor(
        SPFIssueId.MULTIPLE_RECORDS, Severity.HIGH
    ),
    SPFIssueId.LOOKUP_LIMIT_EXCEEDED: IssueDescriptor(
        SPFIssueId.LOOKUP_LIMIT_EXCEEDED, Severity.HIGH
    ),
    SPFIssueId.DISPOSITION_PASS_ALL: IssueDescriptor(
        SPFIssueId.DISPOSITION_PASS_ALL, Severity.CRITICAL
    ),
    SPFIssueId.DISPOSITION_NEUTRAL: IssueDescriptor(
        SPFIssueId.DISPOSITION_NEUTRAL, Severity.MEDIUM
    ),
    SPFIssueId.DISPOSITION_SOFTFAIL: IssueDescriptor(
        SPFIssueId.DISPOSITION_SOFTFAIL, Severity.HIGH
    ),
    SPFIssueId.SYNTAX_INVALID: IssueDescriptor(
        SPFIssueId.SYNTAX_INVALID, Severity.HIGH
    ),
    SPFIssueId.REDIRECT_NOT_ALLOWED: IssueDescriptor(
        SPFIssueId.REDIRECT_NOT_ALLOWED, Severity.MEDIUM
    ),
}

_SPF_REC_DESCRIPTORS: dict[SPFRecommendationId, RecommendationDescriptor] = {
    SPFRecommendationId.USE_DASH_ALL: RecommendationDescriptor(
        SPFRecommendationId.USE_DASH_ALL, priority=Priority.HIGH
    ),
    SPFRecommendationId.REDUCE_LOOKUPS: RecommendationDescriptor(
        SPFRecommendationId.REDUCE_LOOKUPS, priority=Priority.MEDIUM
    ),
}


def issue_descriptor(member: SPFIssueId) -> IssueDescriptor:
    """Return the descriptor for an SPF issue enum member."""
    return _SPF_ISSUE_DESCRIPTORS[member]


def recommendation_descriptor(member: SPFRecommendationId) -> RecommendationDescriptor:
    """Return the descriptor for an SPF recommendation enum member."""
    return _SPF_REC_DESCRIPTORS[member]


# ---------------------------------------------------------------------------
# Flattened view and check data
# ---------------------------------------------------------------------------


class FlattenedSPF(BaseModel):
    """Expanded SPF view after processing include / redirect."""

    model_config = ConfigDict(frozen=True)

    effective_lookup_count: int
    resolved_mechanisms: list[str]
    ip4_ranges: list[str] = Field(default_factory=list)
    ip6_ranges: list[str] = Field(default_factory=list)


class SPFData(BaseCheckData):
    """Parsed SPF data for a domain (apex TXT)."""

    raw_record: str
    disposition: str
    lookup_count: int
    includes: list[str] = Field(default_factory=list)
    mechanisms: list[str] = Field(default_factory=list)
    flattened: FlattenedSPF | None = None
    suggested_record: str | None = None


class SPFGenerateParams(BaseGenerateParams):
    """Parameters to build a minimal SPF TXT record."""

    includes: list[str] = Field(default_factory=list)
    disposition: SpfSchema.DispositionStr = Field(default="-all")

    @classmethod
    def from_config(cls, config: SpfConfig) -> Self:
        """Build params from SpfConfig (disposition from required_disposition)."""
        disp = config.required_disposition
        return cls(includes=[], disposition=disp)
