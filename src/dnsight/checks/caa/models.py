"""CAA check: issue/rec IDs, descriptors, and data models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from dnsight.checks.base import BaseCheckData, BaseGenerateParams
from dnsight.core.config.blocks import CaaConfig
from dnsight.core.types import (
    IssueDescriptor,
    IssueId,
    RecommendationDescriptor,
    RecommendationId,
    Severity,
)


__all__ = [
    "CAAData",
    "CaaGenerateParams",
    "CaaIssueId",
    "CaaNameResult",
    "CaaRecord",
    "CaaRecommendationId",
    "DiscoveryLimitReason",
    "NameDiscoveryKind",
    "issue_descriptor",
    "recommendation_descriptor",
]


class CaaIssueId(IssueId):
    """Issue IDs for the CAA check."""

    RECORD_MISSING = "caa.record.missing"
    SYNTAX_INVALID = "caa.syntax.invalid"
    ISSUE_MISSING = "caa.issue.missing"
    ISSUER_MISSING = "caa.issuer.missing"
    CRT_SH_VIOLATION = "caa.crt_sh.violation"
    ENUMERATION_LIMIT_REACHED = "caa.enumeration.limit_reached"
    ISSUEWILD_PERMISSIVE = "caa.issuewild.permissive"
    ISSUEWILD_RESTRICT = "caa.issuewild.restrict"


class CaaRecommendationId(RecommendationId):
    """Recommendation IDs for the CAA check."""

    ADD_ISSUE = "caa.add_issue"
    ADD_ISSUEWILD = "caa.add_issuewild"


_CAA_ISSUE_DESCRIPTORS: dict[CaaIssueId, IssueDescriptor] = {
    CaaIssueId.RECORD_MISSING: IssueDescriptor(CaaIssueId.RECORD_MISSING, Severity.LOW),
    CaaIssueId.SYNTAX_INVALID: IssueDescriptor(
        CaaIssueId.SYNTAX_INVALID, Severity.MEDIUM
    ),
    CaaIssueId.ISSUE_MISSING: IssueDescriptor(
        CaaIssueId.ISSUE_MISSING, Severity.MEDIUM
    ),
    CaaIssueId.ISSUER_MISSING: IssueDescriptor(
        CaaIssueId.ISSUER_MISSING, Severity.MEDIUM
    ),
    CaaIssueId.CRT_SH_VIOLATION: IssueDescriptor(
        CaaIssueId.CRT_SH_VIOLATION, Severity.MEDIUM
    ),
    CaaIssueId.ENUMERATION_LIMIT_REACHED: IssueDescriptor(
        CaaIssueId.ENUMERATION_LIMIT_REACHED, Severity.LOW
    ),
    CaaIssueId.ISSUEWILD_PERMISSIVE: IssueDescriptor(
        CaaIssueId.ISSUEWILD_PERMISSIVE, Severity.MEDIUM
    ),
    CaaIssueId.ISSUEWILD_RESTRICT: IssueDescriptor(
        CaaIssueId.ISSUEWILD_RESTRICT, Severity.MEDIUM
    ),
}

_CAA_REC_DESCRIPTORS: dict[CaaRecommendationId, RecommendationDescriptor] = {
    CaaRecommendationId.ADD_ISSUE: RecommendationDescriptor(
        CaaRecommendationId.ADD_ISSUE
    ),
    CaaRecommendationId.ADD_ISSUEWILD: RecommendationDescriptor(
        CaaRecommendationId.ADD_ISSUEWILD
    ),
}


def issue_descriptor(member: CaaIssueId) -> IssueDescriptor:
    """Return the descriptor for a CAA issue id."""
    return _CAA_ISSUE_DESCRIPTORS[member]


def recommendation_descriptor(member: CaaRecommendationId) -> RecommendationDescriptor:
    """Return the descriptor for a CAA recommendation id."""
    return _CAA_REC_DESCRIPTORS[member]


class NameDiscoveryKind(StrEnum):
    """How a hostname was selected for CAA checking."""

    APEX = "apex"
    WWW = "www"
    CONFIG = "config"
    ENUM_A = "enum_a"
    ENUM_AAAA = "enum_aaaa"
    ENUM_CNAME = "enum_cname"
    ENUM_DNAME = "enum_dname"
    ENUM_MX = "enum_mx"
    ENUM_SRV = "enum_srv"


class DiscoveryLimitReason(StrEnum):
    """Why name enumeration stopped early."""

    NONE = "none"
    MAX_NAMES = "max_names"
    MAX_DEPTH = "max_depth"


class CaaRecord(BaseModel):
    """Single CAA RDATA (RFC 8659)."""

    model_config = ConfigDict(frozen=True)

    flags: int
    tag: str
    value: str


class CaaNameResult(BaseModel):
    """CAA resolution and validation context for one hostname."""

    model_config = ConfigDict(frozen=True)

    name: str
    discovery: tuple[NameDiscoveryKind, ...] = Field(default_factory=tuple)
    records_at_node: list[CaaRecord] = Field(
        default_factory=list,
        description="Raw CAA records returned at the effective node (first non-empty in the walk).",
    )
    effective_node: str = Field(
        default="",
        description="DNS name where the effective CAA RRset was found (or zone apex if none).",
    )
    effective_records: list[CaaRecord] = Field(
        default_factory=list,
        description="Parsed effective CAA RRset (same as records_at_node when found).",
    )
    missing_issuers: list[str] = Field(default_factory=list)
    cycle_detected: bool = False


class CAAData(BaseCheckData):
    """Per-name CAA inventory for a zone."""

    zone_apex: str = ""
    names_checked: list[CaaNameResult] = Field(default_factory=list)
    enumeration_truncated: bool = False
    discovery_limit_reason: DiscoveryLimitReason = DiscoveryLimitReason.NONE
    names_discovered_count: int = 0


class CaaGenerateParams(BaseGenerateParams):
    """Parameters to synthesize CAA records."""

    issuers: list[str] = Field(
        default_factory=list, description='CA domain names for 0 issue "..." lines.'
    )
    emit_issuewild: bool = Field(
        default=False,
        description="If True, emit 0 issuewild lines matching issuers; if False, omit issuewild.",
    )
    iodef_mailto: str | None = Field(
        default=None, description="If set, emit 0 iodef mailto:..."
    )

    @classmethod
    def from_config(cls, config: CaaConfig) -> CaaGenerateParams:
        """Build generation params from CAA config (issuers + optional iodef)."""
        return cls(
            issuers=list(config.required_issuers),
            emit_issuewild=config.check_issuewild,
            iodef_mailto=config.reporting_email,
        )
