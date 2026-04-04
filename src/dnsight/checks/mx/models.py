"""MX check: issue/rec IDs, descriptors, and data models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dnsight.checks.base import BaseCheckData, BaseGenerateParams
from dnsight.core.config.blocks import MxConfig
from dnsight.core.schema.mx import MxSchema
from dnsight.core.types import (
    IssueDescriptor,
    IssueId,
    Priority,
    RecommendationDescriptor,
    RecommendationId,
    Severity,
)


__all__ = [
    "MXData",
    "MXGenerateParams",
    "MXGenerateTarget",
    "MXHostResult",
    "MXIssueId",
    "MXRecommendationId",
    "issue_descriptor",
    "recommendation_descriptor",
]


class MXIssueId(IssueId):
    """Issue IDs for the MX check."""

    RECORD_MISSING = "mx.record.missing"
    PTR_MISSING = "mx.ptr.missing"
    STARTTLS_NOT_SUPPORTED = "mx.starttls.not_supported"
    STARTTLS_FAILED = "mx.starttls.failed"
    DUPLICATE_PRIORITY = "mx.duplicate_priority"


class MXRecommendationId(RecommendationId):
    """Recommendation IDs for the MX check."""

    ADD_PTR = "mx.add_ptr"
    ENABLE_STARTTLS = "mx.enable_starttls"


_MX_ISSUE_DESCRIPTORS: dict[MXIssueId, IssueDescriptor] = {
    MXIssueId.RECORD_MISSING: IssueDescriptor(MXIssueId.RECORD_MISSING, Severity.HIGH),
    MXIssueId.PTR_MISSING: IssueDescriptor(MXIssueId.PTR_MISSING, Severity.MEDIUM),
    MXIssueId.STARTTLS_NOT_SUPPORTED: IssueDescriptor(
        MXIssueId.STARTTLS_NOT_SUPPORTED, Severity.HIGH
    ),
    MXIssueId.STARTTLS_FAILED: IssueDescriptor(
        MXIssueId.STARTTLS_FAILED, Severity.MEDIUM
    ),
    MXIssueId.DUPLICATE_PRIORITY: IssueDescriptor(
        MXIssueId.DUPLICATE_PRIORITY, Severity.LOW
    ),
}

_MX_REC_DESCRIPTORS: dict[MXRecommendationId, RecommendationDescriptor] = {
    MXRecommendationId.ADD_PTR: RecommendationDescriptor(
        MXRecommendationId.ADD_PTR, priority=Priority.MEDIUM
    ),
    MXRecommendationId.ENABLE_STARTTLS: RecommendationDescriptor(
        MXRecommendationId.ENABLE_STARTTLS, priority=Priority.HIGH
    ),
}


def issue_descriptor(member: MXIssueId) -> IssueDescriptor:
    """Return the descriptor for an MX issue enum member."""
    return _MX_ISSUE_DESCRIPTORS[member]


def recommendation_descriptor(member: MXRecommendationId) -> RecommendationDescriptor:
    """Return the descriptor for an MX recommendation enum member."""
    return _MX_REC_DESCRIPTORS[member]


class MXHostResult(BaseModel):
    """Per-MX-host DNS and optional probe results."""

    model_config = ConfigDict(frozen=True)

    hostname: str
    priority: int
    ptr: str | None = None
    ptr_matches: bool | None = None
    starttls_supported: bool | None = None
    starttls_error: str | None = None


class MXGenerateTarget(BaseModel):
    """One MX row for :class:`MXGenerateParams` (preference + exchange host)."""

    model_config = ConfigDict(frozen=True)

    priority: MxSchema.MxPreferenceInt = Field(
        ..., description="Preference; lower is more preferred."
    )
    hostname: MxSchema.MxExchangeStr = Field(
        ..., description="Mail server hostname (e.g. mail.example.com)."
    )

    @field_validator("hostname")
    @classmethod
    def _strip_hostname(cls, v: str) -> str:
        s = (v or "").strip()
        if not s:
            raise ValueError("hostname must be non-empty")
        return s


class MXGenerateParams(BaseGenerateParams):
    """Parameters to synthesize MX RDATA lines for a zone file."""

    targets: list[MXGenerateTarget] = Field(
        default_factory=list,
        description="MX targets; each becomes one line: preference exchange.",
    )

    @classmethod
    def from_config(cls, config: MxConfig) -> MXGenerateParams:
        """Build params from :class:`MxConfig` (no default targets; use explicit *targets*)."""
        return cls(targets=[])


class MXData(BaseCheckData):
    """MX check data: MX records in resolver order with optional probes."""

    mx_hosts: list[MXHostResult] = Field(default_factory=list)
