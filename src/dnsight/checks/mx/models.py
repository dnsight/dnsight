"""MX check: issue/rec IDs, descriptors, and data models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from dnsight.checks.base import BaseCheckData
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


class MXData(BaseCheckData):
    """MX check data: MX records in resolver order with optional probes."""

    mx_hosts: list[MXHostResult] = Field(default_factory=list)
