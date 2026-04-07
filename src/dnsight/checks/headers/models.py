"""Headers check: issue/rec IDs, descriptors, data, and generate params."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from dnsight.checks.base import BaseCheckData, BaseGenerateParams
from dnsight.core.types import (
    IssueDescriptor,
    IssueId,
    Priority,
    RecommendationDescriptor,
    RecommendationId,
    Severity,
)


__all__ = [
    "CspGenerateParams",
    "GenerateKind",
    "HeaderResult",
    "HeadersData",
    "HeadersGenerateParams",
    "HeadersIssueId",
    "HeadersRecommendationId",
    "HstsGenerateParams",
    "issue_descriptor",
    "recommendation_descriptor",
]


# ---------------------------------------------------------------------------
# Issue and recommendation ID enums
# ---------------------------------------------------------------------------


class HeadersIssueId(IssueId):
    """Issue IDs for the HTTP security headers check."""

    HSTS_MISSING = "headers.hsts.missing"
    HSTS_NOT_SECURE = "headers.hsts.not_secure"
    CSP_MISSING = "headers.csp.missing"
    X_FRAME_OPTIONS_MISSING = "headers.x_frame_options.missing"
    PERMISSIONS_POLICY_MISSING = "headers.permissions_policy.missing"
    X_CONTENT_TYPE_OPTIONS_MISSING = "headers.x_content_type_options.missing"
    FETCH_FAILED = "headers.fetch_failed"


class HeadersRecommendationId(RecommendationId):
    """Recommendation IDs for the headers check."""

    ADD_HSTS = "headers.add_hsts"
    ADD_CSP = "headers.add_csp"
    INCLUDE_SUBDOMAINS_HSTS = "headers.include_subdomains_hsts"


# ---------------------------------------------------------------------------
# Descriptor maps
# ---------------------------------------------------------------------------

_HEADERS_ISSUE_DESCRIPTORS: dict[HeadersIssueId, IssueDescriptor] = {
    HeadersIssueId.HSTS_MISSING: IssueDescriptor(
        HeadersIssueId.HSTS_MISSING, Severity.MEDIUM
    ),
    HeadersIssueId.HSTS_NOT_SECURE: IssueDescriptor(
        HeadersIssueId.HSTS_NOT_SECURE, Severity.LOW
    ),
    HeadersIssueId.CSP_MISSING: IssueDescriptor(
        HeadersIssueId.CSP_MISSING, Severity.MEDIUM
    ),
    HeadersIssueId.X_FRAME_OPTIONS_MISSING: IssueDescriptor(
        HeadersIssueId.X_FRAME_OPTIONS_MISSING, Severity.MEDIUM
    ),
    HeadersIssueId.PERMISSIONS_POLICY_MISSING: IssueDescriptor(
        HeadersIssueId.PERMISSIONS_POLICY_MISSING, Severity.LOW
    ),
    HeadersIssueId.X_CONTENT_TYPE_OPTIONS_MISSING: IssueDescriptor(
        HeadersIssueId.X_CONTENT_TYPE_OPTIONS_MISSING, Severity.LOW
    ),
    HeadersIssueId.FETCH_FAILED: IssueDescriptor(
        HeadersIssueId.FETCH_FAILED, Severity.HIGH
    ),
}

_HEADERS_REC_DESCRIPTORS: dict[HeadersRecommendationId, RecommendationDescriptor] = {
    HeadersRecommendationId.ADD_HSTS: RecommendationDescriptor(
        HeadersRecommendationId.ADD_HSTS, priority=Priority.HIGH
    ),
    HeadersRecommendationId.ADD_CSP: RecommendationDescriptor(
        HeadersRecommendationId.ADD_CSP, priority=Priority.HIGH
    ),
    HeadersRecommendationId.INCLUDE_SUBDOMAINS_HSTS: RecommendationDescriptor(
        HeadersRecommendationId.INCLUDE_SUBDOMAINS_HSTS, priority=Priority.MEDIUM
    ),
}


def issue_descriptor(member: HeadersIssueId) -> IssueDescriptor:
    """Return the descriptor for a headers issue enum member."""
    return _HEADERS_ISSUE_DESCRIPTORS[member]


def recommendation_descriptor(
    member: HeadersRecommendationId,
) -> RecommendationDescriptor:
    """Return the descriptor for a headers recommendation enum member."""
    return _HEADERS_REC_DESCRIPTORS[member]


# ---------------------------------------------------------------------------
# Data and generate params
# ---------------------------------------------------------------------------


class HeaderResult(BaseModel):
    """One required header token and whether it was present on the response."""

    model_config = ConfigDict(frozen=True)

    name: str
    present: bool
    value: str | None = None


class HeadersData(BaseCheckData):
    """Parsed HTTP response headers for the probed URL.

    Attributes:
        url: URL whose response supplied ``headers`` (first successful probe).
        headers: Per-required-token presence and values.
        fetch_error: Set when every probe failed; no response headers were read.
    """

    url: str
    headers: list[HeaderResult] = Field(default_factory=list)
    fetch_error: str | None = None


class GenerateKind(StrEnum):
    """Which header line to generate."""

    CSP = "csp"
    HSTS = "hsts"


class CspGenerateParams(BaseGenerateParams):
    """Build a Content-Security-Policy header line."""

    kind: Literal[GenerateKind.CSP] = GenerateKind.CSP
    sources: dict[str, list[str]] = Field(default_factory=dict)


class HstsGenerateParams(BaseGenerateParams):
    """Build a Strict-Transport-Security header line."""

    kind: Literal[GenerateKind.HSTS] = GenerateKind.HSTS
    max_age: int = Field(default=31536000, ge=0)
    include_subdomains: bool = True
    preload: bool = False


HeadersGenerateParams = CspGenerateParams | HstsGenerateParams
