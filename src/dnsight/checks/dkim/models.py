"""DKIM check: issue/rec IDs, descriptors, and data models."""

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
    "DKIMData",
    "DKIMIssueId",
    "DKIMRecommendationId",
    "DKIMSelectorResult",
    "issue_descriptor",
    "recommendation_descriptor",
]


# ---------------------------------------------------------------------------
# Issue and recommendation ID enums
# ---------------------------------------------------------------------------


class DKIMIssueId(IssueId):
    """Issue IDs for the DKIM check."""

    DISCOVERY_NO_VALID_KEY = "dkim.discovery.no_valid_key"
    EXTRA_SELECTOR_PUBLISHED = "dkim.selector.extra_published"
    SELECTOR_NOT_FOUND = "dkim.selector.not_found"
    KEY_MISSING = "dkim.key.missing"
    ALGORITHM_WEAK = "dkim.algorithm.weak"
    KEY_TOO_SHORT = "dkim.key_too_short"
    SYNTAX_INVALID = "dkim.syntax.invalid"


class DKIMRecommendationId(RecommendationId):
    """Recommendation IDs for the DKIM check."""

    #: Emitted when no TXT exists for any tried selector; title/copy say "configure".
    ADD_COMMON_SELECTORS = "dkim.add_common_selectors"
    STRONGER_ALGORITHM = "dkim.stronger_algorithm"


# ---------------------------------------------------------------------------
# Descriptor maps
# ---------------------------------------------------------------------------

_DKIM_ISSUE_DESCRIPTORS: dict[DKIMIssueId, IssueDescriptor] = {
    DKIMIssueId.DISCOVERY_NO_VALID_KEY: IssueDescriptor(
        DKIMIssueId.DISCOVERY_NO_VALID_KEY, Severity.MEDIUM
    ),
    DKIMIssueId.EXTRA_SELECTOR_PUBLISHED: IssueDescriptor(
        DKIMIssueId.EXTRA_SELECTOR_PUBLISHED, Severity.MEDIUM
    ),
    DKIMIssueId.SELECTOR_NOT_FOUND: IssueDescriptor(
        DKIMIssueId.SELECTOR_NOT_FOUND, Severity.MEDIUM
    ),
    DKIMIssueId.KEY_MISSING: IssueDescriptor(DKIMIssueId.KEY_MISSING, Severity.MEDIUM),
    DKIMIssueId.ALGORITHM_WEAK: IssueDescriptor(
        DKIMIssueId.ALGORITHM_WEAK, Severity.HIGH
    ),
    DKIMIssueId.KEY_TOO_SHORT: IssueDescriptor(
        DKIMIssueId.KEY_TOO_SHORT, Severity.HIGH
    ),
    DKIMIssueId.SYNTAX_INVALID: IssueDescriptor(
        DKIMIssueId.SYNTAX_INVALID, Severity.MEDIUM
    ),
}

_DKIM_REC_DESCRIPTORS: dict[DKIMRecommendationId, RecommendationDescriptor] = {
    DKIMRecommendationId.ADD_COMMON_SELECTORS: RecommendationDescriptor(
        DKIMRecommendationId.ADD_COMMON_SELECTORS, priority=Priority.MEDIUM
    ),
    DKIMRecommendationId.STRONGER_ALGORITHM: RecommendationDescriptor(
        DKIMRecommendationId.STRONGER_ALGORITHM, priority=Priority.HIGH
    ),
}


def issue_descriptor(member: DKIMIssueId) -> IssueDescriptor:
    """Return the descriptor for a DKIM issue enum member."""
    return _DKIM_ISSUE_DESCRIPTORS[member]


def recommendation_descriptor(member: DKIMRecommendationId) -> RecommendationDescriptor:
    """Return the descriptor for a DKIM recommendation enum member."""
    return _DKIM_REC_DESCRIPTORS[member]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class DKIMSelectorResult(BaseModel):
    """Parsed DKIM DNS result for one selector."""

    model_config = ConfigDict(frozen=True)

    selector: str
    found: bool
    algorithm: str | None = None
    key_bits: int | None = None
    raw_record: str | None = None


class DKIMData(BaseCheckData):
    """DKIM check data: selectors tried and per-selector results."""

    selectors_tried: list[str] = Field(default_factory=list)
    selectors_found: list[DKIMSelectorResult] = Field(default_factory=list)
    #: When non-empty, strict mode: these selectors are required; others are probe-only.
    explicit_allowlist: tuple[str, ...] = Field(default_factory=tuple)
