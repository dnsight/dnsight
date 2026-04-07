"""Core models for dnsight.

Frozen Pydantic models for check-level results. Zone/domain audit aggregates live
in :mod:`dnsight.sdk.audit.models`. :class:`ZoneResult` and :class:`DomainResult`
are still available as ``from dnsight.core.models import DomainResult`` (lazy
attribute) for backward compatibility; prefer importing from ``dnsight.sdk.audit``.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from dnsight.core.types import RecordType, Severity, Status


__all__ = [
    "CheckResult",
    "CheckResultAny",
    "GeneratedRecord",
    "Issue",
    "Recommendation",
]

T = TypeVar("T")


def __getattr__(name: str) -> Any:
    """Lazy re-exports for audit aggregates (prefer :mod:`dnsight.sdk.audit.models`)."""
    if name == "ZoneResult":
        from dnsight.sdk.audit.models import ZoneResult as _ZoneResult

        return _ZoneResult
    if name == "DomainResult":
        from dnsight.sdk.audit.models import DomainResult as _DomainResult

        return _DomainResult
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


class Issue(BaseModel):
    """A specific problem found during a check.

    Stable IDs (dot-separated, e.g. ``dmarc.policy.none``) allow CI and
    dashboards to track and suppress by identifier. Checks create issues
    using their StrEnum subclass members for type safety at construction;
    the model stores the string value.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Stable issue identifier (e.g. dmarc.policy.none)")
    severity: Severity = Field(..., description="Issue severity level")
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(..., description="Full explanation of the issue")
    remediation: str = Field(..., description="Actionable remediation steps")


class Recommendation(BaseModel):
    """A suggestion that improves posture but is not required.

    Uses the same dot-separated ID convention as Issue.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        ..., description="Stable recommendation identifier (e.g. dmarc.enable.reject)"
    )
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(..., description="Full explanation of the recommendation")


class CheckResult(BaseModel, Generic[T]):  # NOSONAR S6792
    """The result of a single check run.

    Generic over the check's data type *T*. So
    ``CheckResult[DMARCData]`` gives typed access to ``result.data.policy``
    etc. Serialisers and aggregation code use ``CheckResultAny``.
    """

    model_config = ConfigDict(frozen=True)

    status: Status = Field(..., description="Status of the check run")
    data: T | None = Field(None, description="Parsed data returned by the check")
    raw: str | None = Field(None, description="Raw output from the check, if any")
    issues: list[Issue] = Field(
        default_factory=list, description="Issues found during the check"
    )
    recommendations: list[Recommendation] = Field(
        default_factory=list, description="Recommendations for the check"
    )
    error: str | None = Field(None, description="Error message if the check failed")

    @property
    def passed(self) -> bool:
        """True when the check completed with zero issues."""
        return self.status == Status.COMPLETED and len(self.issues) == 0

    @property
    def failed(self) -> bool:
        """True when the check failed entirely."""
        return self.status == Status.FAILED

    @property
    def skipped(self) -> bool:
        """True when the check was skipped."""
        return self.status == Status.SKIPPED

    @property
    def partial(self) -> bool:
        """True when the check completed partially."""
        return self.status == Status.PARTIAL

    def _has_severity(self, severity: Severity) -> bool:
        return any(issue.severity == severity for issue in self.issues)

    @property
    def has_critical(self) -> bool:
        """True if any issue has CRITICAL severity."""
        return self._has_severity(Severity.CRITICAL)

    def has_severity(self, severity: Severity) -> bool:
        """True if any issue has the given severity."""
        return self._has_severity(severity)


CheckResultAny = CheckResult[Any]


class GeneratedRecord(BaseModel):
    """A DNS record produced by a generate action.

    Returned by check ``generate()`` methods. Gives the CLI and SDK
    consumers a consistent shape for generated output.
    """

    model_config = ConfigDict(frozen=True)

    record_type: RecordType = Field(
        ..., description="DNS record type (e.g. TXT, CNAME)."
    )
    host: str = Field(..., description="Record host/name (e.g. _dmarc, @).")
    value: str = Field(..., description="Record value/content.")
    ttl: int = Field(default=3600, description="Time to live in seconds.")
