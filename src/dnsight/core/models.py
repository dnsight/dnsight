"""Core models for dnsight.

All result types are frozen Pydantic models. Shared vocabulary for checks,
orchestrator, serialisers, and SDK consumers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from dnsight.core.types import RecordType, Severity, Status


__all__ = [
    "CheckResult",
    "CheckResultAny",
    "DomainResult",
    "GeneratedRecord",
    "Issue",
    "Recommendation",
    "ZoneResult",
]

T = TypeVar("T")


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


class CheckResult(BaseModel, Generic[T]):
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


class ZoneResult(BaseModel):
    """Result of running checks for one zone.

    Check results are stored in a dict keyed by check name (e.g. ``"dmarc"``).
    Checks that were not run are absent from the dict.
    """

    model_config = ConfigDict(frozen=True)

    zone: str = Field(..., description="FQDN of the zone")
    parent: str | None = Field(None, description="Parent zone FQDN if child")
    children: list[ZoneResult] = Field(
        default_factory=list, description="Child zone results"
    )
    results: dict[str, CheckResultAny] = Field(
        default_factory=dict, description="Check results keyed by check name"
    )

    def _check_results(self) -> list[CheckResultAny]:
        """Non-None check results in this zone."""
        return list(self.results.values())

    @property
    def partial(self) -> bool:
        """True if any check in this zone or any child zone is PARTIAL or FAILED."""
        if any(c.partial or c.failed for c in self._check_results()):
            return True
        return any(child.partial for child in self.children)

    @property
    def issue_count(self) -> int:
        """Total issues in this zone only (not including children)."""
        return sum(len(c.issues) for c in self._check_results())


class DomainResult(BaseModel):
    """Top-level result for an entire audit.

    One domain, timestamp, config version, and a list of zone results
    (root first).
    """

    model_config = ConfigDict(frozen=True)

    domain: str = Field(..., description="Root domain audited")
    timestamp: datetime = Field(..., description="When the audit ran (UTC)")
    config_version: int = Field(..., description="Config version used")
    zones: list[ZoneResult] = Field(
        default_factory=list, description="Zone results; first is root"
    )
    partial: bool = Field(
        ..., description="True if any zone has a PARTIAL or FAILED check"
    )

    @property
    def root(self) -> ZoneResult:
        """Root zone result (zones[0])."""
        if not self.zones:
            raise ValueError("DomainResult has no zones")
        return self.zones[0]

    def _collect_zone_issues(self, z: ZoneResult) -> list[tuple[str, Issue]]:
        """Collect ``(zone_fqdn, issue)`` pairs for a zone and its children."""
        out: list[tuple[str, Issue]] = [
            (z.zone, issue) for c in z.results.values() for issue in c.issues
        ]
        for child in z.children:
            out.extend(self._collect_zone_issues(child))
        return out

    @property
    def all_issues(self) -> list[tuple[str, Issue]]:
        """Flat ``(zone_fqdn, issue)`` pairs across all zones and children."""
        return [p for z in self.zones for p in self._collect_zone_issues(z)]

    @property
    def critical_count(self) -> int:
        """Number of issues with severity CRITICAL across all zones."""
        return sum(1 for _, i in self.all_issues if i.severity == Severity.CRITICAL)


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
