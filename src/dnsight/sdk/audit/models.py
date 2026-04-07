"""Audit result aggregates: zones, domains, and multi-target audits.

Check-level results remain in :mod:`dnsight.core.models`.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from dnsight.core.models import CheckResultAny, Issue
from dnsight.core.types import Severity


__all__ = ["AuditResult", "DomainResult", "ZoneResult"]


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
    target: str = Field(
        ...,
        description=(
            "Normalised config target (domain or domain/path); same string as "
            "ConfigManager.target_string. Equals domain when the manifest path is apex-only."
        ),
    )
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


class AuditResult(BaseModel):
    """Batch audit: one :class:`DomainResult` per manifest target (or CLI list)."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(..., description="When the batch completed (UTC)")
    config_version: int = Field(..., description="Config schema version used")
    domains: list[DomainResult] = Field(
        default_factory=list, description="Per-target domain audits in order"
    )

    @property
    def partial(self) -> bool:
        """True if any contained domain audit is partial."""
        return any(d.partial for d in self.domains)
