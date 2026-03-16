"""DMARC check: validation rules and helpers.

DMARCRules groups all rules and helpers as static methods. Public methods
(used by DMARCCheck) have no leading underscore; internal helpers use _.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from dnsight.checks.dmarc.models import DMARCData, DMARCIssueId, DMARCRecommendationId
from dnsight.core.config.blocks import Config, DmarcConfig
from dnsight.core.models import CheckResult, Issue, Recommendation
from dnsight.core.types import Severity, Status


__all__ = ["DMARCRules"]


class DMARCRules:
    """Static methods for DMARC validation rules and helpers."""

    # Policy strength for comparison (none < quarantine < reject)
    POLICY_STRENGTH: dict[str, int] = {"none": 0, "quarantine": 1, "reject": 2}
    DMARC1_PREFIX = "v=dmarc1"

    # -----------------------------------------------------------------------
    # Internal helpers (used only within this class)
    # -----------------------------------------------------------------------

    @staticmethod
    def _policy_strength(p: str) -> int:
        return DMARCRules.POLICY_STRENGTH.get((p or "").lower(), -1)

    # -----------------------------------------------------------------------
    # Parser helper (used by parse_dmarc_record in __init__)
    # -----------------------------------------------------------------------

    @staticmethod
    def apply_dmarc_tag(state: dict[str, Any], tag: str, value: str) -> None:
        """Apply a single tag=value to mutable parser state. Idempotent for unknown tags."""
        mapping: dict[str, Callable[[str], str | None]] = {
            "p": lambda v: v.lower() if v else "none",
            "sp": lambda v: v.lower() if v else None,
            "pct": lambda v: int(v) if v else 100,
            "adkim": lambda v: v.lower() if v else "r",
            "aspf": lambda v: v.lower() if v else "r",
            "rua": lambda v: [uri.strip() for uri in v.split(",") if uri.strip()],
            "ruf": lambda v: [uri.strip() for uri in v.split(",") if uri.strip()],
        }
        if tag in mapping:
            state[tag] = mapping[tag](value)
        else:
            state[tag] = value

    # -----------------------------------------------------------------------
    # Config helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def extract_dmarc_config(config: Config | DmarcConfig | None) -> DmarcConfig:
        if isinstance(config, Config):
            return config.dmarc
        return config or DmarcConfig()

    @staticmethod
    def normalise_config(
        config: Config | DmarcConfig | None,
    ) -> tuple[DmarcConfig, bool]:
        if isinstance(config, Config):
            return config.dmarc, config.strict_recommendations
        dmarc = config or DmarcConfig()
        return dmarc, False

    # -----------------------------------------------------------------------
    # Result builders
    # -----------------------------------------------------------------------

    @staticmethod
    def result_missing_dns() -> CheckResult[DMARCData]:
        """CheckResult when DNS lookup fails (no _dmarc TXT)."""
        return CheckResult(
            status=Status.COMPLETED,
            data=None,
            raw=None,
            issues=[
                Issue(
                    id=DMARCIssueId.POLICY_MISSING,
                    severity=Severity.CRITICAL,
                    title="DMARC record missing",
                    description="No _dmarc TXT record found.",
                    remediation="Publish a DMARC TXT record at _dmarc.<domain>.",
                )
            ],
            recommendations=[],
            error=None,
        )

    @staticmethod
    def result_no_valid_record(
        record: str, issues: list[Issue], recommendations: list[Recommendation]
    ) -> CheckResult[DMARCData]:
        """CheckResult when no valid v=DMARC1 record is present."""
        return CheckResult(
            status=Status.COMPLETED,
            data=None,
            raw=record or None,
            issues=issues,
            recommendations=recommendations,
            error=None,
        )

    @staticmethod
    def process_raw_records(raw_list: list[str]) -> tuple[str, list[Issue]]:
        """From resolver TXT list, pick DMARC record string and collect issues (e.g. multiple)."""
        issues: list[Issue] = []
        dmarc_records = [
            (s or "").strip()
            for s in raw_list
            if (s or "").strip().lower().startswith(DMARCRules.DMARC1_PREFIX)
        ]
        if not dmarc_records and raw_list:
            dmarc_records = [(raw_list[0] or "").strip()]
        if len(dmarc_records) > 1:
            issues.append(
                Issue(
                    id=DMARCIssueId.MULTIPLE_RECORDS,
                    severity=Severity.HIGH,
                    title="Multiple DMARC records",
                    description="More than one TXT record starts with v=DMARC1; only one is valid.",
                    remediation="Publish a single DMARC TXT record at _dmarc.<domain>.",
                )
            )
        record = dmarc_records[0] if dmarc_records else ""
        if not record or not record.lower().startswith(DMARCRules.DMARC1_PREFIX):
            issues.append(
                Issue(
                    id=DMARCIssueId.POLICY_MISSING,
                    severity=Severity.CRITICAL,
                    title="DMARC record missing or invalid",
                    description="No valid DMARC record (v=DMARC1) found.",
                    remediation="Publish a DMARC TXT record at _dmarc.<domain>.",
                )
            )
        return record, issues

    # -----------------------------------------------------------------------
    # Validation rules (each called individually by DMARCCheck)
    # -----------------------------------------------------------------------

    @staticmethod
    def rule_policy_strength(
        data: DMARCData, dmarc_config: DmarcConfig, strict: bool
    ) -> tuple[list[Issue], list[Recommendation]]:
        """Check policy strength vs required and target policy."""
        issues: list[Issue] = []
        recommendations: list[Recommendation] = []
        min_strength = DMARCRules._policy_strength(dmarc_config.policy)
        actual_strength = DMARCRules._policy_strength(data.policy)
        if actual_strength < min_strength:
            issues.append(
                Issue(
                    id=DMARCIssueId.POLICY_WEAK,
                    severity=Severity.HIGH,
                    title="DMARC policy weaker than required",
                    description=f"Required at least {dmarc_config.policy}; found {data.policy}.",
                    remediation=f"Set p={dmarc_config.policy} or stronger in your DMARC record.",
                )
            )
        target = (dmarc_config.target_policy or "").strip().lower() or None
        if target and DMARCRules._policy_strength(
            data.policy
        ) < DMARCRules._policy_strength(target):
            if strict or target == "reject":
                recommendations.append(
                    Recommendation(
                        id=DMARCRecommendationId.ENABLE_REJECT,
                        title="Use p=reject",
                        description="Set DMARC policy to reject for strongest protection.",
                    )
                )
            else:
                recommendations.append(
                    Recommendation(
                        id=DMARCRecommendationId.ENABLE_REJECT,
                        title=f"Consider p={target}",
                        description=f"Move to p={target} to meet your target policy.",
                    )
                )
        return issues, recommendations

    @staticmethod
    def rule_subdomain_policy(
        data: DMARCData, dmarc_config: DmarcConfig, strict: bool
    ) -> tuple[list[Issue], list[Recommendation]]:
        """Check subdomain policy meets minimum."""
        issues: list[Issue] = []
        recommendations: list[Recommendation] = []
        if dmarc_config.subdomain_policy_minimum is None:
            return issues, recommendations
        sp_min = DMARCRules._policy_strength(dmarc_config.subdomain_policy_minimum)
        sp_actual = DMARCRules._policy_strength(data.subdomain_policy or "none")
        if sp_actual < sp_min:
            issues.append(
                Issue(
                    id=DMARCIssueId.SUBDOMAIN_POLICY_WEAK,
                    severity=Severity.MEDIUM,
                    title="Subdomain policy weaker than required",
                    description=f"sp must be at least {dmarc_config.subdomain_policy_minimum}; found {data.subdomain_policy or 'none'}.",
                    remediation=f"Set sp={dmarc_config.subdomain_policy_minimum} or stronger.",
                )
            )
        return issues, recommendations

    @staticmethod
    def rule_rua(
        data: DMARCData, dmarc_config: DmarcConfig, strict: bool
    ) -> tuple[list[Issue], list[Recommendation]]:
        """Check RUA (aggregate reporting) requirement."""
        issues: list[Issue] = []
        recommendations: list[Recommendation] = []
        if dmarc_config.rua_required and not data.rua:
            issues.append(
                Issue(
                    id=DMARCIssueId.RUA_MISSING,
                    severity=Severity.MEDIUM,
                    title="RUA missing",
                    description="Aggregate reporting (rua) is required but not set.",
                    remediation="Add at least one rua=mailto:... in your DMARC record.",
                )
            )
            if not strict:
                recommendations.append(
                    Recommendation(
                        id=DMARCRecommendationId.ADD_RUA,
                        title="Add RUA",
                        description="Add rua=mailto: to receive aggregate reports.",
                    )
                )
        if strict and not data.rua:
            recommendations.append(
                Recommendation(
                    id=DMARCRecommendationId.ADD_RUA,
                    title="Add RUA",
                    description="Add rua=mailto: to receive aggregate reports.",
                )
            )
        return issues, recommendations

    @staticmethod
    def rule_ruf(
        data: DMARCData, dmarc_config: DmarcConfig, strict: bool
    ) -> tuple[list[Issue], list[Recommendation]]:
        """Check RUF (forensic reporting) requirement."""
        issues: list[Issue] = []
        recommendations: list[Recommendation] = []
        if dmarc_config.ruf_required and not data.ruf:
            issues.append(
                Issue(
                    id=DMARCIssueId.RUF_MISSING,
                    severity=Severity.LOW,
                    title="RUF missing",
                    description="Forensic reporting (ruf) is required but not set.",
                    remediation="Add at least one ruf=mailto:... in your DMARC record.",
                )
            )
        if (strict or dmarc_config.ruf_required) and not data.ruf:
            recommendations.append(
                Recommendation(
                    id=DMARCRecommendationId.ADD_RUF,
                    title="Add RUF",
                    description="Add ruf=mailto: for forensic reporting.",
                )
            )
        return issues, recommendations

    @staticmethod
    def rule_pct(
        data: DMARCData, dmarc_config: DmarcConfig, strict: bool
    ) -> tuple[list[Issue], list[Recommendation]]:
        """Check pct (percentage) meets minimum and recommend 100."""
        issues: list[Issue] = []
        recommendations: list[Recommendation] = []
        if data.percentage < dmarc_config.minimum_pct:
            issues.append(
                Issue(
                    id=DMARCIssueId.PCT_NOT_MIN,
                    severity=Severity.MEDIUM,
                    title="DMARC pct below minimum",
                    description=f"pct must be at least {dmarc_config.minimum_pct}; found {data.percentage}.",
                    remediation=f"Set pct={dmarc_config.minimum_pct} in your DMARC record.",
                )
            )
        elif data.percentage != 100 and (strict or dmarc_config.minimum_pct == 100):
            issues.append(
                Issue(
                    id=DMARCIssueId.PCT_NOT_100,
                    severity=Severity.MEDIUM,
                    title="DMARC pct is not 100",
                    description=f"Only {data.percentage}% of messages are subject to policy.",
                    remediation="Set pct=100 in your DMARC record.",
                )
            )
        if data.percentage < 100 and (strict or dmarc_config.minimum_pct == 100):
            recommendations.append(
                Recommendation(
                    id=DMARCRecommendationId.SET_PCT_100,
                    title="Set pct=100",
                    description="Apply policy to 100% of messages.",
                )
            )
        return issues, recommendations

    @staticmethod
    def rule_alignment(
        data: DMARCData, dmarc_config: DmarcConfig, strict: bool
    ) -> tuple[list[Issue], list[Recommendation]]:
        """Check alignment (adkim/aspf) when strict alignment required."""
        issues: list[Issue] = []
        recommendations: list[Recommendation] = []
        if not (strict or dmarc_config.require_strict_alignment):
            return issues, recommendations
        if data.alignment_dkim != "r" and data.alignment_spf != "r":
            return issues, recommendations  # both strict, nothing to add
        issues.append(
            Issue(
                id=DMARCIssueId.ALIGNMENT_RELAXED,
                severity=Severity.LOW,
                title="Relaxed alignment",
                description="adkim and/or aspf are relaxed (r); strict (s) is stronger.",
                remediation="Set adkim=s and aspf=s for strict alignment.",
            )
        )
        recommendations.append(
            Recommendation(
                id=DMARCRecommendationId.STRICT_ALIGNMENT,
                title="Use strict alignment",
                description="Set adkim=s and aspf=s for stronger alignment checks.",
            )
        )
        return issues, recommendations
