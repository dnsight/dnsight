"""DMARC check: validation rules, helpers, and record parser."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from dnsight.checks.dmarc.models import (
    DMARCData,
    DMARCIssueId,
    DMARCRecommendationId,
    issue_descriptor,
    recommendation_descriptor,
)
from dnsight.core.config.blocks import Config, DmarcConfig
from dnsight.core.models import CheckResult, Issue, Recommendation
from dnsight.core.types import Status


__all__ = [
    "DMARC1_PREFIX",
    "extract_dmarc_config",
    "normalise_config",
    "parse_dmarc_record",
    "process_raw_records",
    "result_missing_dns",
    "result_no_valid_record",
    "rule_alignment",
    "rule_pct",
    "rule_policy_strength",
    "rule_rua",
    "rule_ruf",
    "rule_subdomain_policy",
]


# Policy strength for comparison (none < quarantine < reject)
_POLICY_STRENGTH: dict[str, int] = {"none": 0, "quarantine": 1, "reject": 2}
DMARC1_PREFIX = "v=dmarc1"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _policy_strength(p: str) -> int:
    return _POLICY_STRENGTH.get((p or "").lower(), -1)


def _normalize_reporting_uri(uri: str) -> str:
    """Normalize a reporting URI for set comparison (strip + casefold)."""
    return (uri or "").strip().casefold()


def _reporting_uri_frozenset(uris: list[str]) -> frozenset[str]:
    """Build a frozenset of normalized URIs; empty strings are dropped."""
    return frozenset(_normalize_reporting_uri(u) for u in uris if (u or "").strip())


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------


def _apply_dmarc_tag(state: dict[str, Any], tag: str, value: str) -> None:
    """Apply a single tag=value to mutable parser state. Idempotent for unknown tags."""
    mapping: dict[str, Callable[[str], Any]] = {
        "p": lambda v: v.lower() if v else "none",
        "sp": lambda v: v.lower() if v else None,
        "pct": lambda v: int(v) if v and v.strip().isdigit() else 100,
        "adkim": lambda v: v.lower() if v else "r",
        "aspf": lambda v: v.lower() if v else "r",
        "rua": lambda v: [uri.strip() for uri in v.split(",") if uri.strip()],
        "ruf": lambda v: [uri.strip() for uri in v.split(",") if uri.strip()],
    }
    if tag in mapping:
        state[tag] = mapping[tag](value)
    else:
        state[tag] = value


def parse_dmarc_record(raw: str) -> DMARCData:
    """Parse a single DMARC TXT string into DMARCData.

    Uses defaults for missing tags. Safe to call with empty or malformed
    strings; invalid tag values are preserved in raw_record for validation.

    Args:
        raw: The raw TXT record string (e.g. "v=DMARC1; p=reject; pct=100").

    Returns:
        Parsed DMARCData with raw_record set to the input string.
    """
    raw = (raw or "").strip()
    state: dict[str, Any] = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        tag, _, value = part.partition("=")
        tag = tag.strip().lower()
        value = value.strip()
        if tag == "v":
            continue
        _apply_dmarc_tag(state, tag, value)
    return DMARCData(
        policy=state.get("p", "none"),
        subdomain_policy=state.get("sp"),
        percentage=state.get("pct", 100),
        alignment_dkim=state.get("adkim", "r"),
        alignment_spf=state.get("aspf", "r"),
        rua=state.get("rua", []),
        ruf=state.get("ruf", []),
        raw_record=raw,
    )


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def extract_dmarc_config(config: Config | DmarcConfig | None) -> DmarcConfig:
    if isinstance(config, Config):
        return config.dmarc
    return config or DmarcConfig()


def normalise_config(config: Config | DmarcConfig | None) -> tuple[DmarcConfig, bool]:
    if isinstance(config, Config):
        return config.dmarc, config.strict_recommendations
    dmarc = config or DmarcConfig()
    return dmarc, False


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------


def result_missing_dns() -> CheckResult[DMARCData]:
    """CheckResult when DNS lookup fails (no _dmarc TXT)."""
    d = issue_descriptor(DMARCIssueId.POLICY_MISSING)
    return CheckResult(
        status=Status.COMPLETED,
        data=None,
        raw=None,
        issues=[
            Issue(
                id=DMARCIssueId.POLICY_MISSING,
                severity=d.severity,
                title="DMARC record missing",
                description="No _dmarc TXT record found.",
                remediation="Publish a DMARC TXT record at _dmarc.<domain>.",
            )
        ],
        recommendations=[],
        error=None,
    )


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


def process_raw_records(raw_list: list[str]) -> tuple[str, list[Issue]]:
    """From resolver TXT list, pick DMARC record string and collect issues (e.g. multiple)."""
    issues: list[Issue] = []
    dmarc_records = [
        (s or "").strip()
        for s in raw_list
        if (s or "").strip().lower().startswith(DMARC1_PREFIX)
    ]
    if not dmarc_records and raw_list:
        dmarc_records = [(raw_list[0] or "").strip()]
    if len(dmarc_records) > 1:
        md = issue_descriptor(DMARCIssueId.MULTIPLE_RECORDS)
        issues.append(
            Issue(
                id=DMARCIssueId.MULTIPLE_RECORDS,
                severity=md.severity,
                title="Multiple DMARC records",
                description="More than one TXT record starts with v=DMARC1; only one is valid.",
                remediation="Publish a single DMARC TXT record at _dmarc.<domain>.",
            )
        )
    record = dmarc_records[0] if dmarc_records else ""
    if not record or not record.lower().startswith(DMARC1_PREFIX):
        pm = issue_descriptor(DMARCIssueId.POLICY_MISSING)
        issues.append(
            Issue(
                id=DMARCIssueId.POLICY_MISSING,
                severity=pm.severity,
                title="DMARC record missing or invalid",
                description="No valid DMARC record (v=DMARC1) found.",
                remediation="Publish a DMARC TXT record at _dmarc.<domain>.",
            )
        )
    return record, issues


# ---------------------------------------------------------------------------
# Validation rules (each called individually by DMARCCheck)
# ---------------------------------------------------------------------------


def rule_policy_strength(
    data: DMARCData, dmarc_config: DmarcConfig, strict: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Check policy strength vs required and target policy."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    min_strength = _policy_strength(dmarc_config.policy)
    actual_strength = _policy_strength(data.policy)
    if actual_strength < min_strength:
        pw = issue_descriptor(DMARCIssueId.POLICY_WEAK)
        issues.append(
            Issue(
                id=DMARCIssueId.POLICY_WEAK,
                severity=pw.severity,
                title="DMARC policy weaker than required",
                description=f"Required at least {dmarc_config.policy}; found {data.policy}.",
                remediation=f"Set p={dmarc_config.policy} or stronger in your DMARC record.",
            )
        )
    target = (dmarc_config.target_policy or "").strip().lower() or None
    if target and _policy_strength(data.policy) < _policy_strength(target):
        rej = recommendation_descriptor(DMARCRecommendationId.ENABLE_REJECT)
        if strict or target == "reject":
            recommendations.append(
                Recommendation(
                    id=rej.id,
                    title="Use p=reject",
                    description="Set DMARC policy to reject for strongest protection.",
                )
            )
        else:
            recommendations.append(
                Recommendation(
                    id=rej.id,
                    title=f"Consider p={target}",
                    description=f"Move to p={target} to meet your target policy.",
                )
            )
    return issues, recommendations


def rule_subdomain_policy(
    data: DMARCData, dmarc_config: DmarcConfig, _strict: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Check subdomain policy meets minimum."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    if dmarc_config.subdomain_policy_minimum is None:
        return issues, recommendations
    sp_min = _policy_strength(dmarc_config.subdomain_policy_minimum)
    sp_actual = _policy_strength(data.subdomain_policy or "none")
    if sp_actual < sp_min:
        sp = issue_descriptor(DMARCIssueId.SUBDOMAIN_POLICY_WEAK)
        issues.append(
            Issue(
                id=DMARCIssueId.SUBDOMAIN_POLICY_WEAK,
                severity=sp.severity,
                title="Subdomain policy weaker than required",
                description=f"sp must be at least {dmarc_config.subdomain_policy_minimum}; found {data.subdomain_policy or 'none'}.",
                remediation=f"Set sp={dmarc_config.subdomain_policy_minimum} or stronger.",
            )
        )
    return issues, recommendations


def rule_rua(
    data: DMARCData, dmarc_config: DmarcConfig, strict: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Check RUA (aggregate reporting) requirement and optional expected URIs."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    if dmarc_config.expected_rua:
        expected = _reporting_uri_frozenset(dmarc_config.expected_rua)
        actual = _reporting_uri_frozenset(data.rua)
        if expected != actual:
            ru = issue_descriptor(DMARCIssueId.RUA_MISMATCH)
            issues.append(
                Issue(
                    id=DMARCIssueId.RUA_MISMATCH,
                    severity=ru.severity,
                    title="RUA URIs do not match configuration",
                    description=(
                        f"Expected rua= {sorted(expected)!r}; "
                        f"found {sorted(actual)!r} in the record."
                    ),
                    remediation="Set rua= to exactly the configured reporting URIs.",
                )
            )
            return issues, recommendations

    if dmarc_config.rua_required and not data.rua:
        rm = issue_descriptor(DMARCIssueId.RUA_MISSING)
        issues.append(
            Issue(
                id=DMARCIssueId.RUA_MISSING,
                severity=rm.severity,
                title="RUA missing",
                description="Aggregate reporting (rua) is required but not set.",
                remediation="Add at least one rua=mailto:... in your DMARC record.",
            )
        )
        if not strict:
            add_rua = recommendation_descriptor(DMARCRecommendationId.ADD_RUA)
            recommendations.append(
                Recommendation(
                    id=add_rua.id,
                    title="Add RUA",
                    description="Add rua=mailto: to receive aggregate reports.",
                )
            )
    if strict and not data.rua:
        add_rua_s = recommendation_descriptor(DMARCRecommendationId.ADD_RUA)
        recommendations.append(
            Recommendation(
                id=add_rua_s.id,
                title="Add RUA",
                description="Add rua=mailto: to receive aggregate reports.",
            )
        )
    return issues, recommendations


def rule_ruf(
    data: DMARCData, dmarc_config: DmarcConfig, strict: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Check RUF (forensic reporting) requirement and optional expected URIs."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    if dmarc_config.expected_ruf:
        expected = _reporting_uri_frozenset(dmarc_config.expected_ruf)
        actual = _reporting_uri_frozenset(data.ruf)
        if expected != actual:
            rf = issue_descriptor(DMARCIssueId.RUF_MISMATCH)
            issues.append(
                Issue(
                    id=DMARCIssueId.RUF_MISMATCH,
                    severity=rf.severity,
                    title="RUF URIs do not match configuration",
                    description=(
                        f"Expected ruf= {sorted(expected)!r}; "
                        f"found {sorted(actual)!r} in the record."
                    ),
                    remediation="Set ruf= to exactly the configured reporting URIs.",
                )
            )
            return issues, recommendations

    if dmarc_config.ruf_required and not data.ruf:
        rfu = issue_descriptor(DMARCIssueId.RUF_MISSING)
        issues.append(
            Issue(
                id=DMARCIssueId.RUF_MISSING,
                severity=rfu.severity,
                title="RUF missing",
                description="Forensic reporting (ruf) is required but not set.",
                remediation="Add at least one ruf=mailto:... in your DMARC record.",
            )
        )
    if (strict or dmarc_config.ruf_required) and not data.ruf:
        add_ruf = recommendation_descriptor(DMARCRecommendationId.ADD_RUF)
        recommendations.append(
            Recommendation(
                id=add_ruf.id,
                title="Add RUF",
                description="Add ruf=mailto: for forensic reporting.",
            )
        )
    return issues, recommendations


def rule_pct(
    data: DMARCData, dmarc_config: DmarcConfig, strict: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Check pct (percentage) meets minimum and recommend 100."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    if data.percentage < dmarc_config.minimum_pct:
        pn = issue_descriptor(DMARCIssueId.PCT_NOT_MIN)
        issues.append(
            Issue(
                id=DMARCIssueId.PCT_NOT_MIN,
                severity=pn.severity,
                title="DMARC pct below minimum",
                description=f"pct must be at least {dmarc_config.minimum_pct}; found {data.percentage}.",
                remediation=f"Set pct={dmarc_config.minimum_pct} in your DMARC record.",
            )
        )
    elif data.percentage != 100 and (strict or dmarc_config.minimum_pct == 100):
        p100 = issue_descriptor(DMARCIssueId.PCT_NOT_100)
        issues.append(
            Issue(
                id=DMARCIssueId.PCT_NOT_100,
                severity=p100.severity,
                title="DMARC pct is not 100",
                description=f"Only {data.percentage}% of messages are subject to policy.",
                remediation="Set pct=100 in your DMARC record.",
            )
        )
    if data.percentage < 100 and (strict or dmarc_config.minimum_pct == 100):
        set_pct = recommendation_descriptor(DMARCRecommendationId.SET_PCT_100)
        recommendations.append(
            Recommendation(
                id=set_pct.id,
                title="Set pct=100",
                description="Apply policy to 100% of messages.",
            )
        )
    return issues, recommendations


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
    al = issue_descriptor(DMARCIssueId.ALIGNMENT_RELAXED)
    issues.append(
        Issue(
            id=DMARCIssueId.ALIGNMENT_RELAXED,
            severity=al.severity,
            title="Relaxed alignment",
            description="adkim and/or aspf are relaxed (r); strict (s) is stronger.",
            remediation="Set adkim=s and aspf=s for strict alignment.",
        )
    )
    st = recommendation_descriptor(DMARCRecommendationId.STRICT_ALIGNMENT)
    recommendations.append(
        Recommendation(
            id=st.id,
            title="Use strict alignment",
            description="Set adkim=s and aspf=s for stronger alignment checks.",
        )
    )
    return issues, recommendations
