"""Tests for checks/dmarc/rules.py — parser, rule functions, and result builders."""

from __future__ import annotations

from dnsight.checks.dmarc.models import DMARCData, DMARCIssueId, DMARCRecommendationId
from dnsight.checks.dmarc.rules import (
    _apply_dmarc_tag,
    parse_dmarc_record,
    process_raw_records,
    result_missing_dns,
    result_no_valid_record,
    rule_alignment,
    rule_pct,
    rule_policy_strength,
    rule_rua,
    rule_ruf,
    rule_subdomain_policy,
)
from dnsight.core.config.blocks import DmarcConfig
from dnsight.core.types import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _data(**kwargs: object) -> DMARCData:
    defaults: dict[str, object] = {
        "policy": "reject",
        "subdomain_policy": None,
        "percentage": 100,
        "alignment_dkim": "r",
        "alignment_spf": "r",
        "rua": ["mailto:dmarc@example.com"],
        "ruf": [],
        "raw_record": "v=DMARC1; p=reject",
    }
    defaults.update(kwargs)
    return DMARCData(**defaults)  # type: ignore[arg-type]


def _cfg(**kwargs: object) -> DmarcConfig:
    return DmarcConfig(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _apply_dmarc_tag
# ---------------------------------------------------------------------------


class TestApplyDmarcTag:
    def test_known_tags_coerced(self) -> None:
        state: dict = {}
        _apply_dmarc_tag(state, "p", "REJECT")
        assert state["p"] == "reject"

    def test_pct_valid(self) -> None:
        state: dict = {}
        _apply_dmarc_tag(state, "pct", "75")
        assert state["pct"] == 75

    def test_pct_malformed_falls_back_to_100(self) -> None:
        state: dict = {}
        _apply_dmarc_tag(state, "pct", "abc")
        assert state["pct"] == 100

    def test_pct_empty_falls_back_to_100(self) -> None:
        state: dict = {}
        _apply_dmarc_tag(state, "pct", "")
        assert state["pct"] == 100

    def test_rua_split(self) -> None:
        state: dict = {}
        _apply_dmarc_tag(state, "rua", "mailto:a@b.com, mailto:c@d.com")
        assert state["rua"] == ["mailto:a@b.com", "mailto:c@d.com"]

    def test_unknown_tag_stored_raw(self) -> None:
        state: dict = {}
        _apply_dmarc_tag(state, "fo", "0")
        assert state["fo"] == "0"


# ---------------------------------------------------------------------------
# parse_dmarc_record
# ---------------------------------------------------------------------------


class TestParseDmarcRecord:
    def test_full_record(self) -> None:
        raw = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:a@b.com; ruf=mailto:f@b.com; sp=quarantine"
        data = parse_dmarc_record(raw)
        assert data.policy == "reject"
        assert data.percentage == 100
        assert data.alignment_dkim == "s"
        assert data.alignment_spf == "s"
        assert data.rua == ["mailto:a@b.com"]
        assert data.ruf == ["mailto:f@b.com"]
        assert data.subdomain_policy == "quarantine"
        assert data.raw_record == raw

    def test_defaults_for_missing_tags(self) -> None:
        data = parse_dmarc_record("v=DMARC1; p=none")
        assert data.percentage == 100
        assert data.alignment_dkim == "r"
        assert data.alignment_spf == "r"
        assert data.rua == []
        assert data.subdomain_policy is None

    def test_malformed_pct_uses_default(self) -> None:
        data = parse_dmarc_record("v=DMARC1; p=reject; pct=abc")
        assert data.percentage == 100

    def test_empty_string_returns_defaults(self) -> None:
        data = parse_dmarc_record("")
        assert data.policy == "none"
        assert data.percentage == 100

    def test_case_insensitive_tags(self) -> None:
        data = parse_dmarc_record("v=DMARC1; P=Reject")
        assert data.policy == "reject"

    def test_parts_without_equals_skipped(self) -> None:
        data = parse_dmarc_record("v=DMARC1; p=reject; garbage")
        assert data.policy == "reject"


# ---------------------------------------------------------------------------
# process_raw_records
# ---------------------------------------------------------------------------


class TestProcessRawRecords:
    def test_single_valid_record(self) -> None:
        _, issues = process_raw_records(["v=dmarc1; p=reject"])
        assert issues == []

    def test_multiple_dmarc_records_adds_issue(self) -> None:
        record, issues = process_raw_records(["v=dmarc1; p=none", "v=DMARC1; p=reject"])
        assert len(issues) == 1
        assert issues[0].id == DMARCIssueId.MULTIPLE_RECORDS
        assert issues[0].severity == Severity.HIGH

    def test_no_dmarc_record_falls_back_to_first(self) -> None:
        record, issues = process_raw_records(["v=spf1 -all"])
        assert record == "v=spf1 -all"
        assert any(i.id == DMARCIssueId.POLICY_MISSING for i in issues)

    def test_empty_list_returns_empty_with_missing_issue(self) -> None:
        record, issues = process_raw_records([])
        assert record == ""
        assert any(i.id == DMARCIssueId.POLICY_MISSING for i in issues)


# ---------------------------------------------------------------------------
# result_missing_dns / result_no_valid_record
# ---------------------------------------------------------------------------


class TestResultBuilders:
    def test_result_missing_dns(self) -> None:
        result = result_missing_dns()
        assert result.data is None
        assert len(result.issues) == 1
        assert result.issues[0].id == DMARCIssueId.POLICY_MISSING
        assert result.issues[0].severity == Severity.CRITICAL

    def test_result_no_valid_record(self) -> None:
        from dnsight.core.models import Issue

        issue = Issue(
            id=DMARCIssueId.POLICY_MISSING,
            severity=Severity.CRITICAL,
            title="x",
            description="x",
            remediation="x",
        )
        result = result_no_valid_record("raw", [issue], [])
        assert result.data is None
        assert result.raw == "raw"
        assert len(result.issues) == 1

    def test_result_no_valid_record_empty_raw(self) -> None:
        result = result_no_valid_record("", [], [])
        assert result.raw is None


# ---------------------------------------------------------------------------
# rule_policy_strength
# ---------------------------------------------------------------------------


class TestRulePolicyStrength:
    def test_passes_when_meets_minimum(self) -> None:
        issues, _ = rule_policy_strength(
            _data(policy="reject"), _cfg(policy="reject"), False
        )
        assert issues == []

    def test_fails_when_below_minimum(self) -> None:
        issues, _ = rule_policy_strength(
            _data(policy="none"), _cfg(policy="reject"), False
        )
        assert len(issues) == 1
        assert issues[0].id == DMARCIssueId.POLICY_WEAK
        assert issues[0].severity == Severity.HIGH

    def test_recommends_reject_when_target_is_reject_strict(self) -> None:
        _, recs = rule_policy_strength(
            _data(policy="quarantine"),
            _cfg(policy="none", target_policy="reject"),
            True,
        )
        assert any(r.id == DMARCRecommendationId.ENABLE_REJECT for r in recs)

    def test_recommends_target_policy_non_strict(self) -> None:
        _, recs = rule_policy_strength(
            _data(policy="none"), _cfg(policy="none", target_policy="quarantine"), False
        )
        assert any(r.id == DMARCRecommendationId.ENABLE_REJECT for r in recs)
        assert any("quarantine" in r.title for r in recs)


# ---------------------------------------------------------------------------
# rule_subdomain_policy
# ---------------------------------------------------------------------------


class TestRuleSubdomainPolicy:
    def test_no_minimum_skips(self) -> None:
        issues, _ = rule_subdomain_policy(_data(subdomain_policy=None), _cfg(), False)
        assert issues == []

    def test_fails_when_sp_below_minimum(self) -> None:
        issues, _ = rule_subdomain_policy(
            _data(subdomain_policy="none"),
            _cfg(subdomain_policy_minimum="reject"),
            False,
        )
        assert len(issues) == 1
        assert issues[0].id == DMARCIssueId.SUBDOMAIN_POLICY_WEAK

    def test_passes_when_sp_meets_minimum(self) -> None:
        issues, _ = rule_subdomain_policy(
            _data(subdomain_policy="reject"),
            _cfg(subdomain_policy_minimum="quarantine"),
            False,
        )
        assert issues == []


# ---------------------------------------------------------------------------
# rule_rua
# ---------------------------------------------------------------------------


class TestRuleRua:
    def test_passes_when_rua_present(self) -> None:
        issues, _ = rule_rua(
            _data(rua=["mailto:a@b.com"]), _cfg(rua_required=True), False
        )
        assert issues == []

    def test_fails_when_rua_required_missing(self) -> None:
        issues, _ = rule_rua(_data(rua=[]), _cfg(rua_required=True), False)
        assert any(i.id == DMARCIssueId.RUA_MISSING for i in issues)

    def test_recommends_rua_strict_when_missing(self) -> None:
        _, recs = rule_rua(_data(rua=[]), _cfg(rua_required=False), True)
        assert any(r.id == DMARCRecommendationId.ADD_RUA for r in recs)


# ---------------------------------------------------------------------------
# rule_ruf
# ---------------------------------------------------------------------------


class TestRuleRuf:
    def test_fails_when_ruf_required_missing(self) -> None:
        issues, _ = rule_ruf(_data(ruf=[]), _cfg(ruf_required=True), False)
        assert any(i.id == DMARCIssueId.RUF_MISSING for i in issues)

    def test_passes_when_ruf_present(self) -> None:
        issues, _ = rule_ruf(
            _data(ruf=["mailto:f@b.com"]), _cfg(ruf_required=True), False
        )
        assert issues == []

    def test_recommends_ruf_when_strict(self) -> None:
        _, recs = rule_ruf(_data(ruf=[]), _cfg(ruf_required=False), True)
        assert any(r.id == DMARCRecommendationId.ADD_RUF for r in recs)


# ---------------------------------------------------------------------------
# rule_pct
# ---------------------------------------------------------------------------


class TestRulePct:
    def test_passes_at_100(self) -> None:
        issues, recs = rule_pct(_data(percentage=100), _cfg(minimum_pct=100), False)
        assert issues == []
        assert recs == []

    def test_fails_below_minimum(self) -> None:
        issues, _ = rule_pct(_data(percentage=50), _cfg(minimum_pct=100), False)
        assert any(i.id == DMARCIssueId.PCT_NOT_MIN for i in issues)

    def test_fails_not_100_when_minimum_is_100(self) -> None:
        # percentage >= minimum_pct (passes min check) but != 100 → PCT_NOT_100
        issues, _ = rule_pct(_data(percentage=75), _cfg(minimum_pct=50), True)
        assert any(i.id == DMARCIssueId.PCT_NOT_100 for i in issues)

    def test_recommends_100_when_below_strict(self) -> None:
        _, recs = rule_pct(_data(percentage=75), _cfg(minimum_pct=0), True)
        assert any(r.id == DMARCRecommendationId.SET_PCT_100 for r in recs)


# ---------------------------------------------------------------------------
# rule_alignment
# ---------------------------------------------------------------------------


class TestRuleAlignment:
    def test_no_strict_requirement_skips(self) -> None:
        issues, _ = rule_alignment(_data(), _cfg(require_strict_alignment=False), False)
        assert issues == []

    def test_adds_issue_when_relaxed_and_strict_required(self) -> None:
        issues, recs = rule_alignment(
            _data(alignment_dkim="r", alignment_spf="r"),
            _cfg(require_strict_alignment=True),
            False,
        )
        assert any(i.id == DMARCIssueId.ALIGNMENT_RELAXED for i in issues)
        assert any(r.id == DMARCRecommendationId.STRICT_ALIGNMENT for r in recs)

    def test_no_issue_when_both_strict(self) -> None:
        issues, _ = rule_alignment(
            _data(alignment_dkim="s", alignment_spf="s"),
            _cfg(require_strict_alignment=True),
            False,
        )
        assert issues == []
