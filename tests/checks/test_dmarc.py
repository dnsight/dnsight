"""Tests for checks/dmarc package — DMARCCheck, DMARCData, enums, and static methods."""

from __future__ import annotations

from pydantic import ValidationError
import pytest

from dnsight.checks.dmarc import (
    DMARCCheck,
    DMARCData,
    DMARCGenerateParams,
    DMARCIssueId,
    DMARCRecommendationId,
    check_dmarc,
    generate_dmarc,
    get_dmarc,
)
from dnsight.core.config.blocks import DmarcConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.models import GeneratedRecord
from dnsight.core.types import Capability
from dnsight.utils.dns import FakeDNSResolver, set_resolver


# -- Enum tests ---------------------------------------------------------------


class TestDMARCIssueId:
    def test_members_exist(self) -> None:
        assert DMARCIssueId.POLICY_MISSING == "dmarc.policy.missing"
        assert DMARCIssueId.POLICY_WEAK == "dmarc.policy.weak"
        assert DMARCIssueId.POLICY_NONE == "dmarc.policy.none"
        assert DMARCIssueId.RUA_MISSING == "dmarc.rua.missing"
        assert DMARCIssueId.PCT_NOT_100 == "dmarc.pct.not_100"

    def test_member_count(self) -> None:
        assert len(DMARCIssueId) == 13


class TestDMARCRecommendationId:
    def test_members_exist(self) -> None:
        assert DMARCRecommendationId.ENABLE_REJECT == "dmarc.enable.reject"
        assert DMARCRecommendationId.ADD_RUA == "dmarc.add.rua"

    def test_member_count(self) -> None:
        assert len(DMARCRecommendationId) == 5


# -- DMARCData tests ----------------------------------------------------------


class TestDMARCData:
    def test_construction(self) -> None:
        data = DMARCData(
            policy="reject",
            percentage=100,
            alignment_dkim="r",
            alignment_spf="r",
            rua=["mailto:dmarc@example.com"],
            raw_record="v=DMARC1; p=reject",
        )
        assert data.policy == "reject"
        assert data.percentage == 100
        assert data.subdomain_policy is None
        assert data.ruf == []

    def test_frozen(self) -> None:
        data = DMARCData(
            policy="none",
            percentage=50,
            alignment_dkim="r",
            alignment_spf="r",
            raw_record="v=DMARC1; p=none",
        )
        with pytest.raises(ValidationError):
            data.policy = "reject"  # type: ignore[misc]

    def test_all_fields(self) -> None:
        data = DMARCData(
            policy="quarantine",
            subdomain_policy="reject",
            percentage=75,
            alignment_dkim="s",
            alignment_spf="s",
            rua=["mailto:a@example.com"],
            ruf=["mailto:b@example.com"],
            raw_record="full record",
        )
        assert data.subdomain_policy == "reject"
        assert data.alignment_dkim == "s"
        assert data.rua == ["mailto:a@example.com"]
        assert data.ruf == ["mailto:b@example.com"]


# -- DMARCCheck class tests ---------------------------------------------------


class TestDMARCCheck:
    def test_name(self) -> None:
        assert DMARCCheck.name == "dmarc"

    def test_capabilities(self) -> None:
        assert Capability.CHECK in DMARCCheck.capabilities
        assert Capability.GENERATE in DMARCCheck.capabilities

    @pytest.mark.asyncio
    async def test_instance_get_delegates(self) -> None:
        set_resolver(
            FakeDNSResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject; pct=100"]})
        )
        check = DMARCCheck()
        data = await check.get("example.com")
        assert isinstance(data, DMARCData)
        assert data.policy == "reject"

    @pytest.mark.asyncio
    async def test_get_missing_raises(self) -> None:
        set_resolver(FakeDNSResolver({}))
        with pytest.raises(CheckError, match="no TXT record"):
            await get_dmarc("example.com")

    @pytest.mark.asyncio
    async def test_check_missing_returns_issue(self) -> None:
        set_resolver(FakeDNSResolver({}))
        result = await check_dmarc("example.com")
        assert len(result.issues) == 1
        assert result.issues[0].id == DMARCIssueId.POLICY_MISSING

    @pytest.mark.asyncio
    async def test_get_dmarc_with_config(self) -> None:
        set_resolver(
            FakeDNSResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject; pct=100"]})
        )
        data = await get_dmarc("example.com", config=DmarcConfig())
        assert data.policy == "reject"

    @pytest.mark.asyncio
    async def test_check_dmarc_with_config(self) -> None:
        set_resolver(
            FakeDNSResolver(
                {
                    "_dmarc.example.com/TXT": [
                        "v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com"
                    ]
                }
            )
        )
        result = await check_dmarc("example.com", config=DmarcConfig())
        assert result.status.value == "completed"
        assert result.data is not None

    @pytest.mark.asyncio
    async def test_instance_check_delegates(self) -> None:
        set_resolver(
            FakeDNSResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject; pct=100"]})
        )
        check = DMARCCheck()
        result = await check.check("example.com")
        assert result.data is not None
        assert result.data.policy == "reject"


# -- generate_dmarc tests ----------------------------------------------------


class TestGenerateDmarc:
    def test_default_config(self) -> None:
        record = generate_dmarc()
        assert isinstance(record, GeneratedRecord)
        assert record.record_type == "TXT"
        assert record.host == "_dmarc"
        assert "v=DMARC1" in record.value
        assert "p=reject" in record.value

    def test_with_custom_policy(self) -> None:
        config = DmarcConfig(policy="quarantine", rua_required=False)
        record = generate_dmarc(config=config)
        assert "p=quarantine" in record.value

    def test_with_rua_required(self) -> None:
        config = DmarcConfig(rua_required=True)
        record = generate_dmarc(config=config)
        assert "rua=mailto:" in record.value

    def test_without_rua(self) -> None:
        config = DmarcConfig(policy="quarantine", rua_required=False)
        record = generate_dmarc(config=config)
        assert "rua=" not in record.value

    def test_none_config_uses_defaults(self) -> None:
        record = generate_dmarc(config=None)
        assert "v=DMARC1" in record.value

    def test_via_instance_generate(self) -> None:
        check = DMARCCheck()
        record = check.generate(params=DMARCGenerateParams())
        assert isinstance(record, GeneratedRecord)
        assert record.record_type == "TXT"

    def test_via_instance_generate_with_params(self) -> None:
        check = DMARCCheck()
        params = DMARCGenerateParams.from_config(
            DmarcConfig(policy="none", rua_required=False)
        )
        record = check.generate(params=params)
        assert "p=none" in record.value
        assert "rua=" not in record.value

    def test_from_config(self) -> None:
        config = DmarcConfig(
            policy="quarantine",
            minimum_pct=50,
            require_strict_alignment=True,
            rua_required=True,
        )
        params = DMARCGenerateParams.from_config(config)
        assert params.policy == "quarantine"
        assert params.percentage == 50
        assert params.alignment_dkim == "s"
        assert params.alignment_spf == "s"
        assert len(params.rua) == 1
        assert "mailto:" in params.rua[0]

    def test_from_config_expected_rua_ruf_override_placeholder(self) -> None:
        config = DmarcConfig(
            expected_rua=["mailto:agg@corp.test"],
            expected_ruf=["mailto:forensic@corp.test"],
            rua_required=True,
            ruf_required=True,
        )
        params = DMARCGenerateParams.from_config(config)
        assert params.rua == ["mailto:agg@corp.test"]
        assert params.ruf == ["mailto:forensic@corp.test"]

    def test_generate_includes_expected_uris(self) -> None:
        config = DmarcConfig(
            expected_rua=["mailto:rua@example.com"],
            expected_ruf=["mailto:ruf@example.com"],
        )
        record = generate_dmarc(config=config)
        assert "rua=mailto:rua@example.com" in record.value
        assert "ruf=mailto:ruf@example.com" in record.value


# -- Module-level aliases test ------------------------------------------------


class TestModuleAliases:
    def test_get_dmarc_is_static_method(self) -> None:
        assert get_dmarc is DMARCCheck.get_dmarc

    def test_check_dmarc_is_static_method(self) -> None:
        assert check_dmarc is DMARCCheck.check_dmarc

    def test_generate_dmarc_is_static_method(self) -> None:
        assert generate_dmarc is DMARCCheck.generate_dmarc
