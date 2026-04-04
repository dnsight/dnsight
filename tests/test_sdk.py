"""Tests for the public SDK (delegation to orchestrator)."""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

import pytest

from dnsight.checks.base import BaseGenerateParams
from dnsight.checks.caa import CaaGenerateParams
from dnsight.checks.dmarc import DMARCGenerateParams
from dnsight.checks.headers import HstsGenerateParams
from dnsight.checks.mx.models import MXGenerateParams, MXGenerateTarget
from dnsight.checks.spf import SPFGenerateParams
from dnsight.core.config import Config, ConfigManager, DmarcConfig, TargetChecks
from dnsight.core.config.targets import Target, TargetConfig
from dnsight.core.exceptions import CapabilityError
from dnsight.core.types import RecordType
from dnsight.sdk import (
    check_dmarc,
    check_dmarc_sync,
    check_spf_sync,
    generate,
    generate_caa,
    generate_headers,
    generate_mx,
    generate_spf,
    run_batch_sync,
    run_check_sync,
    run_domain_sync,
    run_targets_sync,
)
from dnsight.utils.dns import FakeDNSResolver, reset_resolver, set_resolver


pytestmark = pytest.mark.registry_builtins


@pytest.fixture(autouse=True)
def _reset_resolver() -> None:
    reset_resolver()
    yield
    reset_resolver()


def _mgr(enabled: list[str]) -> ConfigManager:
    rules: OrderedDict[str, TargetConfig] = OrderedDict()
    rules["*"] = TargetConfig(include="*", precedence=0, config=Config(), checks=None)
    return ConfigManager(
        targets=[],
        target_configs=rules,
        default_target_config=Config(),
        default_target_checks=TargetChecks.from_enabled(enabled),
    )


def _mgr_dmarc_only() -> ConfigManager:
    return _mgr(["dmarc"])


class TestSdkRunDomain:
    def test_run_domain_sync_with_mgr(self) -> None:
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [txt]}))
        mgr = _mgr_dmarc_only()
        result = run_domain_sync("example.com", mgr=mgr)
        assert result.domain == "example.com"
        assert "dmarc" in result.root.results


class TestSdkRunCheck:
    def test_run_check_sync_dmarc(self) -> None:
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [txt]}))
        mgr = _mgr_dmarc_only()
        result = run_check_sync("dmarc", "example.com", mgr=mgr)
        assert result.data is not None

    def test_run_check_sync_programmatic_config_no_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No dnsight.yaml: inline Config builds a synthetic single-check manager."""
        monkeypatch.chdir(tmp_path)
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [txt]}))
        result = run_check_sync(
            "dmarc", "example.com", config=Config(dmarc=DmarcConfig(policy="reject"))
        )
        assert result.data is not None

    def test_run_check_sync_yaml_plus_overlay_merge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Discovered YAML merged with programmatic Config (overlay)."""
        cfg = tmp_path / "dnsight.yaml"
        cfg.write_text(
            """version: 1
config:
  - include: "*"
    checks: [dmarc]
    dmarc:
      required_policy: none
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [txt]}))
        result = run_check_sync(
            "dmarc", "example.com", config=Config(dmarc=DmarcConfig(policy="reject"))
        )
        assert result.data is not None


class TestSdkDmarcAlias:
    def test_check_dmarc_sync_config_slice_overrides_config(self) -> None:
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [txt]}))
        result = check_dmarc_sync(
            "example.com",
            config=Config(dmarc=DmarcConfig(policy="none")),
            config_slice=DmarcConfig(policy="reject"),
        )
        assert result.data is not None

    @pytest.mark.asyncio
    async def test_check_dmarc_async_config_slice_overrides_config(self) -> None:
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [txt]}))
        result = await check_dmarc(
            "example.com",
            config=Config(dmarc=DmarcConfig(policy="none")),
            config_slice=DmarcConfig(policy="reject"),
        )
        assert result.data is not None


class TestSdkGenerate:
    def test_generate_dmarc(self) -> None:
        rec = generate(
            "dmarc",
            params=DMARCGenerateParams(
                policy="reject",
                percentage=100,
                subdomain_policy=None,
                alignment_dkim="r",
                alignment_spf="r",
                rua=["mailto:a@example.com"],
                ruf=[],
            ),
        )
        assert rec.record_type == RecordType.TXT
        assert rec.host == "_dmarc"
        assert "v=DMARC1" in rec.value

    def test_generate_caa(self) -> None:
        rec = generate_caa(params=CaaGenerateParams(issuers=["letsencrypt.org"]))
        assert rec.record_type == RecordType.CAA
        assert '0 issue "letsencrypt.org"' in rec.value

    def test_generate_spf(self) -> None:
        rec = generate_spf(params=SPFGenerateParams(disposition="-all"))
        assert rec.record_type == RecordType.TXT
        assert "v=spf1" in rec.value

    def test_generate_mx(self) -> None:
        rec = generate_mx(
            params=MXGenerateParams(
                targets=[MXGenerateTarget(priority=10, hostname="mail.example.com")]
            )
        )
        assert rec.record_type == RecordType.MX
        assert rec.value == "10 mail.example.com."

    def test_generate_dkim_raises_capability_error(self) -> None:
        with pytest.raises(CapabilityError, match="dkim"):
            generate("dkim", params=BaseGenerateParams())

    def test_generate_headers_default_hsts(self) -> None:
        rec = generate_headers()
        assert "max-age" in rec.value.lower() or "strict" in rec.value.lower()

    def test_generate_headers_explicit(self) -> None:
        rec = generate_headers(params=HstsGenerateParams(max_age=3600))
        assert "max-age" in rec.value.lower()


class TestSdkCheckSpf:
    def test_check_spf_sync_with_mgr(self) -> None:
        set_resolver(FakeDNSResolver(records={"example.com/TXT": ["v=spf1 -all"]}))
        mgr = _mgr(["spf"])
        result = check_spf_sync("example.com", mgr=mgr)
        assert result.data is not None


class TestSdkTargets:
    def test_run_targets_sync_empty_targets(self) -> None:
        mgr = _mgr_dmarc_only()
        assert run_targets_sync(mgr=mgr) == []

    def test_run_targets_sync_two_targets(self) -> None:
        txt = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"
        set_resolver(
            FakeDNSResolver(
                records={
                    "_dmarc.x.example.com/TXT": [txt],
                    "_dmarc.y.example.com/TXT": [txt],
                }
            )
        )
        rules: OrderedDict[str, TargetConfig] = OrderedDict()
        rules["*"] = TargetConfig(
            include="*", precedence=0, config=Config(), checks=None
        )
        mgr = ConfigManager(
            targets=[Target("x.example.com"), Target("y.example.com")],
            target_configs=rules,
            default_target_config=Config(),
            default_target_checks=TargetChecks.from_enabled(["dmarc"]),
        )
        results = run_targets_sync(mgr=mgr)
        assert len(results) == 2
        assert {r.domain for r in results} == {"x.example.com", "y.example.com"}

    def test_run_batch_sync_deprecated(self) -> None:
        m = _mgr_dmarc_only()
        with pytest.warns(DeprecationWarning, match="run_targets_sync"):
            assert run_batch_sync(mgr=m) == []
