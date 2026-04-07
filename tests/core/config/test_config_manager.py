"""Tests for ConfigManager."""

from __future__ import annotations

from collections import OrderedDict

from dnsight.core.config.blocks import Config, DmarcConfig
from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.targets import (
    ChecksDelta,
    ChecksReplace,
    ResolvedTargetConfig,
    Target,
    TargetChecks,
    TargetConfig,
)


def _make_manager(
    target_configs: OrderedDict[str, TargetConfig] | None = None,
    default_checks: TargetChecks | None = None,
) -> ConfigManager:
    return ConfigManager(
        targets=[Target(domain="example.com")],
        target_configs=target_configs or OrderedDict(),
        default_target_config=Config(),
        default_target_checks=default_checks or TargetChecks(),
    )


class TestTargetString:
    def test_from_target_object(self) -> None:
        result = ConfigManager.target_string(Target("Example.COM", "/api"))
        assert result == "example.com/api"

    def test_from_domain_string(self) -> None:
        result = ConfigManager.target_string("Example.COM")
        assert result == "example.com"

    def test_from_domain_and_path(self) -> None:
        result = ConfigManager.target_string("example.com", "/api/v1")
        assert result == "example.com/api/v1"


class TestResolveDefaults:
    def test_no_rules_returns_defaults(self) -> None:
        mgr = _make_manager()
        resolved = mgr.resolve("example.com")
        assert isinstance(resolved, ResolvedTargetConfig)
        assert resolved.checks.enabled_names() == []
        assert resolved.config.dmarc.policy == "reject"


class TestResolveMatching:
    def test_matching_rule_merges_config(self) -> None:
        configs = OrderedDict()
        configs["*.com"] = TargetConfig(
            include="*.com",
            precedence=1,
            config=Config(dmarc=DmarcConfig(policy="reject")),
        )
        mgr = _make_manager(target_configs=configs)
        resolved = mgr.resolve("example.com")
        assert resolved.config.dmarc.policy == "reject"

    def test_non_matching_rule_ignored(self) -> None:
        configs = OrderedDict()
        configs["*.org"] = TargetConfig(
            include="*.org",
            precedence=1,
            config=Config(dmarc=DmarcConfig(policy="reject")),
        )
        mgr = _make_manager(target_configs=configs)
        resolved = mgr.resolve("example.com")
        assert resolved.config.dmarc.policy == "reject"


class TestResolveExclude:
    def test_exclude_skips_target(self) -> None:
        configs = OrderedDict()
        configs["*.com"] = TargetConfig(
            include="*.com",
            precedence=1,
            config=Config(dmarc=DmarcConfig(policy="reject")),
            exclude=["example.com"],
        )
        mgr = _make_manager(target_configs=configs)
        resolved = mgr.resolve("example.com")
        assert resolved.config.dmarc.policy == "reject"

    def test_non_excluded_target_still_matches(self) -> None:
        configs = OrderedDict()
        configs["*.com"] = TargetConfig(
            include="*.com",
            precedence=1,
            config=Config(dmarc=DmarcConfig(policy="reject")),
            exclude=["other.com"],
        )
        mgr = _make_manager(target_configs=configs)
        resolved = mgr.resolve("example.com")
        assert resolved.config.dmarc.policy == "reject"


class TestResolveCaching:
    def test_cached_result(self) -> None:
        mgr = _make_manager()
        first = mgr.resolve("example.com")
        second = mgr.resolve("example.com")
        assert first is second

    def test_different_targets_not_cached(self) -> None:
        mgr = _make_manager()
        first = mgr.resolve("a.com")
        second = mgr.resolve("b.com")
        assert first is not second


class TestResolveChecksReplace:
    def test_replace_sets_exactly(self) -> None:
        configs = OrderedDict()
        configs["*.com"] = TargetConfig(
            include="*.com",
            precedence=1,
            config=Config(),
            checks=ChecksReplace(enabled=("dmarc", "spf")),
        )
        mgr = _make_manager(target_configs=configs)
        resolved = mgr.resolve("example.com")
        assert set(resolved.checks.enabled_names()) == {"dmarc", "spf"}


class TestResolveChecksDelta:
    def test_delta_adds_and_removes(self) -> None:
        base_checks = TargetChecks.from_enabled(("dmarc", "caa"))
        configs = OrderedDict()
        configs["*.com"] = TargetConfig(
            include="*.com",
            precedence=1,
            config=Config(),
            checks=ChecksDelta(add=frozenset({"spf"}), remove=frozenset({"dmarc"})),
        )
        mgr = _make_manager(target_configs=configs, default_checks=base_checks)
        resolved = mgr.resolve("example.com")
        names = resolved.checks.enabled_names()
        assert "spf" in names
        assert "caa" in names
        assert "dmarc" not in names


class TestResolveMultipleRules:
    def test_later_rule_overrides(self) -> None:
        configs = OrderedDict()
        configs["*.com"] = TargetConfig(
            include="*.com",
            precedence=1,
            config=Config(dmarc=DmarcConfig(policy="quarantine")),
        )
        configs["example.com"] = TargetConfig(
            include="example.com",
            precedence=2,
            config=Config(dmarc=DmarcConfig(policy="reject")),
        )
        mgr = _make_manager(target_configs=configs)
        resolved = mgr.resolve("example.com")
        assert resolved.config.dmarc.policy == "reject"


class TestResolveCallForms:
    def test_resolve_with_target_object(self) -> None:
        mgr = _make_manager()
        resolved = mgr.resolve(Target("example.com", "/api"))
        assert isinstance(resolved, ResolvedTargetConfig)

    def test_resolve_with_domain_and_path(self) -> None:
        mgr = _make_manager()
        resolved = mgr.resolve("example.com", "/api")
        assert isinstance(resolved, ResolvedTargetConfig)
