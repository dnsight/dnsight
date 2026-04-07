"""Tests for the v1 config parser."""

from __future__ import annotations

from typing import Any

import pytest

from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.defaults import (
    DEFAULT_DNSSEC_REQUIRE_DS,
    DEFAULT_GLOBAL_CONCURRENCY_LIMIT,
    DEFAULT_GLOBAL_MAX_RPS,
    DEFAULT_SPF_LOOKUP_LIMIT,
)
from dnsight.core.config.parser.versions.v1 import parse_v1
from dnsight.core.config.targets import ChecksDelta, ChecksReplace, Target
from dnsight.core.exceptions import ConfigError
from dnsight.core.types import DNSProvider


def _minimal(**overrides: Any) -> dict[str, Any]:
    """Build a minimal v1 data dict, merging overrides."""
    base: dict[str, Any] = {"version": 1}
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# parse_v1 — integration
# ---------------------------------------------------------------------------


class TestParseV1Integration:
    def test_minimal_config_returns_config_manager(self) -> None:
        mgr = parse_v1(_minimal())
        assert isinstance(mgr, ConfigManager)
        assert mgr.config_schema_version == 1
        assert mgr.targets == []
        assert mgr.default_target_checks.enabled_names() == []

    def test_full_example(self) -> None:
        data: dict[str, Any] = {
            "version": 1,
            "resolver": {"provider": "cloudflare"},
            "targets": [
                {"domain": "corp.example.com"},
                {"domain": "foo.com", "paths": ["/", "/foo"]},
            ],
            "throttle": {"rps": 25, "concurrency": 4},
            "config": [
                {
                    "include": "*",
                    "checks": ["dmarc", "spf"],
                    "dmarc": {"required_policy": "none"},
                },
                {
                    "include": "corp.example.com",
                    "checks": "+headers",
                    "dmarc": {"required_policy": "reject"},
                },
            ],
        }
        mgr = parse_v1(data)

        assert len(mgr.targets) == 3
        assert mgr.targets[0] == Target(domain="corp.example.com", path="/")
        assert mgr.targets[1] == Target(domain="foo.com", path="/")
        assert mgr.targets[2] == Target(domain="foo.com", path="/foo")

        assert mgr.global_max_rps == 25.0
        assert mgr.global_max_concurrency == 4

        assert mgr.default_target_config.resolver.provider == DNSProvider.CLOUDFLARE
        assert set(mgr.default_target_checks.enabled_names()) == {"dmarc", "spf"}
        # Default rule explicitly sets dmarc.required_policy: "none"
        assert mgr.default_target_config.dmarc.policy == "none"

        assert "corp.example.com" in mgr.target_configs
        tc = mgr.target_configs["corp.example.com"]
        assert tc.config.dmarc.policy == "reject"
        assert isinstance(tc.checks, ChecksDelta)
        assert tc.checks.add == frozenset({"headers"})


# ---------------------------------------------------------------------------
# _parse_targets
# ---------------------------------------------------------------------------


class TestParseTargets:
    def test_empty_targets(self) -> None:
        mgr = parse_v1(_minimal(targets=[]))
        assert mgr.targets == []

    def test_single_domain(self) -> None:
        mgr = parse_v1(_minimal(targets=[{"domain": "a.com"}]))
        assert mgr.targets == [Target(domain="a.com", path="/")]

    def test_domain_with_paths(self) -> None:
        mgr = parse_v1(_minimal(targets=[{"domain": "a.com", "paths": ["/x", "/y"]}]))
        assert mgr.targets == [
            Target(domain="a.com", path="/x"),
            Target(domain="a.com", path="/y"),
        ]

    def test_missing_domain_raises(self) -> None:
        with pytest.raises(ConfigError, match="domain"):
            parse_v1(_minimal(targets=[{"paths": ["/"]}]))

    def test_empty_domain_raises(self) -> None:
        with pytest.raises(ConfigError, match="domain"):
            parse_v1(_minimal(targets=[{"domain": ""}]))

    def test_extra_keys_ignored(self) -> None:
        mgr = parse_v1(_minimal(targets=[{"domain": "a.com", "subdomains": True}]))
        assert mgr.targets == [Target(domain="a.com", path="/")]


# ---------------------------------------------------------------------------
# _parse_resolver
# ---------------------------------------------------------------------------


class TestParseResolver:
    def test_no_resolver_uses_system(self) -> None:
        mgr = parse_v1(_minimal())
        assert mgr.default_target_config.resolver.provider == DNSProvider.SYSTEM

    def test_cloudflare(self) -> None:
        mgr = parse_v1(_minimal(resolver={"provider": "cloudflare"}))
        assert mgr.default_target_config.resolver.provider == DNSProvider.CLOUDFLARE

    def test_google(self) -> None:
        mgr = parse_v1(_minimal(resolver={"provider": "google"}))
        assert mgr.default_target_config.resolver.provider == DNSProvider.GOOGLE


# ---------------------------------------------------------------------------
# _parse_throttle
# ---------------------------------------------------------------------------


class TestParseThrottle:
    def test_no_throttle_uses_defaults(self) -> None:
        mgr = parse_v1(_minimal())
        assert mgr.global_max_rps == DEFAULT_GLOBAL_MAX_RPS
        assert mgr.global_max_concurrency == DEFAULT_GLOBAL_CONCURRENCY_LIMIT

    def test_custom_rps_and_concurrency(self) -> None:
        mgr = parse_v1(_minimal(throttle={"rps": 10, "concurrency": 2}))
        assert mgr.global_max_rps == 10.0
        assert mgr.global_max_concurrency == 2

    def test_partial_rps_only(self) -> None:
        mgr = parse_v1(_minimal(throttle={"rps": 5}))
        assert mgr.global_max_rps == 5.0
        assert mgr.global_max_concurrency == DEFAULT_GLOBAL_CONCURRENCY_LIMIT

    def test_partial_concurrency_only(self) -> None:
        mgr = parse_v1(_minimal(throttle={"concurrency": 3}))
        assert mgr.global_max_rps == DEFAULT_GLOBAL_MAX_RPS
        assert mgr.global_max_concurrency == 3


# ---------------------------------------------------------------------------
# _parse_config_rules — default rule detection
# ---------------------------------------------------------------------------


class TestConfigRulesDefault:
    def test_star_no_exclude_is_default(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*", "checks": ["dmarc", "spf"]}]))
        assert set(mgr.default_target_checks.enabled_names()) == {"dmarc", "spf"}
        assert len(mgr.target_configs) == 0

    def test_star_with_exclude_is_not_default(self) -> None:
        mgr = parse_v1(
            _minimal(
                config=[
                    {"include": "*", "exclude": "internal.com", "checks": ["dmarc"]}
                ]
            )
        )
        assert mgr.default_target_checks.enabled_names() == []
        assert "*" in mgr.target_configs

    def test_default_merges_dmarc_config(self) -> None:
        mgr = parse_v1(
            _minimal(
                config=[
                    {
                        "include": "*",
                        "checks": ["dmarc"],
                        "dmarc": {"required_policy": "quarantine"},
                    }
                ]
            )
        )
        assert mgr.default_target_config.dmarc.policy == "quarantine"

    def test_no_config_rules_gives_empty_defaults(self) -> None:
        mgr = parse_v1(_minimal())
        assert mgr.default_target_checks.enabled_names() == []
        assert len(mgr.target_configs) == 0


# ---------------------------------------------------------------------------
# _parse_config_rules — non-default rules
# ---------------------------------------------------------------------------


class TestConfigRulesNonDefault:
    def test_non_star_rule_goes_to_target_configs(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*.com", "checks": ["dmarc"]}]))
        assert "*.com" in mgr.target_configs
        tc = mgr.target_configs["*.com"]
        assert isinstance(tc.checks, ChecksReplace)
        assert tc.checks.enabled == ("dmarc",)

    def test_delta_checks_string(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "a.com", "checks": "+dmarc,-spf"}]))
        tc = mgr.target_configs["a.com"]
        assert isinstance(tc.checks, ChecksDelta)
        assert tc.checks.add == frozenset({"dmarc"})
        assert tc.checks.remove == frozenset({"spf"})

    def test_no_checks_key_gives_none(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "a.com"}]))
        tc = mgr.target_configs["a.com"]
        assert tc.checks is None

    def test_missing_include_raises(self) -> None:
        with pytest.raises(ConfigError, match="missing 'include'"):
            parse_v1(_minimal(config=[{"checks": ["dmarc"]}]))

    def test_precedence_matches_index(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*.com"}, {"include": "a.com"}]))
        assert mgr.target_configs["*.com"].precedence == 0
        assert mgr.target_configs["a.com"].precedence == 1

    def test_order_preserved(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "z.com"}, {"include": "a.com"}]))
        keys = list(mgr.target_configs.keys())
        assert keys == ["z.com", "a.com"]


# ---------------------------------------------------------------------------
# Exclude normalisation
# ---------------------------------------------------------------------------


class TestExcludeNormalisation:
    def test_string_becomes_list(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*.com", "exclude": "skip.com"}]))
        assert mgr.target_configs["*.com"].exclude == ["skip.com"]

    def test_list_stays_list(self) -> None:
        mgr = parse_v1(
            _minimal(config=[{"include": "*.com", "exclude": ["a.com", "b.com"]}])
        )
        assert mgr.target_configs["*.com"].exclude == ["a.com", "b.com"]

    def test_none_stays_none(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*.com"}]))
        assert mgr.target_configs["*.com"].exclude is None


# ---------------------------------------------------------------------------
# _build_rule_config — throttle overrides
# ---------------------------------------------------------------------------


class TestRuleConfigThrottle:
    def test_rps_in_rule(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*", "rps": 99}]))
        assert mgr.default_target_config.throttle.global_max_rps == 99.0

    def test_concurrency_in_rule(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*", "concurrency": 3}]))
        assert mgr.default_target_config.throttle.global_max_concurrency == 3

    def test_no_throttle_keys_uses_defaults(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*"}]))
        cfg = mgr.default_target_config
        assert cfg.throttle.global_max_rps == DEFAULT_GLOBAL_MAX_RPS
        assert cfg.throttle.global_max_concurrency == DEFAULT_GLOBAL_CONCURRENCY_LIMIT


# ---------------------------------------------------------------------------
# _build_rule_config — DMARC field remapping
# ---------------------------------------------------------------------------


class TestRuleConfigDmarc:
    def test_required_policy_maps_to_policy(self) -> None:
        mgr = parse_v1(
            _minimal(config=[{"include": "*", "dmarc": {"required_policy": "reject"}}])
        )
        assert mgr.default_target_config.dmarc.policy == "reject"

    def test_rua_required(self) -> None:
        mgr = parse_v1(
            _minimal(config=[{"include": "*", "dmarc": {"rua_required": True}}])
        )
        assert mgr.default_target_config.dmarc.rua_required is True

    def test_no_dmarc_key_uses_default(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*"}]))
        assert mgr.default_target_config.dmarc.policy == "reject"

    def test_non_dict_dmarc_ignored(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*", "dmarc": "not-a-dict"}]))
        assert mgr.default_target_config.dmarc.policy == "reject"


# ---------------------------------------------------------------------------
# Headers config in rules
# ---------------------------------------------------------------------------


class TestHeadersConfigInRules:
    def test_headers_config_merges_from_rule(self) -> None:
        mgr = parse_v1(
            _minimal(config=[{"include": "*", "headers": {"require": ["CSP", "HSTS"]}}])
        )
        assert mgr.default_target_config.headers.require == ["CSP", "HSTS"]


# ---------------------------------------------------------------------------
# SPF and DNSSEC config in rules
# ---------------------------------------------------------------------------


class TestRuleConfigSpfDnssec:
    def test_spf_config_merges_from_rule(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*", "spf": {"lookup_limit": 5}}]))
        assert mgr.default_target_config.spf.lookup_limit == 5

    def test_spf_absent_uses_defaults(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*"}]))
        assert mgr.default_target_config.spf.lookup_limit == DEFAULT_SPF_LOOKUP_LIMIT

    def test_dnssec_config_merges_from_rule(self) -> None:
        mgr = parse_v1(
            _minimal(
                config=[
                    {
                        "include": "*",
                        "dnssec": {
                            "require_ds": True,
                            "signature_expiry_days_warning": 14,
                        },
                    }
                ]
            )
        )
        assert mgr.default_target_config.dnssec.require_ds is True
        assert mgr.default_target_config.dnssec.signature_expiry_days_warning == 14

    def test_dnssec_absent_uses_defaults(self) -> None:
        mgr = parse_v1(_minimal(config=[{"include": "*"}]))
        assert mgr.default_target_config.dnssec.require_ds == DEFAULT_DNSSEC_REQUIRE_DS


# ---------------------------------------------------------------------------
# Unknown check config keys in rules are silently skipped
# ---------------------------------------------------------------------------


class TestUnknownCheckConfig:
    def test_unknown_rule_keys_do_not_error(self) -> None:
        mgr = parse_v1(
            _minimal(config=[{"include": "*", "future_unknown_slice": {"a": 1}}])
        )
        assert isinstance(mgr, ConfigManager)


# ---------------------------------------------------------------------------
# Resolver propagation into default config
# ---------------------------------------------------------------------------


class TestResolverInDefaultConfig:
    def test_resolver_set_on_default_config(self) -> None:
        mgr = parse_v1(_minimal(resolver={"provider": "quad9"}))
        assert mgr.default_target_config.resolver.provider == DNSProvider.QUAD9

    def test_resolver_survives_default_rule_merge(self) -> None:
        mgr = parse_v1(
            _minimal(
                resolver={"provider": "opendns"},
                config=[{"include": "*", "dmarc": {"required_policy": "reject"}}],
            )
        )
        assert mgr.default_target_config.resolver.provider == DNSProvider.OPENDNS
        assert mgr.default_target_config.dmarc.policy == "reject"
