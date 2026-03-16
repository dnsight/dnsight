"""Tests for config blocks."""

from __future__ import annotations

import pytest

from dnsight.core.config.blocks import (
    Config,
    DmarcConfig,
    ResolverConfig,
    ThrottleConfig,
)
from dnsight.core.config.defaults import (
    DEFAULT_DMARC_POLICY,
    DEFAULT_DMARC_RUA_REQUIRED,
    DEFAULT_GLOBAL_CONCURRENCY_LIMIT,
    DEFAULT_GLOBAL_MAX_RPS,
    DNS_PROVIDER_NAMESERVERS,
)
from dnsight.core.types import DNSProvider


class TestResolverConfig:
    def test_default_provider_is_system(self) -> None:
        cfg = ResolverConfig()
        assert cfg.provider == DNSProvider.SYSTEM

    def test_resolved_nameservers_system_returns_none(self) -> None:
        cfg = ResolverConfig(provider=DNSProvider.SYSTEM)
        assert cfg.resolved_nameservers() is None

    @pytest.mark.parametrize(
        "provider", [p for p in DNSProvider if p != DNSProvider.SYSTEM]
    )
    def test_resolved_nameservers_named_provider(self, provider: DNSProvider) -> None:
        cfg = ResolverConfig(provider=provider)
        expected = DNS_PROVIDER_NAMESERVERS[provider.value]
        assert cfg.resolved_nameservers() == expected


class TestThrottleConfig:
    def test_defaults(self) -> None:
        cfg = ThrottleConfig()
        assert cfg.global_max_rps == DEFAULT_GLOBAL_MAX_RPS
        assert cfg.global_max_concurrency == DEFAULT_GLOBAL_CONCURRENCY_LIMIT


class TestDmarcConfig:
    def test_defaults(self) -> None:
        cfg = DmarcConfig()
        assert cfg.policy == DEFAULT_DMARC_POLICY
        assert cfg.rua_required == DEFAULT_DMARC_RUA_REQUIRED


class TestConfig:
    def test_default_construction(self) -> None:
        cfg = Config()
        assert isinstance(cfg.resolver, ResolverConfig)
        assert isinstance(cfg.throttle, ThrottleConfig)
        assert isinstance(cfg.dmarc, DmarcConfig)

    def test_merge_nested(self) -> None:
        base = Config()
        override = Config(dmarc=DmarcConfig(policy="reject"))

        merged = base.merge(override)
        assert merged.dmarc.policy == "reject"
        assert merged.throttle.global_max_rps == DEFAULT_GLOBAL_MAX_RPS

    def test_merge_multiple_nested_blocks(self) -> None:
        base = Config()
        override = Config(dmarc=DmarcConfig(policy="quarantine"))

        merged = base.merge(override)
        assert merged.dmarc.policy == "quarantine"
        assert merged.resolver.provider == DNSProvider.SYSTEM
