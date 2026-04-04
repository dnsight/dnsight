"""Tests for the orchestrator."""

from __future__ import annotations

from collections import OrderedDict

import pytest

from dnsight.core.config import Config, ConfigManager, TargetChecks
from dnsight.core.config.blocks import ResolverConfig
from dnsight.core.config.defaults import DNS_PROVIDER_NAMESERVERS
from dnsight.core.config.targets import Target, TargetConfig
from dnsight.core.registry import CheckDefinition, get
from dnsight.core.types import DNSProvider, Status
from dnsight.orchestrator import (
    RunAuditOptions,
    apply_resolver_config,
    run_check_for_target,
    run_config_targets,
    run_domain,
    run_domain_stream,
)
from dnsight.utils.dns import (
    AsyncDNSResolver,
    FakeDNSResolver,
    get_resolver,
    reset_resolver,
    set_resolver,
)


pytestmark = pytest.mark.registry_builtins

_DMARC_TXT = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"


@pytest.fixture(autouse=True)
def _reset_resolver() -> None:
    reset_resolver()
    yield
    reset_resolver()


def _mgr_dmarc_only() -> ConfigManager:
    rules: OrderedDict[str, TargetConfig] = OrderedDict()
    rules["*"] = TargetConfig(include="*", precedence=0, config=Config(), checks=None)
    return ConfigManager(
        targets=[],
        target_configs=rules,
        default_target_config=Config(),
        default_target_checks=TargetChecks.from_enabled(["dmarc"]),
    )


class TestApplyResolverConfig:
    def test_cloudflare_nameservers(self) -> None:
        apply_resolver_config(ResolverConfig(provider=DNSProvider.CLOUDFLARE))
        r = get_resolver()
        assert isinstance(r, AsyncDNSResolver)
        assert r._inner.nameservers == DNS_PROVIDER_NAMESERVERS["cloudflare"]


class TestRunDomain:
    async def test_dmarc_completes_with_fake_dns(self) -> None:
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        result = await run_domain("example.com", mgr=mgr)
        assert result.domain == "example.com"
        assert not result.partial
        assert "dmarc" in result.root.results
        assert result.root.results["dmarc"].status == Status.COMPLETED

    async def test_respects_check_subset(self) -> None:
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        result = await run_domain("example.com", mgr=mgr, checks=["dmarc"])
        assert set(result.root.results.keys()) == {"dmarc"}

    async def test_failed_check_makes_partial(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_get = get

        class _BoomCheck:
            async def check(
                self,
                domain: str,
                *,
                config: object | None = None,
                throttler: object | None = None,
            ) -> object:
                raise RuntimeError("intentional boom")

        def fake_get(name: str) -> CheckDefinition:
            if name == "boom":
                return CheckDefinition(
                    name="boom", cls=_BoomCheck, capabilities=frozenset()
                )
            return real_get(name)

        monkeypatch.setattr("dnsight.orchestrator.get", fake_get)
        set_resolver(FakeDNSResolver(records={}))

        mgr = ConfigManager(
            targets=[],
            target_configs=OrderedDict(),
            default_target_config=Config(),
            default_target_checks=TargetChecks.from_enabled(["boom"]),
        )
        result = await run_domain("example.com", mgr=mgr, checks=["boom"])
        assert result.partial
        assert result.root.results["boom"].failed
        err = result.root.results["boom"].error or ""
        assert "RuntimeError" in err
        assert "intentional boom" in err

    async def test_exclude_removes_check(self) -> None:
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        rules: OrderedDict[str, TargetConfig] = OrderedDict()
        rules["*"] = TargetConfig(
            include="*", precedence=0, config=Config(), checks=None
        )
        mgr = ConfigManager(
            targets=[],
            target_configs=rules,
            default_target_config=Config(),
            default_target_checks=TargetChecks.from_enabled(["dmarc", "spf"]),
        )
        result = await run_domain("example.com", mgr=mgr, exclude=["spf"])
        assert set(result.root.results.keys()) == {"dmarc"}

    async def test_run_config_targets_empty(self) -> None:
        mgr = _mgr_dmarc_only()
        out = await run_config_targets(mgr=mgr)
        assert out == []

    async def test_run_config_targets_sequential(self) -> None:
        set_resolver(
            FakeDNSResolver(
                records={
                    "_dmarc.a.example.com/TXT": [_DMARC_TXT],
                    "_dmarc.b.example.com/TXT": [_DMARC_TXT],
                }
            )
        )
        rules: OrderedDict[str, TargetConfig] = OrderedDict()
        rules["*"] = TargetConfig(
            include="*", precedence=0, config=Config(), checks=None
        )
        mgr = ConfigManager(
            targets=[Target("a.example.com"), Target("b.example.com")],
            target_configs=rules,
            default_target_config=Config(),
            default_target_checks=TargetChecks.from_enabled(["dmarc"]),
        )
        results = await run_config_targets(mgr=mgr)
        assert len(results) == 2
        assert results[0].domain == "a.example.com"
        assert results[1].domain == "b.example.com"
        assert not results[0].partial and not results[1].partial

    async def test_run_check_for_target_matches_run_zone(self) -> None:
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        one = await run_check_for_target("dmarc", "example.com", mgr=mgr)
        full = await run_domain("example.com", mgr=mgr, checks=["dmarc"])
        assert one.status == full.root.results["dmarc"].status
        assert one.data is not None and full.root.results["dmarc"].data is not None

    async def test_run_audit_options_overrides_keyword_checks(self) -> None:
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        result = await run_domain(
            "example.com",
            mgr=mgr,
            checks=["spf"],
            options=RunAuditOptions(checks=["dmarc"]),
        )
        assert set(result.root.results.keys()) == {"dmarc"}

    async def test_recursive_depth_one_discovers_delegated_child_zone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # build_runtime() normally replaces the resolver from merged config; keep the
        # fake so NS discovery and checks see the same records.
        monkeypatch.setattr(
            "dnsight.orchestrator.apply_resolver_config", lambda _c: None
        )
        set_resolver(
            FakeDNSResolver(
                records={
                    "example.com/NS": ["delegated.example.com."],
                    "_dmarc.example.com/TXT": [_DMARC_TXT],
                    "_dmarc.delegated.example.com/TXT": [_DMARC_TXT],
                }
            )
        )
        mgr = _mgr_dmarc_only()
        result = await run_domain(
            "example.com", mgr=mgr, recursive=True, depth=1, checks=["dmarc"]
        )
        assert result.domain == "example.com"
        assert len(result.root.children) == 1
        child = result.root.children[0]
        assert child.zone == "delegated.example.com"
        assert child.parent == "example.com"
        assert child.children == []
        assert "dmarc" in child.results

    async def test_recursive_depth_zero_skips_child_zones(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "dnsight.orchestrator.apply_resolver_config", lambda _c: None
        )
        set_resolver(
            FakeDNSResolver(
                records={
                    "example.com/NS": ["delegated.example.com."],
                    "_dmarc.example.com/TXT": [_DMARC_TXT],
                    "_dmarc.delegated.example.com/TXT": [_DMARC_TXT],
                }
            )
        )
        mgr = _mgr_dmarc_only()
        result = await run_domain(
            "example.com", mgr=mgr, recursive=True, depth=0, checks=["dmarc"]
        )
        assert result.root.children == []

    async def test_recursive_depth_one_does_not_descend_into_grandchild(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With depth=1, child zones run with remaining depth 0 — no further NS walk."""
        monkeypatch.setattr(
            "dnsight.orchestrator.apply_resolver_config", lambda _c: None
        )
        set_resolver(
            FakeDNSResolver(
                records={
                    "example.com/NS": ["delegated.example.com."],
                    "delegated.example.com/NS": ["ns.child.delegated.example.com."],
                    "_dmarc.example.com/TXT": [_DMARC_TXT],
                    "_dmarc.delegated.example.com/TXT": [_DMARC_TXT],
                }
            )
        )
        mgr = _mgr_dmarc_only()
        result = await run_domain(
            "example.com", mgr=mgr, recursive=True, depth=1, checks=["dmarc"]
        )
        assert len(result.root.children) == 1
        assert result.root.children[0].zone == "delegated.example.com"
        assert result.root.children[0].children == []


class TestRunDomainStream:
    async def test_stream_non_recursive_yields_root_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "dnsight.orchestrator.apply_resolver_config", lambda _c: None
        )
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        zones: list[str] = []
        async for z in run_domain_stream(
            "example.com", mgr=mgr, recursive=False, checks=["dmarc"]
        ):
            zones.append(z.zone)
        assert zones == ["example.com"]

    async def test_stream_recursive_depth_first_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "dnsight.orchestrator.apply_resolver_config", lambda _c: None
        )
        set_resolver(
            FakeDNSResolver(
                records={
                    "example.com/NS": ["delegated.example.com."],
                    "_dmarc.example.com/TXT": [_DMARC_TXT],
                    "_dmarc.delegated.example.com/TXT": [_DMARC_TXT],
                }
            )
        )
        mgr = _mgr_dmarc_only()
        zones: list[str] = []
        async for z in run_domain_stream(
            "example.com", mgr=mgr, recursive=True, depth=1, checks=["dmarc"]
        ):
            zones.append(z.zone)
        assert zones == ["example.com", "delegated.example.com"]
