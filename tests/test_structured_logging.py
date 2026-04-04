"""Tests for CLI log level mapping and orchestrator / DNS debug logging."""

from __future__ import annotations

import logging

import pytest
from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.core.config import Config, ConfigManager, TargetChecks
from dnsight.core.config.targets import TargetConfig
from dnsight.core.types import Status
from dnsight.orchestrator import run_check_for_target, run_domain
from dnsight.utils.dns import FakeDNSResolver, set_resolver
from dnsight.utils.http import FakeHTTPClient, HTTPResponse


pytestmark = pytest.mark.registry_builtins

runner = CliRunner()

_DMARC_TXT = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"


def _mgr_dmarc_only() -> ConfigManager:
    from collections import OrderedDict

    rules: OrderedDict[str, TargetConfig] = OrderedDict()
    rules["*"] = TargetConfig(include="*", precedence=0, config=Config(), checks=None)
    return ConfigManager(
        targets=[],
        target_configs=rules,
        default_target_config=Config(),
        default_target_checks=TargetChecks.from_enabled(["dmarc"]),
    )


class TestCliConfigure:
    def test_default_sets_info(self) -> None:
        runner.invoke(app, ["dmarc", "--help"])
        assert logging.getLogger("dnsight").level == logging.INFO

    def test_quiet_sets_error(self) -> None:
        runner.invoke(app, ["--quiet", "dmarc", "--help"])
        assert logging.getLogger("dnsight").level == logging.ERROR

    def test_verbose_sets_debug(self) -> None:
        runner.invoke(app, ["--verbose", "dmarc", "--help"])
        assert logging.getLogger("dnsight").level == logging.DEBUG

    def test_quiet_wins_over_verbose(self) -> None:
        runner.invoke(app, ["--quiet", "--verbose", "dmarc", "--help"])
        assert logging.getLogger("dnsight").level == logging.ERROR


class TestOrchestratorLogging:
    @pytest.mark.asyncio
    async def test_run_domain_info_audit(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.INFO, logger="dnsight.orchestrator")
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        await run_domain("example.com", mgr=mgr)
        assert any("Running audit for example.com" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_run_check_info(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO, logger="dnsight.orchestrator")
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        await run_check_for_target("dmarc", "example.com", mgr=mgr)
        assert any(
            "Running check 'dmarc' for example.com" in r.message for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_dns_debug_query_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="dnsight.utils.dns")
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()
        await run_domain("example.com", mgr=mgr)
        # build_runtime applies ResolverConfig and replaces the resolver with
        # AsyncDNSResolver; DEBUG still records the live query path.
        assert any(
            "DNS query backend=AsyncDNSResolver" in r.message
            and "_dmarc.example.com" in r.message
            for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_fake_dns_resolver_logs_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="dnsight.utils.dns")
        fake = FakeDNSResolver(records={"example.com/TXT": ["v=spf1 -all"]})
        await fake.resolve_txt("example.com")
        assert any(
            "DNS query backend=FakeDNSResolver" in r.message for r in caplog.records
        )


class TestUtilsHttpLogging:
    @pytest.mark.asyncio
    async def test_fake_http_client_logs_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="dnsight.utils.http")
        client = FakeHTTPClient(
            responses={
                "https://example.com/": HTTPResponse(
                    status_code=200, headers={}, text=""
                )
            }
        )
        await client.get("https://example.com/")
        assert any(
            "HTTP request backend=FakeHTTPClient" in r.message for r in caplog.records
        )


class TestOrchestratorErrorLogging:
    @pytest.mark.asyncio
    async def test_check_exception_logs_error(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        caplog.set_level(logging.ERROR, logger="dnsight.orchestrator")
        set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC_TXT]}))
        mgr = _mgr_dmarc_only()

        from dnsight.checks.dmarc import DMARCCheck

        async def boom(domain: str, *, config: object | None = None) -> object:
            raise RuntimeError("boom")

        monkeypatch.setattr(DMARCCheck, "check_dmarc", staticmethod(boom))

        result = await run_check_for_target("dmarc", "example.com", mgr=mgr)
        assert result.status == Status.FAILED
        assert any(
            "Check 'dmarc' raised RuntimeError" in r.message for r in caplog.records
        )
