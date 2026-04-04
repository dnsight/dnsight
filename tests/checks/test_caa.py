"""Tests for CAA check — discovery, validation, generate, crt.sh."""

from __future__ import annotations

import importlib
import json
from urllib.parse import quote

import pytest

import dnsight.checks  # noqa: F401 — registers checks
from dnsight.checks.caa import (
    CAACheck,
    CaaGenerateParams,
    CaaIssueId,
    CaaRecommendationId,
    check_caa,
    generate_caa,
    get_caa,
)
from dnsight.core.config.blocks import CaaConfig, Config
from dnsight.core.registry import get
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.dns import FakeDNSResolver, reset_resolver, set_resolver
from dnsight.utils.http import FakeHTTPClient, HTTPResponse, set_http_client


@pytest.fixture(autouse=True)
def _reset_dns_resolver() -> None:
    yield
    reset_resolver()


class TestCAARegistry:
    def test_caa_registered(self) -> None:
        import dnsight.checks.caa

        importlib.reload(dnsight.checks.caa)
        d = get("caa")
        assert d.name == "caa"
        assert Capability.CHECK in d.capabilities
        assert Capability.GENERATE in d.capabilities


class TestCAACheckClass:
    def test_name_and_capabilities(self) -> None:
        assert CAACheck.name == "caa"
        assert Capability.GENERATE in CAACheck.capabilities


def _base_empty_caa(zone: str = "example.com") -> dict[str, list]:
    """Minimal empty CAA chain for apex + www."""
    return {f"{zone}/CAA": [], f"www.{zone}/CAA": []}


@pytest.mark.asyncio
class TestCAAValidation:
    async def test_required_issuer_missing(self) -> None:
        z = "example.com"
        records = _base_empty_caa(z)
        records[f"{z}/CAA"] = [(0, "issue", "digicert.com")]
        records[f"www.{z}/CAA"] = []
        set_resolver(FakeDNSResolver(records))
        cfg = CaaConfig(required_issuers=["letsencrypt.org"])
        result = await check_caa(z, config=cfg)
        assert result.status == Status.COMPLETED
        ids = [i.id for i in result.issues]
        assert CaaIssueId.ISSUER_MISSING.value in ids

    async def test_required_issuer_present(self) -> None:
        z = "example.com"
        records = _base_empty_caa(z)
        records[f"{z}/CAA"] = [(0, "issue", "letsencrypt.org")]
        records[f"www.{z}/CAA"] = []
        set_resolver(FakeDNSResolver(records))
        cfg = CaaConfig(required_issuers=["letsencrypt.org"])
        result = await check_caa(z, config=cfg)
        assert result.status == Status.COMPLETED
        assert CaaIssueId.ISSUER_MISSING.value not in [i.id for i in result.issues]

    async def test_issuewild_permissive(self) -> None:
        z = "example.com"
        records = _base_empty_caa(z)
        records[f"{z}/CAA"] = [
            (0, "issue", "letsencrypt.org"),
            (0, "issuewild", "digicert.com"),
        ]
        records[f"www.{z}/CAA"] = []
        set_resolver(FakeDNSResolver(records))
        cfg = CaaConfig(check_issuewild=True)
        result = await check_caa(z, config=cfg)
        assert CaaIssueId.ISSUEWILD_PERMISSIVE.value in [i.id for i in result.issues]

    async def test_enumeration_limit_issue(self) -> None:
        z = "example.com"
        records = {
            f"{z}/CAA": [],
            f"www.{z}/CAA": [],
            f"www.{z}/CNAME": ["cdn.example.com"],
            f"cdn.{z}/CAA": [],
            f"cdn.{z}/CNAME": ["alt.example.com"],
            f"alt.{z}/CAA": [],
        }
        set_resolver(FakeDNSResolver(records))
        cfg = CaaConfig(enumerate_names=True, max_names=3, include_www=True)
        result = await check_caa(z, config=cfg)
        assert CaaIssueId.ENUMERATION_LIMIT_REACHED.value in [
            i.id for i in result.issues
        ]
        assert result.data is not None
        assert result.data.enumeration_truncated is True

    async def test_get_caa_inventory(self) -> None:
        z = "example.com"
        records = _base_empty_caa(z)
        set_resolver(FakeDNSResolver(records))
        data = await get_caa(z, config=CaaConfig())
        assert data.zone_apex == z
        assert len(data.names_checked) >= 1


@pytest.mark.asyncio
class TestCAAGenerate:
    async def test_generate_caa_lines(self) -> None:
        rec = generate_caa(
            params=CaaGenerateParams(
                issuers=["letsencrypt.org"],
                emit_issuewild=True,
                iodef_mailto="ops@example.com",
            )
        )
        assert rec.record_type == RecordType.CAA
        assert rec.host == "@"
        assert '0 issue "letsencrypt.org"' in rec.value
        assert '0 issuewild "letsencrypt.org"' in rec.value
        assert "iodef" in rec.value.lower()
        assert "mailto:ops@example.com" in rec.value

    async def test_from_config(self) -> None:
        cfg = CaaConfig(
            required_issuers=["ca.example"],
            check_issuewild=False,
            reporting_email="a@b.com",
        )
        p = CaaGenerateParams.from_config(cfg)
        rec = generate_caa(params=p)
        assert '0 issue "ca.example"' in rec.value
        assert "issuewild" not in rec.value.lower()


@pytest.mark.asyncio
class TestCAACrtSh:
    async def test_crt_sh_violation(self) -> None:
        z = "example.com"
        records = {f"{z}/CAA": [(0, "issue", "letsencrypt.org")], f"www.{z}/CAA": []}
        set_resolver(FakeDNSResolver(records))
        q = quote("%." + z)
        url = f"https://crt.sh/?q={q}&output=json"
        payload = json.dumps([{"name_value": f"www.{z}", "issuer_name": "O=Evil CA"}])
        set_http_client(
            FakeHTTPClient(
                {url: HTTPResponse(status_code=200, headers={}, text=payload)}
            )
        )
        cfg = CaaConfig(cross_reference_crt_sh=True)
        result = await check_caa(z, config=cfg)
        assert CaaIssueId.CRT_SH_VIOLATION.value in [i.id for i in result.issues]


@pytest.mark.asyncio
class TestCAAFailure:
    async def test_dns_failure_fails_check(self) -> None:
        set_resolver(FakeDNSResolver({}))
        result = await check_caa("example.com", config=CaaConfig())
        assert result.status == Status.FAILED
        assert result.error is not None

    async def test_strict_recommendations(self) -> None:
        z = "example.com"
        records = _base_empty_caa(z)
        records[f"{z}/CAA"] = [(0, "iodef", "mailto:x@y.com")]
        records[f"www.{z}/CAA"] = []
        set_resolver(FakeDNSResolver(records))
        root = Config(caa=CaaConfig(), strict_recommendations=True)
        result = await check_caa(z, config=root)
        rec_ids = [r.id for r in result.recommendations]
        assert CaaRecommendationId.ADD_ISSUE.value in rec_ids
