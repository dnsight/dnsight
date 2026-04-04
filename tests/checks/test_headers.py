"""Tests for the HTTP headers check — fake HTTP client only."""

from __future__ import annotations

import importlib

import pytest

import dnsight.checks  # noqa: F401 — registers checks
import dnsight.checks.headers
from dnsight.checks.headers import (
    CspGenerateParams,
    GenerateKind,
    HeadersCheck,
    HeadersIssueId,
    HstsGenerateParams,
    check_headers,
    generate_headers,
    get_headers,
)
from dnsight.core.config.blocks import HeadersConfig
from dnsight.core.models import GeneratedRecord
from dnsight.core.registry import get
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.http import FakeHTTPClient, HTTPResponse, set_http_client


class TestHeadersRegistry:
    def test_headers_registered(self) -> None:
        importlib.reload(dnsight.checks.headers)
        d = get("headers")
        assert d.name == "headers"
        assert Capability.CHECK in d.capabilities
        assert Capability.GENERATE in d.capabilities


class TestHeadersCheckClass:
    def test_name_and_capabilities(self) -> None:
        assert HeadersCheck.name == "headers"
        assert Capability.CHECK in HeadersCheck.capabilities
        assert Capability.GENERATE in HeadersCheck.capabilities


def _ok_headers() -> dict[str, str]:
    return {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
    }


@pytest.mark.asyncio
async def test_check_headers_pass() -> None:
    set_http_client(
        FakeHTTPClient(
            {
                "https://example.com": HTTPResponse(
                    status_code=200, headers=_ok_headers(), text=""
                )
            }
        )
    )
    cfg = HeadersConfig(require=["HSTS", "CSP", "X-Frame-Options"])
    r = await check_headers("example.com", config=cfg)
    assert r.status == Status.COMPLETED
    assert r.data is not None
    assert r.data.url == "https://example.com"
    assert r.data.fetch_error is None
    assert not r.issues


@pytest.mark.asyncio
async def test_check_headers_missing_csp() -> None:
    h = _ok_headers()
    del h["content-security-policy"]
    set_http_client(
        FakeHTTPClient(
            {"https://example.com": HTTPResponse(status_code=200, headers=h, text="")}
        )
    )
    cfg = HeadersConfig(require=["CSP"])
    r = await check_headers("example.com", config=cfg)
    assert r.status == Status.COMPLETED
    assert any(i.id == HeadersIssueId.CSP_MISSING for i in r.issues)


@pytest.mark.asyncio
async def test_check_headers_fetch_failed() -> None:
    set_http_client(FakeHTTPClient({}))
    cfg = HeadersConfig(require=["CSP"])
    r = await check_headers("example.com", config=cfg)
    assert r.status == Status.COMPLETED
    assert r.data is not None
    assert r.data.fetch_error
    assert any(i.id == HeadersIssueId.FETCH_FAILED for i in r.issues)


@pytest.mark.asyncio
async def test_check_headers_hsts_not_secure() -> None:
    set_http_client(
        FakeHTTPClient(
            {
                "https://example.com": HTTPResponse(
                    status_code=200,
                    headers={"strict-transport-security": "max-age=0"},
                    text="",
                )
            }
        )
    )
    cfg = HeadersConfig(require=["HSTS"])
    r = await check_headers("example.com", config=cfg)
    assert any(i.id == HeadersIssueId.HSTS_NOT_SECURE for i in r.issues)


@pytest.mark.asyncio
async def test_get_headers_returns_data() -> None:
    set_http_client(
        FakeHTTPClient(
            {
                "https://example.com": HTTPResponse(
                    status_code=200, headers=_ok_headers(), text=""
                )
            }
        )
    )
    cfg = HeadersConfig(require=["HSTS"])
    d = await get_headers("example.com", config=cfg)
    assert d.url == "https://example.com"
    assert not d.fetch_error


def test_generate_csp() -> None:
    rec = generate_headers(
        params=CspGenerateParams(
            sources={"default-src": ["'self'"], "script-src": ["'self'"]}
        )
    )
    assert isinstance(rec, GeneratedRecord)
    assert rec.record_type == RecordType.HTTP_HEADER
    assert rec.host == ""
    assert rec.value.startswith("Content-Security-Policy:")
    assert "'self'" in rec.value


def test_generate_hsts() -> None:
    rec = generate_headers(
        params=HstsGenerateParams(
            max_age=31536000, include_subdomains=True, preload=False
        )
    )
    assert isinstance(rec, GeneratedRecord)
    assert rec.record_type == RecordType.HTTP_HEADER
    assert "Strict-Transport-Security:" in rec.value
    assert "max-age=31536000" in rec.value
    assert "includeSubDomains" in rec.value


def test_generate_kind_enum() -> None:
    assert GenerateKind.CSP.value == "csp"
    assert GenerateKind.HSTS.value == "hsts"
