"""Tests for utils/http singleton, AsyncHTTPClient, HTTPResponse, and FakeHTTPClient."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from pydantic import ValidationError
import pytest

from dnsight.core.exceptions import CheckError
from dnsight.utils.http import (
    AsyncHTTPClient,
    FakeHTTPClient,
    HTTPResponse,
    get_http_client,
    reset_http_client,
    set_http_client,
)


class TestHTTPResponse:
    def test_construction(self) -> None:
        resp = HTTPResponse(
            status_code=200, headers={"content-type": "text/html"}, text="ok"
        )
        assert resp.status_code == 200
        assert resp.headers == {"content-type": "text/html"}
        assert resp.text == "ok"

    def test_frozen(self) -> None:
        resp = HTTPResponse(status_code=200, headers={}, text="")
        with pytest.raises(ValidationError):
            resp.status_code = 404  # type: ignore[misc]


class TestSingleton:
    def test_get_creates_async_client(self) -> None:
        client = get_http_client()
        assert isinstance(client, AsyncHTTPClient)

    def test_get_returns_same_instance(self) -> None:
        a = get_http_client()
        b = get_http_client()
        assert a is b

    def test_set_overrides(self) -> None:
        fake = FakeHTTPClient()
        set_http_client(fake)
        assert get_http_client() is fake

    def test_reset_clears(self) -> None:
        fake = FakeHTTPClient()
        set_http_client(fake)
        reset_http_client()
        client = get_http_client()
        assert isinstance(client, AsyncHTTPClient)
        assert client is not fake


class TestFakeHTTPClient:
    def _response(self, status: int = 200, text: str = "ok") -> HTTPResponse:
        return HTTPResponse(status_code=status, headers={}, text=text)

    async def test_get_returns_configured(self) -> None:
        resp = self._response(200, "hello")
        fake = FakeHTTPClient({"https://example.com": resp})
        result = await fake.get("https://example.com")
        assert result.status_code == 200
        assert result.text == "hello"

    async def test_head_returns_configured(self) -> None:
        resp = self._response(301, "")
        fake = FakeHTTPClient({"https://example.com": resp})
        result = await fake.head("https://example.com")
        assert result.status_code == 301

    async def test_get_unknown_url_raises(self) -> None:
        fake = FakeHTTPClient()
        with pytest.raises(CheckError, match="no configured response"):
            await fake.get("https://missing.example.com")

    async def test_head_unknown_url_raises(self) -> None:
        fake = FakeHTTPClient()
        with pytest.raises(CheckError, match="no configured response"):
            await fake.head("https://missing.example.com")

    async def test_multiple_urls(self) -> None:
        fake = FakeHTTPClient(
            {
                "https://a.com": self._response(200, "A"),
                "https://b.com": self._response(404, "Not found"),
            }
        )
        a = await fake.get("https://a.com")
        b = await fake.get("https://b.com")
        assert a.text == "A"
        assert b.status_code == 404


# -- AsyncHTTPClient tests ---------------------------------------------------


def _mock_httpx_response(
    status_code: int = 200, headers: dict[str, str] | None = None, text: str = "ok"
) -> SimpleNamespace:
    return SimpleNamespace(
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
        text=text,
    )


class TestAsyncHTTPClient:
    def test_constructor_creates_client(self) -> None:
        client = AsyncHTTPClient()
        assert isinstance(client._client, httpx.AsyncClient)

    def test_constructor_custom_timeout(self) -> None:
        client = AsyncHTTPClient(timeout=5.0)
        assert isinstance(client._client, httpx.AsyncClient)

    async def test_get_success(self) -> None:
        client = AsyncHTTPClient()
        mock_response = _mock_httpx_response(200, text="hello")
        with patch.object(
            client._client, "request", new=AsyncMock(return_value=mock_response)
        ):
            result = await client.get("https://example.com")
        assert result.status_code == 200
        assert result.text == "hello"

    async def test_head_success(self) -> None:
        client = AsyncHTTPClient()
        mock_response = _mock_httpx_response(200, text="")
        with patch.object(
            client._client, "request", new=AsyncMock(return_value=mock_response)
        ):
            result = await client.head("https://example.com")
        assert result.status_code == 200

    async def test_request_http_error(self) -> None:
        client = AsyncHTTPClient()
        with (
            patch.object(
                client._client,
                "request",
                new=AsyncMock(side_effect=httpx.HTTPError("connection failed")),
            ),
            pytest.raises(CheckError, match="HTTP GET request failed"),
        ):
            await client.get("https://fail.example.com")

    async def test_request_returns_http_response_model(self) -> None:
        client = AsyncHTTPClient()
        mock_response = _mock_httpx_response(
            404, headers={"x-custom": "value"}, text="not found"
        )
        with patch.object(
            client._client, "request", new=AsyncMock(return_value=mock_response)
        ):
            result = await client.get("https://example.com/missing")
        assert isinstance(result, HTTPResponse)
        assert result.status_code == 404
        assert result.headers == {"x-custom": "value"}
        assert result.text == "not found"
