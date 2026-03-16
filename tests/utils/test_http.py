"""Tests for utils/http singleton, AsyncHTTPClient, HTTPResponse, and FakeHTTPClient."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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
    def test_constructor_defaults(self) -> None:
        client = AsyncHTTPClient()
        assert client._timeout == 10.0
        assert client._user_agent == "dnsight/0.1"
        assert client._follow_redirects is True

    def test_constructor_custom(self) -> None:
        client = AsyncHTTPClient(
            timeout=5.0, user_agent="test/1.0", follow_redirects=False
        )
        assert client._timeout == 5.0
        assert client._user_agent == "test/1.0"
        assert client._follow_redirects is False

    async def test_get_success(self) -> None:
        client = AsyncHTTPClient()
        mock_response = _mock_httpx_response(200, text="hello")

        mock_client_instance = MagicMock()
        mock_client_instance.request = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "dnsight.utils.http.httpx.AsyncClient", return_value=mock_client_instance
        ):
            result = await client.get("https://example.com")

        assert result.status_code == 200
        assert result.text == "hello"
        mock_client_instance.request.assert_awaited_once_with(
            "GET", "https://example.com"
        )

    async def test_head_success(self) -> None:
        client = AsyncHTTPClient()
        mock_response = _mock_httpx_response(200, text="")

        mock_client_instance = MagicMock()
        mock_client_instance.request = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "dnsight.utils.http.httpx.AsyncClient", return_value=mock_client_instance
        ):
            result = await client.head("https://example.com")

        assert result.status_code == 200
        mock_client_instance.request.assert_awaited_once_with(
            "HEAD", "https://example.com"
        )

    async def test_request_http_error(self) -> None:
        client = AsyncHTTPClient()

        mock_client_instance = MagicMock()
        mock_client_instance.request = AsyncMock(
            side_effect=httpx.HTTPError("connection failed")
        )
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(
                "dnsight.utils.http.httpx.AsyncClient",
                return_value=mock_client_instance,
            ),
            pytest.raises(CheckError, match="HTTP GET request failed"),
        ):
            await client.get("https://fail.example.com")

    async def test_request_returns_http_response_model(self) -> None:
        client = AsyncHTTPClient()
        mock_response = _mock_httpx_response(
            404, headers={"x-custom": "value"}, text="not found"
        )

        mock_client_instance = MagicMock()
        mock_client_instance.request = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "dnsight.utils.http.httpx.AsyncClient", return_value=mock_client_instance
        ):
            result = await client.get("https://example.com/missing")

        assert isinstance(result, HTTPResponse)
        assert result.status_code == 404
        assert result.headers == {"x-custom": "value"}
        assert result.text == "not found"
