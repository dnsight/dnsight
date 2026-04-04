"""Singleton async HTTP client for dnsight checks.

Module-level singleton with ``get_http_client()`` / ``set_http_client()``
/ ``reset_http_client()``.  Checks that need HTTP (e.g. security headers,
MTA-STS) call ``get_http_client()`` inside their ``_get`` / ``_check``
methods; tests call ``set_http_client(FakeHTTPClient(...))`` to avoid
real network I/O.

The ``AsyncHTTPClient`` wraps :mod:`httpx` and raises ``CheckError`` on
request failures so checks receive a uniform exception type.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ConfigDict

from dnsight.core.exceptions import CheckError
from dnsight.version import __version__


__all__ = [
    "AsyncHTTPClient",
    "FakeHTTPClient",
    "HTTPClient",
    "HTTPResponse",
    "get_http_client",
    "reset_http_client",
    "set_http_client",
]


class HTTPResponse(BaseModel):
    """Lightweight HTTP response returned by the client wrapper.

    Attributes:
        status_code: HTTP status code (e.g. 200, 301, 404).
        headers: Response headers as a flat dict (last value wins for
            duplicate header names).
        text: Decoded response body.
    """

    model_config = ConfigDict(frozen=True)

    status_code: int
    headers: dict[str, str]
    text: str


@runtime_checkable
class HTTPClient(Protocol):
    """Protocol that all HTTP client implementations must satisfy.

    Checks depend on this protocol, not on a concrete class, so custom
    clients (e.g. caching, logging, or mock backends) can be swapped
    in via ``set_http_client()``.
    """

    async def get(self, url: str, **kwargs: Any) -> HTTPResponse: ...
    async def head(self, url: str, **kwargs: Any) -> HTTPResponse: ...


_client: HTTPClient | None = None


def get_http_client() -> HTTPClient:
    """Return the current module-level HTTP client, creating one if needed.

    Returns:
        The active HTTP client instance.
    """
    global _client  # noqa: PLW0603
    if _client is None:
        _client = AsyncHTTPClient()
    return _client


def set_http_client(client: HTTPClient) -> None:
    """Replace the module-level HTTP client (primarily for testing).

    Args:
        client: Any object satisfying the ``HTTPClient`` protocol.
    """
    global _client  # noqa: PLW0603
    _client = client


def reset_http_client() -> None:
    """Reset the module-level HTTP client to ``None``.

    The next call to ``get_http_client()`` will create a fresh
    ``AsyncHTTPClient``.
    """
    global _client  # noqa: PLW0603
    _client = None


_DEFAULT_TIMEOUT = 10.0
_DEFAULT_USER_AGENT = f"dnsight/{__version__}"


class AsyncHTTPClient:
    """Async HTTP client wrapping :mod:`httpx`.

    Provides ``get`` and ``head`` methods that return an ``HTTPResponse``
    and translate transport/protocol errors into ``CheckError``.

    Args:
        timeout: Request timeout in seconds.
        user_agent: ``User-Agent`` header value.
        follow_redirects: Whether to follow redirects.
    """

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        user_agent: str = _DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
    ) -> None:
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers={"User-Agent": user_agent},
        )

    async def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send an HTTP GET request.

        Args:
            url: The URL to request.
            **kwargs: Extra keyword arguments forwarded to
                :meth:`httpx.AsyncClient.get`.

        Returns:
            An ``HTTPResponse`` with status, headers, and body.

        Raises:
            CheckError: On transport or protocol errors.
        """
        return await self._request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send an HTTP HEAD request.

        Args:
            url: The URL to request.
            **kwargs: Extra keyword arguments forwarded to
                :meth:`httpx.AsyncClient.head`.

        Returns:
            An ``HTTPResponse`` with status and headers (body is empty).

        Raises:
            CheckError: On transport or protocol errors.
        """
        return await self._request("HEAD", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> HTTPResponse:
        """Execute an HTTP request and wrap the response.

        Args:
            method: HTTP method (``"GET"``, ``"HEAD"``, etc.).
            url: The URL to request.
            **kwargs: Extra keyword arguments forwarded to httpx.

        Returns:
            An ``HTTPResponse``.

        Raises:
            CheckError: On transport or protocol errors.
        """
        try:
            response = await self._client.request(method, url, **kwargs)
            return HTTPResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
            )
        except httpx.HTTPError as exc:
            raise CheckError(f"HTTP {method} request failed for {url}: {exc}") from exc


class FakeHTTPClient:
    """Test double returning pre-configured HTTP responses.

    Responses are keyed by URL. If a URL is not found, ``CheckError``
    is raised, matching real client behaviour.

    Args:
        responses: Mapping of URL to ``HTTPResponse`` instances.
    """

    def __init__(self, responses: dict[str, HTTPResponse] | None = None) -> None:
        self._responses: dict[str, HTTPResponse] = responses or {}

    def _get_response(self, url: str) -> HTTPResponse:
        if url not in self._responses:
            raise CheckError(f"no configured response for {url}")
        return self._responses[url]

    async def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Return pre-configured response for *url* or raise ``CheckError``."""
        return self._get_response(url)

    async def head(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Return pre-configured response for *url* or raise ``CheckError``."""
        return self._get_response(url)
