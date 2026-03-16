"""I/O utilities for dnsight checks.

Provides singleton DNS resolver and HTTP client with get/set/reset API.
Checks import ``get_resolver()`` and ``get_http_client()`` from this
package; tests inject fakes via ``set_resolver`` / ``set_http_client``.
"""

from __future__ import annotations

from dnsight.utils.dns import (
    AsyncDNSResolver,
    DNSResolver,
    FakeDNSResolver,
    get_resolver,
    reset_resolver,
    set_resolver,
)
from dnsight.utils.http import (
    AsyncHTTPClient,
    FakeHTTPClient,
    HTTPClient,
    HTTPResponse,
    get_http_client,
    reset_http_client,
    set_http_client,
)


__all__ = [
    "AsyncDNSResolver",
    "AsyncHTTPClient",
    "DNSResolver",
    "FakeDNSResolver",
    "FakeHTTPClient",
    "HTTPClient",
    "HTTPResponse",
    "get_http_client",
    "get_resolver",
    "reset_http_client",
    "reset_resolver",
    "set_http_client",
    "set_resolver",
]
