"""I/O utilities for dnsight checks.

Provides singleton DNS resolver, HTTP client, and STARTTLS probe with
get/set/reset API. Checks call the getters; tests inject fakes.
"""

from __future__ import annotations

from dnsight.utils.dns import (
    AsyncDNSResolver,
    DNSKEYDict,
    DNSResolver,
    DnssecQueryResult,
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
from dnsight.utils.smtp import (
    AsyncStartTLSProbe,
    FakeStartTLSProbe,
    StartTLSOutcome,
    StartTLSProbe,
    StartTLSProbeResult,
    get_starttls_probe,
    reset_starttls_probe,
    set_starttls_probe,
)


__all__ = [
    "AsyncDNSResolver",
    "AsyncHTTPClient",
    "AsyncStartTLSProbe",
    "DNSKEYDict",
    "DNSResolver",
    "DnssecQueryResult",
    "FakeDNSResolver",
    "FakeHTTPClient",
    "FakeStartTLSProbe",
    "HTTPClient",
    "HTTPResponse",
    "StartTLSOutcome",
    "StartTLSProbe",
    "StartTLSProbeResult",
    "get_http_client",
    "get_resolver",
    "get_starttls_probe",
    "reset_http_client",
    "reset_resolver",
    "reset_starttls_probe",
    "set_http_client",
    "set_resolver",
    "set_starttls_probe",
]
