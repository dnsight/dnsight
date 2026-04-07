"""Invoke each per-check CLI group with fakes so command modules execute run paths."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.utils.dns import FakeDNSResolver, set_resolver
from dnsight.utils.http import FakeHTTPClient, HTTPResponse, set_http_client


runner = CliRunner()

pytestmark = pytest.mark.registry_builtins


def _caa_empty_apex() -> dict[str, list]:
    z = "example.com"
    return {f"{z}/CAA": [], f"www.{z}/CAA": []}


def _headers_ok() -> None:
    set_http_client(
        FakeHTTPClient(
            {
                "https://example.com": HTTPResponse(
                    status_code=200,
                    headers={
                        "strict-transport-security": "max-age=31536000",
                        "content-security-policy": "default-src 'self'",
                        "x-frame-options": "DENY",
                    },
                    text="",
                )
            }
        )
    )


@pytest.mark.parametrize(
    ("argv_tail", "setup"),
    [
        (
            ["spf", "--lookup-limit", "5", "example.com"],
            lambda: set_resolver(FakeDNSResolver({"example.com/TXT": ["v=spf1 -all"]})),
        ),
        (
            ["mx", "example.com"],
            lambda: set_resolver(
                FakeDNSResolver({"example.com/MX": [(10, "mail.example.com")]})
            ),
        ),
        (
            ["caa", "--no-require-caa", "example.com"],
            lambda: set_resolver(FakeDNSResolver(_caa_empty_apex())),
        ),
        (["dkim", "example.com"], lambda: set_resolver(FakeDNSResolver({}))),
        (["dnssec", "example.com"], lambda: set_resolver(FakeDNSResolver({}))),
        (["headers", "example.com"], _headers_ok),
    ],
    ids=["spf", "mx", "caa", "dkim", "dnssec", "headers"],
)
def test_per_check_cli_json_quiet_exits_zero_or_audit_code(
    argv_tail: list[str], setup: Callable[[], None]
) -> None:
    setup()
    result = runner.invoke(
        app, ["--quiet", "-f", "json", *argv_tail], catch_exceptions=False
    )
    assert result.exit_code in {0, 1, 2}
