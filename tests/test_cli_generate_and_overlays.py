"""Exercise per-check CLI overlays and ``generate`` subcommands (user-facing paths)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.utils.dns import FakeDNSResolver, set_resolver
from dnsight.utils.http import FakeHTTPClient, HTTPResponse, set_http_client


runner = CliRunner()

pytestmark = pytest.mark.registry_builtins

_DMARC = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"


def test_dmarc_check_with_overlay_and_generate_subcommand() -> None:
    set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC]}))
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "dmarc",
            "--policy",
            "none",
            "--no-rua-required",
            "example.com",
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}
    gen = runner.invoke(
        app,
        ["dmarc", "generate", "--policy", "reject", "--rua", "mailto:x@y.com"],
        catch_exceptions=False,
    )
    assert gen.exit_code == 0
    assert "v=DMARC1" in gen.stdout
    assert "reject" in gen.stdout.lower() or "p=" in gen.stdout


def test_headers_check_overlay_and_generate_hsts_csp() -> None:
    set_http_client(
        FakeHTTPClient(
            {
                "https://example.com": HTTPResponse(
                    status_code=200,
                    headers={
                        "strict-transport-security": "max-age=1",
                        "content-security-policy": "default-src 'self'",
                        "x-frame-options": "DENY",
                    },
                    text="",
                )
            }
        )
    )
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "headers",
            "--require",
            "HSTS,CSP",
            "--strict-recommendations",
            "example.com",
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}
    hsts = runner.invoke(
        app,
        ["headers", "generate", "hsts", "--max-age", "3600", "--no-include-subdomains"],
        catch_exceptions=False,
    )
    assert hsts.exit_code == 0
    assert "max-age" in hsts.stdout.lower()
    src = json.dumps({"default-src": ["'self'"]})
    csp = runner.invoke(
        app,
        ["headers", "generate", "csp", "--sources-json", src],
        catch_exceptions=False,
    )
    assert csp.exit_code == 0
    assert (
        "content-security-policy" in csp.stdout.lower() or "default-src" in csp.stdout
    )


def test_headers_generate_csp_invalid_json_exits_3() -> None:
    bad = runner.invoke(
        app,
        ["headers", "generate", "csp", "--sources-json", "not-json"],
        catch_exceptions=False,
    )
    assert bad.exit_code == 3
    assert "json" in bad.stderr.lower()


def test_mx_overlay_and_generate() -> None:
    set_resolver(FakeDNSResolver({"example.com/MX": [(10, "mail.example.com")]}))
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "mx",
            "--no-check-ptr",
            "--starttls-timeout-seconds",
            "1",
            "example.com",
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}
    gen = runner.invoke(
        app,
        ["mx", "generate", "--mx", "10:mail.example.com,20:mx2.example.com"],
        catch_exceptions=False,
    )
    assert gen.exit_code == 0
    assert "mail.example.com" in gen.stdout


def test_mx_generate_invalid_rows_exits_3() -> None:
    bad = runner.invoke(
        app, ["mx", "generate", "--mx", "not-a-valid-row"], catch_exceptions=False
    )
    assert bad.exit_code == 3


def test_spf_overlay_flatten_and_generate() -> None:
    set_resolver(FakeDNSResolver(records={"example.com/TXT": ["v=spf1 -all"]}))
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "spf",
            "--allow-redirect",
            "--flatten",
            "--required-disposition",
            "-all",
            "example.com",
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}
    gen = runner.invoke(
        app,
        ["spf", "generate", "--include", "_spf.example.com", "--disposition", "-all"],
        catch_exceptions=False,
    )
    assert gen.exit_code == 0
    assert "v=spf1" in gen.stdout


def test_caa_overlay_and_generate() -> None:
    z = "example.com"
    rec = {f"{z}/CAA": [(0, "issue", "letsencrypt.org")], f"www.{z}/CAA": []}
    set_resolver(FakeDNSResolver(records=rec))
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "caa",
            "--require-caa",
            "--required-issuers",
            "letsencrypt.org",
            "--max-names",
            "5",
            z,
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}
    gen = runner.invoke(
        app,
        ["caa", "generate", "--issuers", "letsencrypt.org", "--emit-issuewild"],
        catch_exceptions=False,
    )
    assert gen.exit_code == 0
    assert "letsencrypt" in gen.stdout.lower() or "issue" in gen.stdout.lower()


def test_dnssec_overlay_flags() -> None:
    set_resolver(FakeDNSResolver({}))
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "dnssec",
            "--no-require-ds",
            "--signature-expiry-days-warning",
            "7",
            "--disallowed-algorithms",
            "1,5",
            "--validate-negative-responses",
            "--nxdomain-probe-label",
            "nxtest",
            "--require-ns",
            "example.com",
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}


def test_dkim_overlay_flags() -> None:
    set_resolver(FakeDNSResolver({}))
    r = runner.invoke(
        app,
        [
            "--quiet",
            "-f",
            "json",
            "dkim",
            "--selectors",
            "google,default",
            "--min-key-bits",
            "1024",
            "--disallowed-algorithms",
            "sha1",
            "example.com",
        ],
        catch_exceptions=False,
    )
    assert r.exit_code in {0, 1, 2}
