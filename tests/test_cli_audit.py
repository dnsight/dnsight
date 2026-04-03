"""CLI ``audit``: manifest mode, global ``--config`` with explicit domains, JSON shape."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.utils.dns import FakeDNSResolver, set_resolver


runner = CliRunner()

pytestmark = pytest.mark.registry_builtins

_DMARC = "v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com; adkim=r; aspf=r"


def _manifest_yaml(path: Path) -> None:
    path.write_text(
        "version: 1\n"
        "targets:\n"
        "  - domain: example.com\n"
        "config:\n"
        '  - include: "*"\n'
        "    checks: [dmarc]\n"
        "    dmarc:\n"
        "      rua_required: false\n",
        encoding="utf-8",
    )


def test_audit_manifest_runs_only_configured_checks(tmp_path: Path) -> None:
    cfg = tmp_path / "dnsight.yaml"
    _manifest_yaml(cfg)
    set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC]}))
    result = runner.invoke(
        app,
        ["--quiet", "--config", str(cfg), "-f", "json", "audit"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output.strip())
    checks = doc["domains"][0]["zones"][0]["results"].keys()
    assert set(checks) == {"dmarc"}


def test_audit_explicit_domains_honour_global_config_path(tmp_path: Path) -> None:
    """Regression: ``--config`` must apply to ``audit <domain>``, not only manifest mode."""
    cfg = tmp_path / "dnsight.yaml"
    cfg.write_text(
        "version: 1\n"
        "targets: []\n"
        "config:\n"
        '  - include: "*"\n'
        "    checks: [dmarc]\n"
        "    dmarc:\n"
        "      rua_required: false\n",
        encoding="utf-8",
    )
    set_resolver(FakeDNSResolver(records={"_dmarc.example.com/TXT": [_DMARC]}))
    result = runner.invoke(
        app,
        ["--quiet", "--config", str(cfg), "-f", "json", "audit", "example.com"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output.strip())
    checks = doc["domains"][0]["zones"][0]["results"].keys()
    assert set(checks) == {"dmarc"}
