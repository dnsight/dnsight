"""Audit command helpers and config error path."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.cli.commands import audit as audit_mod


pytestmark = pytest.mark.registry_builtins


def test_registered_check_names_includes_core_checks() -> None:
    names = audit_mod._registered_check_names()
    assert "dmarc" in names
    assert "spf" in names
    assert names == tuple(sorted(names))


def test_complete_audit_checks_returns_filtered() -> None:
    out = audit_mod._complete_audit_checks(MagicMock(), "dma")
    assert any("dmarc" in x for x in out)


def test_complete_audit_exclude_delegates() -> None:
    out = audit_mod._complete_audit_exclude(MagicMock(), "spf")
    assert any("spf" in x for x in out)


def test_audit_config_error_exits_fatal(tmp_path: Path) -> None:
    bad = tmp_path / "dnsight.yaml"
    # Valid YAML that fails version dispatch → :class:`ConfigError`, not scanner errors.
    bad.write_text("version: 999\n", encoding="utf-8")
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["--config", str(bad), "-f", "json", "audit", "example.com"],
        catch_exceptions=False,
    )
    assert r.exit_code == 3
    assert "error" in r.stderr.lower() or r.stderr
