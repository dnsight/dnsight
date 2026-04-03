"""CLI smoke and help contracts (global options, stable subcommand names)."""

from __future__ import annotations

from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.cli.urls import DOCUMENTATION_SITE_URL


runner = CliRunner()


def test_help_lists_global_options_and_audit_subcommand() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    out = result.output
    assert "dnsight" in out
    assert "--config" in out
    assert "--format" in out or "-f" in out
    assert "--quiet" in out or "-q" in out
    assert "audit" in out
    # Typer/Rich may wrap; assert distinctive phrases from cli/main _APP_HELP.
    assert "SPF, DKIM, DMARC" in out
    assert "audit command" in out
    assert "dnsight COMMAND" in out and "--help" in out


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "dnsight" in result.output


def test_docs_prints_documentation_url():
    result = runner.invoke(app, ["docs"])
    assert result.exit_code == 0
    assert result.output.strip() == DOCUMENTATION_SITE_URL


def test_dmarc_help_lists_check_options() -> None:
    result = runner.invoke(app, ["dmarc", "--help"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "dmarc" in out
    assert "--config" in out
    assert "--policy" in out or "policy" in out
