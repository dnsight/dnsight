from typer.testing import CliRunner

from dnsight.cli import app
from dnsight.cli.urls import DOCUMENTATION_SITE_URL


runner = CliRunner()


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "dnsight" in result.output


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "dnsight" in result.output


def test_docs_prints_documentation_url():
    result = runner.invoke(app, ["docs"])
    assert result.exit_code == 0
    assert result.output.strip() == DOCUMENTATION_SITE_URL


def test_dmarc_help():
    result = runner.invoke(app, ["dmarc", "--help"])
    assert result.exit_code == 0
    assert "dmarc" in result.output.lower()
