from typer.testing import CliRunner

from dnsight.cli import app


runner = CliRunner()


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "dnsight" in result.output


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "dnsight" in result.output


def test_dmarc_help():
    result = runner.invoke(app, ["dmarc", "--help"])
    assert result.exit_code == 0
    assert "dmarc" in result.output.lower()
