"""CLI ``config validate``: paths, global ``--config``, YAML and config errors."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from dnsight.cli import app


runner = CliRunner()


def test_config_validate_file_argument_succeeds(tmp_path: Path) -> None:
    cfg = tmp_path / "dnsight.yaml"
    cfg.write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(
        app, ["--quiet", "config", "validate", str(cfg)], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "Config validated successfully." in result.output


def test_config_validate_uses_global_config_when_no_argument(tmp_path: Path) -> None:
    cfg = tmp_path / "dnsight.yaml"
    cfg.write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["--quiet", "--config", str(cfg), "config", "validate"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Config validated successfully." in result.output


def test_config_validate_invalid_yaml_exits_fatal(tmp_path: Path) -> None:
    cfg = tmp_path / "broken.yaml"
    cfg.write_text("version: [1, 2\n", encoding="utf-8")
    result = runner.invoke(
        app, ["config", "validate", str(cfg)], catch_exceptions=False
    )
    assert result.exit_code == 3
    assert "invalid YAML" in result.output


def test_config_validate_config_error_exits_fatal(tmp_path: Path) -> None:
    cfg = tmp_path / "dnsight.yaml"
    cfg.write_text("not_a_version_key: 1\n", encoding="utf-8")
    result = runner.invoke(
        app, ["config", "validate", str(cfg)], catch_exceptions=False
    )
    assert result.exit_code == 3
    assert "Error:" in result.output


def test_config_validate_no_config_source_exits_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No file argument, no global --config, no discovered dnsight.yaml."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["config", "validate"], catch_exceptions=False)
    assert result.exit_code == 3
    assert "no config path" in result.output


def test_config_validate_stdin_succeeds() -> None:
    result = runner.invoke(
        app,
        ["--quiet", "config", "validate", "-"],
        input="version: 1\n",
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Config validated successfully." in result.output


def test_config_validate_resolve_targets_runs_resolve(tmp_path: Path) -> None:
    cfg = tmp_path / "dnsight.yaml"
    cfg.write_text(
        "version: 1\n"
        "targets:\n"
        "  - domain: example.com\n"
        "config:\n"
        '  - include: "*"\n'
        "    checks: [dmarc]\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["--quiet", "config", "validate", str(cfg), "--resolve"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Config validated successfully." in result.output
