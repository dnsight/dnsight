"""CLI manifest resolution: fatal errors when domains omitted and config is unusable."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from dnsight.cli import app


runner = CliRunner()

pytestmark = pytest.mark.registry_builtins


def test_dmarc_manifest_mode_fails_without_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No domains and no discoverable dnsight.yaml → fatal exit (code 3).

    Discovery walks parents of CWD; without a patch, a repo-root ``dnsight.yaml``
    would be found from any temp dir. ``dmarc`` uses ``no_args_is_help=True``,
    so pass a real option so the callback runs instead of printing subcommand help.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "dnsight.cli.commands._check_base.discover_config_path", lambda start=None: None
    )
    result = runner.invoke(app, ["dmarc", "--policy", "none"], catch_exceptions=False)
    assert result.exit_code == 3
    assert "no domains given" in result.stderr.lower()
    assert "config file" in result.stderr.lower()


def test_dmarc_manifest_mode_fails_when_config_has_no_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Config exists but ``targets`` is empty → fatal exit (code 3)."""
    cfg = tmp_path / "dnsight.yaml"
    cfg.write_text(
        'version: 1\ntargets: []\nconfig:\n  - include: "*"\n    checks: [dmarc]\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app, ["--config", str(cfg), "dmarc", "--policy", "none"], catch_exceptions=False
    )
    assert result.exit_code == 3
    assert "no domains given" in result.stderr.lower()
    assert "targets" in result.stderr.lower()
