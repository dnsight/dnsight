"""Tests for config_manager_from_file."""

from __future__ import annotations

from pathlib import Path

import pytest

from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.parser.file import config_manager_from_file
from dnsight.core.exceptions import ConfigError


@pytest.fixture()
def config_dir(tmp_path: Path) -> Path:
    return tmp_path


def _write_yaml(directory: Path, name: str, content: str) -> Path:
    p = directory / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Suffix validation
# ---------------------------------------------------------------------------


class TestSuffixValidation:
    def test_yaml_suffix_accepted(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", "version: 1\n")
        mgr = config_manager_from_file(p)
        assert isinstance(mgr, ConfigManager)

    def test_yml_suffix_accepted(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yml", "version: 1\n")
        mgr = config_manager_from_file(p)
        assert isinstance(mgr, ConfigManager)

    def test_json_suffix_rejected(self, config_dir: Path) -> None:
        p = config_dir / "c.json"
        p.write_text('{"version": 1}', encoding="utf-8")
        with pytest.raises(ConfigError, match="YAML"):
            config_manager_from_file(p)

    def test_no_suffix_rejected(self, config_dir: Path) -> None:
        p = config_dir / "config"
        p.write_text("version: 1\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="YAML"):
            config_manager_from_file(p)


# ---------------------------------------------------------------------------
# File not found
# ---------------------------------------------------------------------------


class TestFileNotFound:
    def test_missing_file_raises(self, config_dir: Path) -> None:
        with pytest.raises(FileNotFoundError):
            config_manager_from_file(config_dir / "nope.yaml")


# ---------------------------------------------------------------------------
# Version validation
# ---------------------------------------------------------------------------


class TestVersionValidation:
    def test_missing_version_key(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", "resolver:\n  provider: system\n")
        with pytest.raises(ConfigError, match="version"):
            config_manager_from_file(p)

    def test_non_dict_yaml(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", "- one\n- two\n")
        with pytest.raises(ConfigError, match="version"):
            config_manager_from_file(p)

    def test_null_version(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", "version: null\n")
        with pytest.raises(ConfigError, match="Invalid version"):
            config_manager_from_file(p)

    def test_string_version_coerced(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", 'version: "1"\n')
        mgr = config_manager_from_file(p)
        assert isinstance(mgr, ConfigManager)

    def test_unknown_version(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", "version: 999\n")
        with pytest.raises(ConfigError, match="Unknown config version"):
            config_manager_from_file(p)


# ---------------------------------------------------------------------------
# Happy path — round-trip with v1 example
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_round_trip(self, config_dir: Path) -> None:
        content = (
            "version: 1\n"
            "targets:\n"
            "  - domain: example.com\n"
            "config:\n"
            '  - include: "*"\n'
            "    checks: [dmarc]\n"
            "    dmarc:\n"
            "      required_policy: reject\n"
        )
        p = _write_yaml(config_dir, "dnsight.yaml", content)
        mgr = config_manager_from_file(p)
        assert mgr.targets[0].domain == "example.com"
        assert mgr.default_target_config.dmarc.policy == "reject"
        assert mgr.default_target_checks.is_enabled("dmarc")

    def test_accepts_string_path(self, config_dir: Path) -> None:
        p = _write_yaml(config_dir, "c.yaml", "version: 1\n")
        mgr = config_manager_from_file(str(p))
        assert isinstance(mgr, ConfigManager)
