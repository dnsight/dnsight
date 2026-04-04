"""Tests for :func:`dnsight.core.config.parser.file.iter_existing_config_paths`."""

from __future__ import annotations

from pathlib import Path

import pytest

from dnsight.core.config.parser.file import iter_existing_config_paths


def test_iter_existing_config_paths_finds_yaml_upward(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    sub = root / "a" / "b"
    sub.mkdir(parents=True)
    cfg = root / "dnsight.yaml"
    cfg.write_text("version: 1\n", encoding="utf-8")
    monkeypatch.chdir(sub)
    found = iter_existing_config_paths()
    assert found == [cfg.resolve()]


def test_iter_existing_config_paths_both_names_same_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    d = tmp_path / "w"
    d.mkdir()
    (d / "dnsight.yaml").write_text("version: 1\n", encoding="utf-8")
    (d / "dnsight.yml").write_text("version: 1\n", encoding="utf-8")
    monkeypatch.chdir(d)
    found = iter_existing_config_paths()
    assert len(found) == 2
    assert {p.name for p in found} == {"dnsight.yaml", "dnsight.yml"}


def test_iter_existing_config_paths_respects_max_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "r"
    sub = root / "x"
    sub.mkdir(parents=True)
    (root / "dnsight.yaml").write_text("version: 1\n", encoding="utf-8")
    monkeypatch.chdir(sub)
    assert iter_existing_config_paths(max_directories=1) == []
