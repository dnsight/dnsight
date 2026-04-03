"""Tests for CLI documentation generator (option tables, nav helpers)."""

from __future__ import annotations

import json
import runpy
import sys
from unittest.mock import patch

import pytest
from typer.main import get_command

from dnsight.cli.main import app
from tools.docgen.generate import _format_param_row, _root_index_sections, main
from tools.docgen.hooks import on_config


def test_main_writes_cli_index(tmp_path, monkeypatch) -> None:
    """Smoke: docgen runs and writes root index under a temp docs tree."""
    import tools.docgen.generate as g

    cli_root = tmp_path / "cli"
    monkeypatch.setattr(g, "DOCS_CLI", cli_root)
    monkeypatch.setattr(g, "GENERATED_NAV_PATH", cli_root / "_generated_nav.json")
    main()
    index = cli_root / "index.md"
    assert index.is_file()
    text = index.read_text(encoding="utf-8")
    assert "AUTO-GENERATED" in text
    assert "Command index" in text
    assert (cli_root / "_generated_nav.json").is_file()


def test_dual_flag_row_lists_no_variant_and_unset_default() -> None:
    root = get_command(app)
    caa = root.commands["caa"]
    param = next(p for p in caa.params if p.name == "require_caa")
    row = _format_param_row(param)
    assert "`--require-caa`" in row
    assert "`--no-require-caa`" in row
    # Default column: no CLI default (None); we do not document YAML defaults here.
    parts = [c.strip() for c in row.strip("|").split("|")]
    assert parts[2] == "—"


def test_dual_flag_row_shows_false_default() -> None:
    root = get_command(app)
    caa = root.commands["caa"]
    gen = caa.commands["generate"]
    param = next(p for p in gen.params if p.name == "emit_issuewild")
    row = _format_param_row(param)
    assert "`--emit-issuewild`" in row
    assert "`--no-emit-issuewild`" in row
    assert "`false`" in row


def test_single_flag_row_shows_short_option() -> None:
    root = get_command(app)
    param = next(p for p in root.params if p.name == "quiet")
    row = _format_param_row(param)
    assert "`--quiet`" in row
    assert "-q`" in row
    assert "`false`" in row


def test_root_index_sections_grouping() -> None:
    root = get_command(app)
    body = "".join(_root_index_sections(root))
    assert "General" in body
    assert "version/index.md" in body
    assert "docs/index.md" in body
    assert "Audit" in body
    assert "Checks" in body
    assert "dmarc/index.md" in body


def test_mkdocs_nav_hook_merges_generated_cli_nav(tmp_path) -> None:
    docs = tmp_path / "docs"
    cli = docs / "cli"
    cli.mkdir(parents=True)
    fragment = [{"Overview": "cli/index.md"}, {"version": "cli/version/index.md"}]
    (cli / "_generated_nav.json").write_text(json.dumps(fragment), encoding="utf-8")
    config = {"docs_dir": str(docs), "nav": [{"Home": "index.md"}, {"CLI": []}]}
    out = on_config(config)
    assert out["nav"][1]["CLI"] == fragment


def test_mkdocs_nav_hook_missing_fragment_raises(tmp_path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    config = {"docs_dir": str(docs), "nav": [{"CLI": []}]}
    with pytest.raises(FileNotFoundError, match=r"_generated_nav\.json"):
        on_config(config)


def test_mkdocs_nav_hook_requires_cli_nav_slot(tmp_path) -> None:
    docs = tmp_path / "docs"
    cli = docs / "cli"
    cli.mkdir(parents=True)
    (cli / "_generated_nav.json").write_text("[]", encoding="utf-8")
    config = {"docs_dir": str(docs), "nav": [{"Home": "index.md"}]}
    with pytest.raises(RuntimeError, match="CLI"):
        on_config(config)


def test_docgen_main_module_invokes_generate_main() -> None:
    """PEP 338 ``python -m tools.docgen`` entry calls :func:`tools.docgen.generate.main`."""
    with patch("tools.docgen.generate.main") as mock_main:
        sys.modules.pop("tools.docgen.__main__", None)
        runpy.run_module("tools.docgen.__main__", run_name="__main__")
    mock_main.assert_called_once()
