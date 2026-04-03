"""MkDocs hooks: merge generated CLI nav into ``mkdocs.yml`` ``nav``.

Referenced from the repo-root ``mkdocs.yml`` ``hooks:`` list. The nav fragment
is produced by :mod:`tools.docgen.generate` as ``docs/cli/_generated_nav.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def on_config(config: Any, **kwargs: Any) -> Any:
    """Replace the ``CLI`` nav entry with ``docs/cli/_generated_nav.json`` contents."""
    docs_dir = Path(config["docs_dir"])
    path = docs_dir / "cli" / "_generated_nav.json"
    if not path.is_file():
        msg = (
            "Missing docs/cli/_generated_nav.json. Run `just docs-generate` from the "
            "repository root."
        )
        raise FileNotFoundError(msg)
    cli_nav: list[Any] = json.loads(path.read_text(encoding="utf-8"))
    nav: list[Any] = config["nav"]
    for item in nav:
        if isinstance(item, dict) and "CLI" in item:
            item["CLI"] = cli_nav
            break
    else:
        msg = (
            "mkdocs.yml nav must include a top-level `CLI` entry for the docgen nav hook "
            "(tools/docgen/hooks.py)."
        )
        raise RuntimeError(msg)
    return config
