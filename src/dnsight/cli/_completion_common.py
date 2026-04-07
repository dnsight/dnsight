"""Shared shell-completion helpers for Typer/Click (generic only).

Per-command completers live next to their commands; this module holds CSV token
splitting, prefix filtering, and config discovery paths.
"""

from __future__ import annotations

from collections.abc import Iterable

import typer

from dnsight.core.config.parser.file import iter_existing_config_paths
from dnsight.core.types import OutputFormat


__all__ = [
    "complete_config_discovery_paths",
    "complete_output_format",
    "complete_with_csv_suffix",
    "current_csv_token",
    "prefix_choices",
]


def current_csv_token(incomplete: str | None) -> str:
    """Return the segment after the last comma (strip outer whitespace on that segment)."""
    return (incomplete or "").split(",")[-1].strip()


def prefix_choices(incomplete: str | None, choices: Iterable[str]) -> list[str]:
    """Return *choices* that case-insensitively prefix-match *incomplete*."""
    needle = (incomplete or "").strip().lower()
    return sorted(c for c in choices if c.lower().startswith(needle))


def complete_with_csv_suffix(
    incomplete: str | None, choices: Iterable[str]
) -> list[str]:
    """Prefix-match the current CSV token and prepend prior comma-separated prefix."""
    raw = incomplete or ""
    if "," in raw:
        prefix, _sep, token = raw.rpartition(",")
        lead = prefix + ","
        token_stripped = token.strip()
    else:
        lead = ""
        token_stripped = raw.strip()
    matched = prefix_choices(token_stripped, choices)
    return sorted({lead + m for m in matched})


def complete_config_discovery_paths(
    ctx: typer.Context, incomplete: str | None
) -> list[str]:
    """Suggest discovered ``dnsight.yaml`` / ``dnsight.yml`` paths for path-like options."""
    _ = ctx
    needle = (incomplete or "").strip().lower()
    paths = iter_existing_config_paths()
    out = [str(p) for p in paths if str(p).lower().startswith(needle)]
    return sorted(set(out))


def complete_output_format(ctx: typer.Context, incomplete: str | None) -> list[str]:
    """Suggest :class:`OutputFormat` values (case-insensitive prefix)."""
    _ = ctx
    return prefix_choices(incomplete or "", (m.value for m in OutputFormat))
