"""CLI argument helpers."""

from __future__ import annotations


__all__ = ["parse_csv_option"]


def parse_csv_option(value: str | None) -> list[str] | None:
    """Split a comma-separated option into non-empty strings, or ``None``.

    Use for ``--checks`` / ``--exclude`` style options: ``None`` or blank means
    “do not override” (SDK uses config / defaults).
    """
    if value is None or not value.strip():
        return None
    return [part.strip() for part in value.split(",") if part.strip()]
