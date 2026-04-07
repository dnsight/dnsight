"""Capped key/value preview for arbitrary check ``data`` (human serialisers only)."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel


__all__ = ["generic_data_preview_lines"]

_MAX_KEYS = 14
_MAX_VAL_LEN = 96


def generic_data_preview_lines(
    data: object | None, *, max_keys: int = _MAX_KEYS, max_val_len: int = _MAX_VAL_LEN
) -> list[str]:
    """Return short ``key: value`` lines when *data* is a model or mapping.

    Nested structures are summarised, not expanded.
    """
    if data is None:
        return []
    raw: dict[str, object]
    if isinstance(data, BaseModel):
        raw = data.model_dump(mode="python", exclude_none=True)
    elif isinstance(data, Mapping):
        raw = {str(k): v for k, v in data.items()}
    else:
        return []

    lines: list[str] = []
    for key in sorted(raw.keys())[:max_keys]:
        val = raw[key]
        if isinstance(val, BaseModel):
            rendered = f"<{type(val).__name__}>"
        elif isinstance(val, Mapping):
            rendered = f"{{{len(val)} keys}}"
        elif isinstance(val, list):
            rendered = f"[{len(val)} items]"
        else:
            s = str(val).replace("\n", " ").strip()
            if len(s) > max_val_len:
                s = f"{s[: max_val_len - 1]}…"
            rendered = s
        lines.append(f"{key}: {rendered}")
    extra = len(raw) - min(len(raw), max_keys)
    if extra > 0:
        lines.append(f"… +{extra} more keys")
    return lines
