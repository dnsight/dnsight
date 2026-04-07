"""Duck-typed summaries of check ``data`` for human-facing serialisers.

Uses :class:`collections.abc.Mapping` and :func:`getattr` only so this package
stays independent of ``checks/``. Typical keys/attributes: ``raw_record``,
``flattened`` (lookup/IP view), ``suggested_record``.
"""

from __future__ import annotations

from collections.abc import Mapping


__all__ = ["data_summary_lines"]

_RECORD_MAX = 240
_SUGGESTED_MAX = 240
_MECH_MAX_LINE = 400
_IP_LIST_CAP = 20


def _get_field(obj: object, name: str) -> object | None:
    if isinstance(obj, Mapping):
        val = obj.get(name)
        return val
    return getattr(obj, name, None)


def _truncate_one_line(text: str, max_len: int) -> str:
    single = " ".join(text.splitlines())
    if len(single) <= max_len:
        return single
    return f"{single[: max_len - 1]}…"


def _format_str_list(items: list[object], *, cap: int, label: str) -> list[str]:
    strs = [str(x) for x in items if isinstance(x, str) and x.strip()]
    if not strs:
        return []
    out: list[str] = []
    shown = strs[:cap]
    for s in shown:
        out.append(f"  {label}: {s}")
    extra = len(strs) - len(shown)
    if extra > 0:
        out.append(f"  … +{extra} more {label}")
    return out


def data_summary_lines(  # NOSONAR S3776
    data: object | None,
    *,
    record_max: int = _RECORD_MAX,
    suggested_max: int = _SUGGESTED_MAX,
    flatten_detail: bool = False,
) -> list[str]:
    """Return short lines describing *data* when it looks like SPF/DMARC-style models.

    Args:
        data: Check result payload; may be ``None``.
        record_max: Max length for record line body.
        suggested_max: Max length for suggested line body.
        flatten_detail: If true, expand ``flattened`` with mechanisms and IP lists
            (capped); SPF-only callers should set this from CLI ``--flatten``.

    Returns:
        Zero or more lines (no leading/trailing empties).
    """
    if data is None:
        return []
    lines: list[str] = []

    raw = _get_field(data, "raw_record")
    if isinstance(raw, str) and raw.strip():
        lines.append(f"Record: {_truncate_one_line(raw, record_max)}")

    flat = _get_field(data, "flattened")
    if flat is not None:
        n_lookups = _get_field(flat, "effective_lookup_count")
        if isinstance(n_lookups, int):
            ip4 = _get_field(flat, "ip4_ranges")
            ip6 = _get_field(flat, "ip6_ranges")
            n_ip = 0
            if isinstance(ip4, list):
                n_ip += len(ip4)
            if isinstance(ip6, list):
                n_ip += len(ip6)
            lines.append(f"Flattened: {n_lookups} lookups, {n_ip} IP ranges")
            if flatten_detail:
                mechs = _get_field(flat, "resolved_mechanisms")
                if isinstance(mechs, list) and mechs:
                    joined = ", ".join(str(m) for m in mechs if m is not None)
                    lines.append(
                        f"Resolved mechanisms: {_truncate_one_line(joined, _MECH_MAX_LINE)}"
                    )
                if isinstance(ip4, list) and ip4:
                    lines.extend(
                        _format_str_list(list(ip4), cap=_IP_LIST_CAP, label="ip4")
                    )
                if isinstance(ip6, list) and ip6:
                    lines.extend(
                        _format_str_list(list(ip6), cap=_IP_LIST_CAP, label="ip6")
                    )

    suggested = _get_field(data, "suggested_record")
    if isinstance(suggested, str) and suggested.strip():
        lines.append(f"Suggested: {_truncate_one_line(suggested, suggested_max)}")

    return lines
