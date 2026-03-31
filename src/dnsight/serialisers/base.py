"""Serialiser protocol and shared file output."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from dnsight.core.models import DomainResult


__all__ = ["SerialiserProtocol", "write_serialiser"]


class SerialiserProtocol(Protocol):
    """Object that returns a :class:`~dnsight.core.models.DomainResult` as a string."""

    def serialise(self, result: DomainResult) -> str:
        """Return the full formatted output for *result*."""
        ...


def write_serialiser(
    serialiser: SerialiserProtocol, result: DomainResult, path: Path | str
) -> None:
    """Write *serialiser* output to *path* using an atomic replace.
    Writes to a sibling ``*.tmp`` file (preserving the original suffix when
    present, e.g. ``report.json`` → ``report.json.tmp``) then replaces *path*
    so readers never see a half-written file on the same filesystem.
    Args:
        serialiser: Implementation that produces the output string.
        result: Audit result to serialise.
        path: Destination path.
    """
    dest = Path(path)
    suffix = dest.suffix
    tmp_suffix = f"{suffix or ''}.tmp"
    tmp = dest.with_suffix(tmp_suffix)
    content = serialiser.serialise(result)
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    tmp.replace(dest)
