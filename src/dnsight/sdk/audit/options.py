"""Shared keyword options for domain audit entrypoints."""

from __future__ import annotations

from dataclasses import dataclass


__all__ = ["RunAuditOptions", "resolve_audit_params"]


@dataclass(frozen=True)
class RunAuditOptions:
    """Options shared by domain audit, stream, and manifest batch runs.

    When passed, overrides the individual ``checks`` / ``exclude`` / ``recursive`` /
    ``depth`` keyword arguments for that call.
    """

    checks: list[str] | None = None
    exclude: list[str] | None = None
    recursive: bool = False
    depth: int = 3


def resolve_audit_params(
    options: RunAuditOptions | None,
    *,
    checks: list[str] | None,
    exclude: list[str] | None,
    recursive: bool,
    depth: int,
) -> tuple[list[str] | None, list[str] | None, bool, int]:
    """Merge :class:`RunAuditOptions` with explicit kwargs (options win when set)."""
    if options is not None:
        return options.checks, options.exclude, options.recursive, options.depth
    return checks, exclude, recursive, depth
