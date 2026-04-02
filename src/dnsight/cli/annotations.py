"""Reusable Typer shapes for shared CLI parameters.

Factories build ``typer.Argument`` / ``typer.Option`` values; type aliases wrap them
in :class:`typing.Annotated` for command signatures. Check- and generate-specific
parameters stay on their commands.
"""

from __future__ import annotations

from dnsight.cli.helpers import (
    ConfigSourceArg,
    DepthOpt,
    DomainsArg,
    RecursiveOpt,
    ResolveTargetsOpt,
    config_source_argument,
    depth_option,
    domains_argument,
    recursive_option,
    resolve_targets_option,
)


__all__ = [
    "ConfigSourceArg",
    "DepthOpt",
    "DomainsArg",
    "RecursiveOpt",
    "ResolveTargetsOpt",
    "config_source_argument",
    "depth_option",
    "domains_argument",
    "recursive_option",
    "resolve_targets_option",
]
