"""Reusable Typer shapes for shared CLI parameters.

This package is the stable import surface for cross-command ``Annotated`` aliases
(see ``cli/helpers.py`` for implementations). **Convention:** all CLI options and
arguments use ``Annotated[T, typer.Option(...)]`` or ``Annotated[..., typer.Argument(...)]``
with the Python default on ``=``; check-specific options stay defined in
``cli/commands/`` (often as local ``TypeAlias`` names when reused within a file).
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
