"""Public entrypoints for loading and discovering dnsight configuration files."""

from __future__ import annotations

from dnsight.core.config.parser.file import (
    config_manager_from_discovered,
    config_manager_from_file,
    config_manager_from_mapping,
    default_config_manager,
    discover_config_path,
)


__all__ = [
    "config_manager_from_discovered",
    "config_manager_from_file",
    "config_manager_from_mapping",
    "default_config_manager",
    "discover_config_path",
]
