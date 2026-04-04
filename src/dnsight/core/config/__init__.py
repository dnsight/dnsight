"""Config package: targets, pattern rules, mergeable blocks, and resolution."""

from typing import TypeAlias

from dnsight.core.config.blocks import (
    Config,
    DmarcConfig,
    ResolverConfig,
    ThrottleConfig,
)
from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.mergeable import MergeableConfig
from dnsight.core.config.parser import (
    config_manager_from_discovered,
    config_manager_from_file,
    default_config_manager,
    discover_config_path,
)
from dnsight.core.config.pattern import Pattern
from dnsight.core.config.targets import (
    ChecksDelta,
    ChecksReplace,
    ChecksUpdate,
    ResolvedTargetConfig,
    Target,
    TargetChecks,
    TargetConfig,
    parse_checks,
)


ResolvedConfig: TypeAlias = ResolvedTargetConfig
"""Alias so runtime and orchestrator import a stable name."""


__all__ = [
    "ChecksDelta",
    "ChecksReplace",
    "ChecksUpdate",
    "Config",
    "ConfigManager",
    "DmarcConfig",
    "config_manager_from_discovered",
    "config_manager_from_file",
    "default_config_manager",
    "discover_config_path",
    "MergeableConfig",
    "ResolverConfig",
    "Pattern",
    "ResolvedConfig",
    "ResolvedTargetConfig",
    "Target",
    "TargetConfig",
    "TargetChecks",
    "ThrottleConfig",
    "parse_checks",
]
