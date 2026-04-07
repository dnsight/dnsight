"""Config package: targets, pattern rules, mergeable blocks, and resolution."""

from typing import TypeAlias

from dnsight.core.config.blocks import (
    CaaConfig,
    Config,
    DkimConfig,
    DmarcConfig,
    DnssecConfig,
    HeadersConfig,
    MxConfig,
    ResolverConfig,
    SpfConfig,
    ThrottleConfig,
)
from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.mergeable import MergeableConfig
from dnsight.core.config.parser import (
    config_manager_from_discovered,
    config_manager_from_file,
    config_manager_from_mapping,
    default_config_manager,
    discover_config_path,
    iter_existing_config_paths,
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


ResolvedConfig: TypeAlias = ResolvedTargetConfig  # NOSONAR S6794
"""Alias so runtime and orchestrator import a stable name."""


__all__ = [
    "CaaConfig",
    "ChecksDelta",
    "ChecksReplace",
    "ChecksUpdate",
    "Config",
    "ConfigManager",
    "DkimConfig",
    "DmarcConfig",
    "DnssecConfig",
    "HeadersConfig",
    "MxConfig",
    "SpfConfig",
    "config_manager_from_discovered",
    "config_manager_from_file",
    "config_manager_from_mapping",
    "default_config_manager",
    "discover_config_path",
    "iter_existing_config_paths",
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
