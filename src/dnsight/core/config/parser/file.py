from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any

from yaml import safe_load

from dnsight.core.config.blocks import Config
from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.parser.versions import VERSION_PARSERS
from dnsight.core.config.targets import TargetChecks
from dnsight.core.exceptions import ConfigError
from dnsight.core.registry import all_checks


__all__ = [
    "config_manager_from_discovered",
    "config_manager_from_file",
    "config_manager_from_mapping",
    "default_config_manager",
    "discover_config_path",
]

_ALLOWED_SUFFIXES = frozenset({".yaml", ".yml"})
_CONFIG_FILE_NAMES = ("dnsight.yaml", "dnsight.yml")


def discover_config_path(start: Path | None = None) -> Path | None:
    """Search upward from *start* (or CWD) for a config file.

    Looks for ``dnsight.yaml`` then ``dnsight.yml`` in each directory,
    starting at *start* and then each parent directory.

    Args:
        start: Directory to begin from; defaults to :func:`Path.cwd`.

    Returns:
        Path to the first matching file, or ``None`` if none exist.
    """
    cur = (start or Path.cwd()).resolve()
    for search_dir in (cur, *cur.parents):
        for name in _CONFIG_FILE_NAMES:
            candidate = search_dir / name
            if candidate.is_file():
                return candidate
    return None


def default_config_manager() -> ConfigManager:
    """Build a manager with merged defaults and every registered check enabled.

    Use when no config file is found. Loads ``dnsight.checks`` so
    ``@register`` runs, then enables all names from :func:`all_checks`.
    ``config_schema_version`` stays ``0`` (no YAML file).
    """
    # Register checks at runtime
    import dnsight.checks  # noqa: F401

    enabled = frozenset(d.name for d in all_checks())
    return ConfigManager(
        targets=[],
        target_configs=OrderedDict(),
        default_target_config=Config(),
        default_target_checks=TargetChecks(enabled=enabled),
    )


def config_manager_from_discovered(start: Path | None = None) -> ConfigManager:
    """Load YAML from the first discovered file, or fall back to defaults.

    Args:
        start: Directory to begin discovery from; defaults to :func:`Path.cwd`.

    Returns:
        A :class:`ConfigManager` from disk, or from :func:`default_config_manager`.
    """
    path = discover_config_path(start)
    if path is None:
        return default_config_manager()
    return config_manager_from_file(path)


def config_manager_from_file(path: Path | str) -> ConfigManager:
    """Load and parse a YAML config file into a :class:`ConfigManager`."""
    try:
        resolved = Path(path).resolve(strict=True)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    if resolved.suffix not in _ALLOWED_SUFFIXES:
        raise ConfigError(
            f"Config file must be YAML ({', '.join(sorted(_ALLOWED_SUFFIXES))}), "
            f"got: {resolved.suffix!r}"
        )
    data = safe_load(resolved.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "version" not in data:
        raise ConfigError("Config file must contain a 'version' key")
    try:
        version = int(data["version"])
    except (TypeError, ValueError):
        raise ConfigError(f"Invalid version: {data['version']!r}") from None
    if version not in VERSION_PARSERS:
        raise ConfigError(f"Unknown config version: {version}")
    return VERSION_PARSERS[version](data)


def config_manager_from_mapping(data: Any) -> ConfigManager:
    """Build a :class:`ConfigManager` from a decoded YAML mapping.
    Same validation and version dispatch as :func:`config_manager_from_file`, for
    stdin or in-memory documents after :func:`yaml.safe_load`.
    """
    if not isinstance(data, dict) or "version" not in data:
        raise ConfigError("Config must be a mapping with a 'version' key")
    try:
        version = int(data["version"])
    except (TypeError, ValueError):
        raise ConfigError(f"Invalid version: {data['version']!r}") from None
    if version not in VERSION_PARSERS:
        raise ConfigError(f"Unknown config version: {version}")
    return VERSION_PARSERS[version](data)
