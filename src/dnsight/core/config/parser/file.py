from __future__ import annotations

from pathlib import Path

from yaml import safe_load

from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.parser.versions import VERSION_PARSERS
from dnsight.core.exceptions import ConfigError


_ALLOWED_SUFFIXES = frozenset({".yaml", ".yml"})


def config_manager_from_file(path: Path | str) -> ConfigManager:
    resolved = Path(path).resolve(strict=True)
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
    config = VERSION_PARSERS[version](data)
    # Check if config has "*" rule with no exclude
    return config
