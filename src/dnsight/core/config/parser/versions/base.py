from __future__ import annotations

from typing import Any, Protocol

from dnsight.core.config.config_manager import ConfigManager


__all__ = ["VersionParser"]


class VersionParser(Protocol):
    """Callable that parses raw config data into a ConfigManager."""

    def __call__(self, data: dict[str, Any]) -> ConfigManager: ...
