"""Registry for dnsight checks.

Module-level singleton: checks self-register with ``@register`` at import
time. The orchestrator and CLI query the registry by name or capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dnsight.core.exceptions import CheckNotFoundError
from dnsight.core.types import Capability


__all__ = ["CheckDefinition", "all_checks", "get_check_def", "register", "supporting"]

# Registry is internal; cls is intentionally type[Any] so core/ does not depend on checks/.
_CHECKS: dict[str, CheckDefinition] = {}


@dataclass(frozen=True)
class CheckDefinition:
    """Metadata about a registered check."""

    name: str
    cls: type[Any]
    capabilities: frozenset[Capability]


def register(cls: type[Any]) -> type[Any]:
    """Register a check class. Use as a decorator on the check class.

    The class must have ``name`` and ``capabilities`` class variables.

    Args:
        cls: The check class to register.

    Returns:
        The same class, unmodified.
    """
    if cls.name in _CHECKS:
        raise RuntimeError(f"Check {cls.name!r} is already registered")
    _CHECKS[cls.name] = CheckDefinition(
        name=cls.name, cls=cls, capabilities=cls.capabilities
    )
    return cls


def get_check_def(name: str) -> CheckDefinition:
    """Look up a check by name.

    Args:
        name: The check name (e.g. ``"dmarc"``).

    Raises:
        CheckNotFoundError: If no check is registered with that name.
    """
    if name not in _CHECKS:
        raise CheckNotFoundError(name)
    return _CHECKS[name]


def all_checks() -> list[CheckDefinition]:
    """Return all registered check definitions."""
    return list(_CHECKS.values())


def supporting(capability: Capability) -> list[CheckDefinition]:
    """Return check definitions that support the given capability.

    Args:
        capability: The capability to filter by (e.g. ``Capability.GENERATE``).
    """
    return [d for d in _CHECKS.values() if capability in d.capabilities]
