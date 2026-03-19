"""Targets, check rules, and resolved config types for the config system.

``TargetChecks`` stores enabled check names as a ``frozenset[str]`` so
that adding a new check never requires touching this module. The registry
(``core/registry.py``) is the single source of truth for valid check
names; config just stores strings.

Loaders should use ``parse_checks()`` when building ``TargetConfig``
from YAML.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from dnsight.core.config.blocks import Config


__all__ = [
    "ChecksDelta",
    "ChecksReplace",
    "ChecksUpdate",
    "Target",
    "TargetConfig",
    "TargetChecks",
    "ResolvedTargetConfig",
    "parse_checks",
]


@dataclass(frozen=True)
class ChecksReplace:
    """Enable exactly these checks; all others disabled."""

    enabled: tuple[str, ...]


@dataclass(frozen=True)
class ChecksDelta:
    """Add/remove checks from current set."""

    add: frozenset[str] | None = None
    remove: frozenset[str] | None = None


ChecksUpdate = ChecksReplace | ChecksDelta


def parse_checks(raw: str | list[str] | None) -> ChecksUpdate | None:
    """Parse raw YAML checks (list or +/- string) into a ChecksUpdate.

    Returns None for None or empty string. List -> replace (exactly those checks).
    Non-empty string -> delta (comma-separated +name or -name).
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, list):
        return ChecksReplace(enabled=tuple(raw))
    add: set[str] = set()
    remove: set[str] = set()
    for part in raw.split(","):
        name = part.strip().lstrip("+-").strip()
        if not name:
            continue
        if part.strip().startswith("-"):
            remove.add(name)
        else:
            add.add(name)
    if not add and not remove:
        return None
    return ChecksDelta(
        add=frozenset(add) if add else None,
        remove=frozenset(remove) if remove else None,
    )


@dataclass(frozen=True)
class Target:
    """Target domain and path."""

    domain: str
    path: str = "/"


@dataclass(frozen=True)
class TargetConfig:
    """Per-target config: pattern match gives config object.

    Merged in precedence order during resolve (checks use ChecksUpdate:
    replace or delta).
    """

    include: str
    precedence: int
    config: Config
    exclude: list[str] | None = None
    checks: ChecksUpdate | None = None


@dataclass(frozen=True)
class TargetChecks:
    """Set of enabled check names for a target.

    Stores names as a ``frozenset[str]`` so the config layer is
    decoupled from the set of available checks. The registry validates
    names at runtime; this class just tracks the requested set.
    """

    enabled: frozenset[str] = frozenset()

    def enabled_names(self) -> list[str]:
        """Return the sorted list of enabled check names."""
        return sorted(self.enabled)

    def is_enabled(self, check_name: str) -> bool:
        """True if the given check is enabled."""
        return check_name in self.enabled

    @classmethod
    def from_enabled(cls, names: Iterable[str]) -> TargetChecks:
        """Build TargetChecks with exactly the given check names enabled.

        Args:
            names: Check name strings (e.g. ``["dmarc", "spf"]``).

        Returns:
            A new ``TargetChecks`` with those names enabled.
        """
        return cls(enabled=frozenset(names))

    def apply_delta(
        self,
        add: frozenset[str] | set[str] | None = None,
        remove: frozenset[str] | set[str] | None = None,
    ) -> TargetChecks:
        """Return a new TargetChecks with *add* enabled and *remove* disabled."""
        result = set(self.enabled)
        result |= add or set()
        result -= remove or set()
        return TargetChecks(enabled=frozenset(result))

    def merge(self, other: TargetChecks) -> TargetChecks:
        """Return a new TargetChecks combining both enabled sets."""
        return TargetChecks(enabled=self.enabled | other.enabled)


@dataclass(frozen=True)
class ResolvedTargetConfig:
    """Resolved target config based on pattern match and checks to run."""

    checks: TargetChecks
    config: Config
