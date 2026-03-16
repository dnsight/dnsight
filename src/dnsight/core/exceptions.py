"""Core exceptions for dnsight."""

from __future__ import annotations


__all__ = [
    "CapabilityError",
    "CheckError",
    "CheckNotFoundError",
    "ConfigError",
    "ConfigValidationError",
    "DNSightError",
]


class DNSightError(Exception):
    """Base for all dnsight errors. Catch this for generic error handling."""


class CheckError(DNSightError):
    """Raised when a check cannot complete (e.g. DNS failure, HTTP error, parsing error)."""


class ConfigError(DNSightError):
    """Base for config loading, migration, and validation errors."""


class ConfigValidationError(ConfigError):
    """Config file failed schema or semantic validation."""


class CheckNotFoundError(DNSightError):
    """Registry has no check with the given name."""


class CapabilityError(DNSightError):
    """A check was asked to perform an action it does not support.

    Args:
        check_name: Name of the check (e.g. ``"caa"``).
        capability: The capability that was requested (e.g. ``Capability.GENERATE`` or its string value).
    """

    def __init__(self, check_name: str, capability: str) -> None:
        self.check_name = check_name
        self.capability = capability
        super().__init__(
            f"Check {check_name!r} does not support capability {capability!r}"
        )
