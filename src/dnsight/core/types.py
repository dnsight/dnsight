"""Core enums for dnsight."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, StrEnum
from types import NotImplementedType
from typing import Self, cast


__all__ = [
    "Capability",
    "DNSProvider",
    "IssueId",
    "OutputFormat",
    "RecommendationId",
    "RecordType",
    "Severity",
    "Status",
    "IssueDescriptor",
    "RecommendationDescriptor",
]


class IssueId(StrEnum):
    """Base for per-check issue ID enums. Subclass in each check and add members."""


class RecommendationId(StrEnum):
    """Base for per-check recommendation ID enums. Subclass in each check and add members."""


class RankedEnum(str, Enum):  # noqa: UP042 - custom __new__ with rank; StrEnum doesn't support tuple values
    """Base for ranked enums."""

    __slots__ = ("_rank",)

    def __new__(cls, value: str, rank: int) -> Self:
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj._rank = rank
        return obj

    def _assert_same_type(self, other: Self) -> None:
        if not isinstance(other, type(self)):
            raise TypeError(f"Cannot compare {type(self)} with {type(other)}")

    def __lt__(self, other: Self) -> bool:
        self._assert_same_type(other)
        return self._rank < other._rank

    def __le__(self, other: Self) -> bool:
        self._assert_same_type(other)
        return self._rank <= other._rank

    def __gt__(self, other: Self) -> bool:
        self._assert_same_type(other)
        return self._rank > other._rank

    def __ge__(self, other: Self) -> bool:
        self._assert_same_type(other)
        return self._rank >= other._rank

    def __eq__(self, other: object) -> bool | NotImplementedType:
        if type(other) is not type(self):
            if isinstance(other, str):
                return self.value == other
            return NotImplemented
        same: Self = cast(Self, other)
        return self._rank == same._rank

    def __ne__(self, other: object) -> bool | NotImplementedType:
        if type(other) is not type(self):
            if isinstance(other, str):
                return self.value != other
            return NotImplemented
        same: Self = cast(Self, other)
        return self._rank != same._rank

    def __str__(self) -> str:
        return self.value


class Severity(RankedEnum):
    """The severity of an issue."""

    CRITICAL = "critical", 5
    HIGH = "high", 4
    MEDIUM = "medium", 3
    LOW = "low", 2
    INFO = "info", 1


class Priority(RankedEnum):
    """The priority of an issue."""

    HIGH = "high", 2
    MEDIUM = "medium", 1
    LOW = "low", 0


@dataclass(frozen=True)
class IssueDescriptor:
    """Stable id (enum member), default severity, and optional priority for an issue."""

    id: IssueId
    severity: Severity
    priority: Priority | None = None


@dataclass(frozen=True)
class RecommendationDescriptor:
    """Stable id (enum member), default severity, and optional priority for a recommendation."""

    id: RecommendationId
    priority: Priority | None = None


class Status(StrEnum):
    """The status of a check."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class Capability(StrEnum):
    """The capability of a check."""

    CHECK = "check"
    GENERATE = "generate"


class OutputFormat(StrEnum):
    """The output format of a check."""

    RICH = "rich"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


class DNSProvider(StrEnum):
    """Named DNS resolver presets.

    Use ``SYSTEM`` for the OS-configured resolver, or pick a well-known
    public resolver.
    """

    SYSTEM = "system"
    GOOGLE = "google"
    CLOUDFLARE = "cloudflare"
    QUAD9 = "quad9"
    OPENDNS = "opendns"


class RecordType(StrEnum):
    """DNS record type for generated records and resolver lookups."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
