"""Serialiser protocol and shared file output."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypeAlias

from dnsight.core.models import CheckResult, CheckResultAny, DomainResult, ZoneResult


__all__ = ["BaseDomainSerialiser", "SerialiserOptions", "domain_result_from_check"]


@dataclass(frozen=True, slots=True)
class SerialiserOptions:
    """Rendering hints for human-oriented output (ignored where irrelevant)."""

    spf_flatten_detail: bool = False


def domain_result_from_check(
    *,
    domain: str,
    check_name: str,
    result: CheckResultAny,
    timestamp: datetime | None = None,
    config_version: int = 0,
) -> DomainResult:
    """Wrap a single :class:`~dnsight.core.models.CheckResult` as a one-zone audit."""
    ts = timestamp if timestamp is not None else datetime.now(UTC)
    zone = ZoneResult(
        zone=domain, parent=None, children=[], results={check_name: result}
    )
    return DomainResult(
        domain=domain,
        timestamp=ts,
        config_version=config_version,
        zones=[zone],
        partial=zone.partial,
    )


ResultType: TypeAlias = DomainResult | CheckResultAny | Sequence[DomainResult]


class BaseDomainSerialiser(ABC):
    """Subclasses implement :meth:`_serialise_batch` only; :meth:`serialise` normalises input."""

    def serialise(
        self,
        result: ResultType,
        *,
        domain: str | None = None,
        check_name: str | None = None,
        options: SerialiserOptions | None = None,
    ) -> str:
        """Serialise a domain audit, a batch of audits, or a single check (wrapped as one domain)."""
        opts = options or SerialiserOptions()
        if isinstance(result, CheckResult):
            if domain is None or check_name is None:
                msg = "serialise(CheckResult) requires keyword arguments domain= and check_name="
                raise TypeError(msg)
            wrapped = domain_result_from_check(
                domain=domain, check_name=check_name, result=result
            )
            return self._serialise_batch((wrapped,), options=opts)

        if isinstance(result, DomainResult):
            return self._serialise_batch((result,), options=opts)

        if isinstance(result, str | bytes):
            msg = f"unexpected {type(result).__name__} in serialise()"
            raise TypeError(msg)

        batch = list(result)
        if not batch:
            msg = "domain result sequence must not be empty"
            raise ValueError(msg)

        if not all(isinstance(d, DomainResult) for d in batch):
            msg = "sequence must contain only DomainResult instances"
            raise TypeError(msg)

        return self._serialise_batch(batch, options=opts)

    @abstractmethod
    def _serialise_batch(
        self, results: Sequence[DomainResult], *, options: SerialiserOptions
    ) -> str:
        """Format ``domains`` (length >= 1) into one output string."""
        ...
