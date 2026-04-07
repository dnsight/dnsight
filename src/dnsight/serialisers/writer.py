"""Atomic file output for :class:`~dnsight.serialisers.base.BaseDomainSerialiser`."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import overload

from dnsight.core.models import CheckResult, CheckResultAny
from dnsight.sdk.audit.models import DomainResult
from dnsight.serialisers.base import BaseDomainSerialiser, ResultType, SerialiserOptions


__all__ = ["write_serialiser"]


@overload
def write_serialiser(
    serialiser: BaseDomainSerialiser,
    result: CheckResultAny,
    path: Path | str,
    *,
    domain: str,
    check_name: str,
    options: SerialiserOptions | None = None,
) -> None: ...


@overload
def write_serialiser(
    serialiser: BaseDomainSerialiser,
    result: DomainResult,
    path: Path | str,
    *,
    options: SerialiserOptions | None = None,
) -> None: ...


@overload
def write_serialiser(
    serialiser: BaseDomainSerialiser,
    result: Sequence[DomainResult],
    path: Path | str,
    *,
    options: SerialiserOptions | None = None,
) -> None: ...


def write_serialiser(
    serialiser: BaseDomainSerialiser,
    result: ResultType,
    path: Path | str,
    *,
    domain: str | None = None,
    check_name: str | None = None,
    options: SerialiserOptions | None = None,
) -> None:
    """Write serialised output to *path* (atomic replace).

    For a :class:`~dnsight.core.models.CheckResult`, pass ``domain=`` and
    ``check_name=``. For a :class:`~dnsight.sdk.audit.models.DomainResult` or a
    non-empty sequence of them, omit those keywords.

    ``options.spf_flatten_detail`` expands SPF flattened summaries in Rich/Markdown;
    ``options.human_finding_detail`` expands issue/remediation and recommendation
    text; ``options.human_data_preview`` (default false; CLI: ``--markdown-data-preview``)
    adds a generic ``data`` preview in Markdown when no typed summary lines exist.
    JSON/SARIF ignore these hints.
    """
    if isinstance(result, CheckResult):
        if domain is None or check_name is None:
            msg = (
                "write_serialiser(CheckResult) requires keyword arguments "
                "domain= and check_name="
            )
            raise TypeError(msg)
        content = serialiser.serialise(
            result, domain=domain, check_name=check_name, options=options
        )
    else:
        content = serialiser.serialise(result, options=options)

    dest = Path(path)
    suffix = dest.suffix
    tmp_suffix = f"{suffix or ''}.tmp"
    tmp = dest.with_suffix(tmp_suffix)
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    tmp.replace(dest)
