"""Serialise :class:`~dnsight.core.models.DomainResult` to output formats."""

from __future__ import annotations

from dnsight.serialisers.base import (
    BaseDomainSerialiser,
    ResultType,
    SerialiserOptions,
    domain_result_from_check,
)
from dnsight.serialisers.json import JsonSerialiser
from dnsight.serialisers.markdown import MarkdownSerialiser
from dnsight.serialisers.rich import RichSerialiser
from dnsight.serialisers.sarif import SarifSerialiser
from dnsight.serialisers.writer import write_serialiser


__all__ = [
    "JsonSerialiser",
    "MarkdownSerialiser",
    "RichSerialiser",
    "SarifSerialiser",
    "BaseDomainSerialiser",
    "SerialiserOptions",
    "domain_result_from_check",
    "ResultType",
    "write_serialiser",
]
