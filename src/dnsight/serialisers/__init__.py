"""Serialise :class:`~dnsight.core.models.DomainResult` to output formats."""

from __future__ import annotations

from dnsight.serialisers.base import SerialiserProtocol, write_serialiser
from dnsight.serialisers.json import JsonSerialiser
from dnsight.serialisers.markdown import MarkdownSerialiser
from dnsight.serialisers.rich import RichSerialiser
from dnsight.serialisers.sarif import SarifSerialiser


__all__ = [
    "JsonSerialiser",
    "MarkdownSerialiser",
    "RichSerialiser",
    "SarifSerialiser",
    "SerialiserProtocol",
    "write_serialiser",
]
