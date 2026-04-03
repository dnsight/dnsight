"""Registry mapping config schema version numbers to parser callables."""

from __future__ import annotations

from dnsight.core.config.parser.versions.base import VersionParser
from dnsight.core.config.parser.versions.v1 import parse_v1


__all__ = ["VERSION_PARSERS"]

VERSION_PARSERS: dict[int, VersionParser] = {1: parse_v1}
