"""Tests for flat zone iteration."""

from __future__ import annotations

from datetime import UTC, datetime

from dnsight.core.models import CheckResult
from dnsight.core.types import Status
from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers._zone import iter_flat_zones


def test_iter_flat_zones_dfs_root_before_child() -> None:
    child = ZoneResult(
        zone="sub.example.com",
        results={"spf": CheckResult[object](status=Status.COMPLETED)},
    )
    root = ZoneResult(
        zone="example.com",
        results={"dmarc": CheckResult[object](status=Status.COMPLETED)},
        children=[child],
    )
    dr = DomainResult(
        domain="example.com",
        target="example.com",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        config_version=1,
        zones=[root],
        partial=False,
    )
    fqdns = [z.zone for z in iter_flat_zones(dr)]
    assert fqdns == ["example.com", "sub.example.com"]
