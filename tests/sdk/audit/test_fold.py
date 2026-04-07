"""Tests for :mod:`dnsight.sdk.audit.fold`."""

from __future__ import annotations

import pytest

from dnsight.core.models import CheckResult
from dnsight.core.types import Status
from dnsight.sdk.audit.fold import nest_flat_zone_results
from dnsight.sdk.audit.models import ZoneResult


def test_nest_single_zone() -> None:
    flat = [
        ZoneResult(
            zone="example.com",
            parent=None,
            children=[],
            results={"dmarc": CheckResult[str](status=Status.COMPLETED)},
        )
    ]
    root = nest_flat_zone_results(flat)
    assert root.zone == "example.com"
    assert root.children == []
    assert "dmarc" in root.results


def test_nest_parent_child_dfs_order() -> None:
    flat = [
        ZoneResult(
            zone="example.com",
            parent=None,
            children=[],
            results={"dmarc": CheckResult[str](status=Status.COMPLETED)},
        ),
        ZoneResult(
            zone="child.example.com",
            parent="example.com",
            children=[],
            results={"dmarc": CheckResult[str](status=Status.COMPLETED)},
        ),
    ]
    root = nest_flat_zone_results(flat)
    assert root.zone == "example.com"
    assert len(root.children) == 1
    assert root.children[0].zone == "child.example.com"
    assert root.children[0].parent == "example.com"


def test_nest_empty_raises() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        nest_flat_zone_results(())
