"""Tests for :mod:`dnsight.serialisers.tree` helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dnsight.sdk.audit.models import DomainResult, ZoneResult
from dnsight.serialisers.tree import node_from_domain_batch


def _make_domain(
    domain: str = "example.com",
    *,
    ts: datetime | None = None,
    config_version: int = 1,
    partial: bool = False,
) -> DomainResult:
    zone = ZoneResult(zone=domain, parent=None, results={})
    return DomainResult(
        domain=domain,
        target=domain,
        timestamp=ts or datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
        config_version=config_version,
        zones=[zone],
        partial=partial,
    )


class TestNodeFromDomainBatch:
    def test_raises_on_empty_sequence(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            node_from_domain_batch([])

    def test_single_result(self) -> None:
        dr = _make_domain()
        node = node_from_domain_batch([dr])
        assert node.kind == "audit"
        assert node.timestamp == dr.timestamp
        assert node.config_version == dr.config_version
        assert len(node.children) == 1

    def test_uses_min_timestamp(self) -> None:
        early = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        late = datetime(2025, 1, 1, 14, 0, 0, tzinfo=UTC)
        dr1 = _make_domain("a.com", ts=late)
        dr2 = _make_domain("b.com", ts=early)
        node = node_from_domain_batch([dr1, dr2])
        assert node.timestamp == early

    def test_consistent_config_version_is_used(self) -> None:
        dr1 = _make_domain("a.com", config_version=2)
        dr2 = _make_domain("b.com", config_version=2)
        node = node_from_domain_batch([dr1, dr2])
        assert node.config_version == 2

    def test_mixed_config_version_raises(self) -> None:
        dr1 = _make_domain("a.com", config_version=1)
        dr2 = _make_domain("b.com", config_version=2)
        with pytest.raises(ValueError, match="mixed config_version"):
            node_from_domain_batch([dr1, dr2])

    def test_partial_set_when_any_domain_is_partial(self) -> None:
        dr1 = _make_domain("a.com", partial=False)
        dr2 = _make_domain("b.com", partial=True)
        node = node_from_domain_batch([dr1, dr2])
        assert node.partial is True

    def test_partial_false_when_no_domain_is_partial(self) -> None:
        dr1 = _make_domain("a.com", partial=False)
        dr2 = _make_domain("b.com", partial=False)
        node = node_from_domain_batch([dr1, dr2])
        assert node.partial is False

    def test_children_count_matches_input(self) -> None:
        results = [_make_domain(f"d{i}.com") for i in range(5)]
        node = node_from_domain_batch(results)
        assert len(node.children) == 5
