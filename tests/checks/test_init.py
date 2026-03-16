"""Tests for checks/__init__.py — re-exports from dmarc module."""

from __future__ import annotations

from dnsight.checks import (
    DMARCCheck,
    DMARCData,
    DMARCIssueId,
    DMARCRecommendationId,
    check_dmarc,
    generate_dmarc,
    get_dmarc,
)


class TestChecksReExports:
    def test_dmarc_check_reexported(self) -> None:
        assert DMARCCheck is not None

    def test_dmarc_data_reexported(self) -> None:
        assert DMARCData is not None

    def test_issue_id_reexported(self) -> None:
        assert DMARCIssueId is not None

    def test_recommendation_id_reexported(self) -> None:
        assert DMARCRecommendationId is not None

    def test_function_aliases_reexported(self) -> None:
        assert callable(get_dmarc)
        assert callable(check_dmarc)
        assert callable(generate_dmarc)
