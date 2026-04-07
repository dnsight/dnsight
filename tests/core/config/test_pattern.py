"""Tests for config pattern matching."""

from __future__ import annotations

import pytest

from dnsight.core.config.pattern import Pattern


class TestNormalise:
    def test_lowercase_and_strip_slashes(self) -> None:
        assert Pattern.normalise("Example.COM", "/API/v1/") == "example.com/api/v1"

    def test_domain_only(self) -> None:
        assert Pattern.normalise("example.com") == "example.com"

    def test_trailing_dot_stripped(self) -> None:
        assert Pattern.normalise("example.com.") == "example.com"

    def test_root_path(self) -> None:
        assert Pattern.normalise("example.com", "/") == "example.com"

    def test_empty_path(self) -> None:
        assert Pattern.normalise("example.com", "") == "example.com"


class TestMatches:
    def test_exact_match(self) -> None:
        assert Pattern.matches("example.com", "example.com") is True

    def test_case_insensitive_target(self) -> None:
        assert Pattern.matches("example.com", "EXAMPLE.COM") is True

    def test_wildcard_one_label(self) -> None:
        assert Pattern.matches("*.example.com", "sub.example.com") is True

    def test_wildcard_mismatch_label_count(self) -> None:
        assert Pattern.matches("*.example.com", "example.com") is False

    def test_wildcard_two_labels(self) -> None:
        assert Pattern.matches("*.example.com", "a.b.example.com") is False

    def test_pipe_alternatives(self) -> None:
        assert Pattern.matches("a.com|b.com", "b.com") is True
        assert Pattern.matches("a.com|b.com", "a.com") is True
        assert Pattern.matches("a.com|b.com", "c.com") is False

    def test_path_wildcard(self) -> None:
        assert Pattern.matches("example.com/api/*", "example.com/api/v1") is True

    def test_path_exact(self) -> None:
        assert Pattern.matches("example.com/api/v1", "example.com/api/v1") is True

    def test_path_mismatch(self) -> None:
        assert Pattern.matches("example.com/api/v1", "example.com/api/v2") is False

    def test_no_pattern_path_matches_any_target_path(self) -> None:
        assert Pattern.matches("example.com", "example.com/anything") is True

    def test_path_segment_count_mismatch(self) -> None:
        assert Pattern.matches("example.com/a/b", "example.com/a") is False

    def test_fnmatch_glob_in_segment(self) -> None:
        assert Pattern.matches("ex*.com", "example.com") is True
        assert Pattern.matches("ex*.com", "extra.com") is True
        assert Pattern.matches("ex*.com", "other.com") is False

    @pytest.mark.parametrize(
        ("pattern", "target", "expected"),
        [
            ("example.com", "EXAMPLE.COM", True),
            ("*.io", "mysite.io", True),
            ("*.io", "io", False),
            ("a.b.c", "a.b.c", True),
            ("a.b.c", "x.b.c", False),
        ],
    )
    def test_parametrized(self, pattern: str, target: str, expected: bool) -> None:
        assert Pattern.matches(pattern, target) is expected
