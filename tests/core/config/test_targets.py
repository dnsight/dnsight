"""Tests for config targets."""

from __future__ import annotations

import pytest

from dnsight.core.config.targets import (
    ChecksDelta,
    ChecksReplace,
    Target,
    TargetChecks,
    parse_checks,
)


class TestParseChecks:
    def test_none_returns_none(self) -> None:
        assert parse_checks(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert parse_checks("") is None

    def test_list_returns_replace(self) -> None:
        result = parse_checks(["dmarc", "spf"])
        assert isinstance(result, ChecksReplace)
        assert result.enabled == ("dmarc", "spf")

    def test_delta_add_and_remove(self) -> None:
        result = parse_checks("+dmarc,-spf")
        assert isinstance(result, ChecksDelta)
        assert result.add == frozenset({"dmarc"})
        assert result.remove == frozenset({"spf"})

    def test_delta_add_only(self) -> None:
        result = parse_checks("+caa")
        assert isinstance(result, ChecksDelta)
        assert result.add == frozenset({"caa"})
        assert result.remove is None

    def test_delta_remove_only(self) -> None:
        result = parse_checks("-headers")
        assert isinstance(result, ChecksDelta)
        assert result.add is None
        assert result.remove == frozenset({"headers"})

    def test_delta_implicit_add(self) -> None:
        result = parse_checks("dmarc")
        assert isinstance(result, ChecksDelta)
        assert result.add == frozenset({"dmarc"})

    def test_delta_ignores_empty_parts(self) -> None:
        result = parse_checks("+dmarc,,+spf")
        assert isinstance(result, ChecksDelta)
        assert result.add == frozenset({"dmarc", "spf"})


class TestTarget:
    def test_construction(self) -> None:
        t = Target(domain="example.com")
        assert t.domain == "example.com"
        assert t.path == "/"

    def test_custom_path(self) -> None:
        t = Target(domain="example.com", path="/api")
        assert t.path == "/api"


class TestTargetChecks:
    def test_default_empty(self) -> None:
        tc = TargetChecks()
        assert tc.enabled == frozenset()
        assert tc.enabled_names() == []

    def test_from_enabled(self) -> None:
        tc = TargetChecks.from_enabled(("dmarc", "spf"))
        assert tc.is_enabled("dmarc")
        assert tc.is_enabled("spf")
        assert not tc.is_enabled("dkim")
        assert tc.enabled_names() == ["dmarc", "spf"]

    def test_from_enabled_accepts_any_names(self) -> None:
        tc = TargetChecks.from_enabled(("custom-check", "dmarc"))
        assert tc.is_enabled("custom-check")
        assert tc.is_enabled("dmarc")

    def test_is_enabled(self) -> None:
        tc = TargetChecks.from_enabled(("dmarc",))
        assert tc.is_enabled("dmarc") is True
        assert tc.is_enabled("spf") is False

    def test_apply_delta_add(self) -> None:
        tc = TargetChecks.from_enabled(("dmarc",))
        updated = tc.apply_delta(add={"caa"})
        assert updated.is_enabled("dmarc")
        assert updated.is_enabled("caa")

    def test_apply_delta_remove(self) -> None:
        tc = TargetChecks.from_enabled(("dmarc", "spf"))
        updated = tc.apply_delta(remove={"dmarc"})
        assert not updated.is_enabled("dmarc")
        assert updated.is_enabled("spf")

    def test_apply_delta_add_and_remove(self) -> None:
        tc = TargetChecks.from_enabled(("dmarc",))
        updated = tc.apply_delta(add={"caa"}, remove={"dmarc"})
        assert not updated.is_enabled("dmarc")
        assert updated.is_enabled("caa")

    def test_apply_delta_remove_nonexistent_is_noop(self) -> None:
        tc = TargetChecks.from_enabled(("dmarc",))
        updated = tc.apply_delta(remove={"nonexistent"})
        assert updated.enabled_names() == ["dmarc"]

    def test_merge_combines_enabled_sets(self) -> None:
        tc1 = TargetChecks.from_enabled(("dmarc",))
        tc2 = TargetChecks.from_enabled(("spf",))
        merged = tc1.merge(tc2)
        assert merged.is_enabled("dmarc")
        assert merged.is_enabled("spf")

    def test_enabled_names_sorted(self) -> None:
        tc = TargetChecks.from_enabled(("dnssec", "dmarc", "caa"))
        assert tc.enabled_names() == ["caa", "dmarc", "dnssec"]

    def test_frozen(self) -> None:
        tc = TargetChecks()
        with pytest.raises(AttributeError):
            tc.enabled = frozenset({"dmarc"})  # type: ignore[misc]
