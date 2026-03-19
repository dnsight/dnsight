"""Tests for core registry."""

from __future__ import annotations

import pytest

from dnsight.core.exceptions import CheckNotFoundError
from dnsight.core.registry import all_checks, get, register, supporting
from dnsight.core.types import Capability


class _FakeCheck:
    name = "fake"
    capabilities = frozenset({Capability.CHECK})


class _FakeGenerateCheck:
    name = "fake-gen"
    capabilities = frozenset({Capability.CHECK, Capability.GENERATE})


class TestRegister:
    def test_register_and_get(self) -> None:
        register(_FakeCheck)
        defn = get("fake")
        assert defn.name == "fake"
        assert defn.cls is _FakeCheck
        assert Capability.CHECK in defn.capabilities

    def test_register_returns_class(self) -> None:
        result = register(_FakeCheck)
        assert result is _FakeCheck

    def test_register_duplicate_raises(self) -> None:
        register(_FakeCheck)

        class _FakeCheck2:
            name = "fake"
            capabilities = frozenset({Capability.GENERATE})

        with pytest.raises(RuntimeError, match="already registered"):
            register(_FakeCheck2)


class TestGet:
    def test_unknown_raises(self) -> None:
        with pytest.raises(CheckNotFoundError):
            get("nonexistent")


class TestAllChecks:
    def test_returns_all_registered(self) -> None:
        register(_FakeCheck)
        register(_FakeGenerateCheck)
        checks = all_checks()
        names = {c.name for c in checks}
        assert "fake" in names
        assert "fake-gen" in names

    def test_empty_when_none_registered(self) -> None:
        assert all_checks() == []


class TestSupporting:
    def test_filters_by_capability(self) -> None:
        register(_FakeCheck)
        register(_FakeGenerateCheck)
        gen_checks = supporting(Capability.GENERATE)
        assert len(gen_checks) == 1
        assert gen_checks[0].name == "fake-gen"

    def test_check_capability(self) -> None:
        register(_FakeCheck)
        register(_FakeGenerateCheck)
        check_checks = supporting(Capability.CHECK)
        assert len(check_checks) == 2

    def test_supporting_returns_matching_checks(self) -> None:
        register(_FakeCheck)
        result = supporting(Capability.CHECK)
        assert isinstance(result, list)
        assert any(d.cls is _FakeCheck for d in result)
