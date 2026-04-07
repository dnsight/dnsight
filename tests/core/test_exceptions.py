"""Tests for core exceptions."""

from __future__ import annotations

import pytest

from dnsight.core.exceptions import (
    CapabilityError,
    CheckError,
    CheckNotFoundError,
    ConfigError,
    ConfigValidationError,
    DNSightError,
)


class TestHierarchy:
    @pytest.mark.parametrize(
        "exc_cls", [CheckError, ConfigError, CheckNotFoundError, CapabilityError]
    )
    def test_subclass_of_dnsight_error(self, exc_cls: type[DNSightError]) -> None:
        assert issubclass(exc_cls, DNSightError)
        assert issubclass(exc_cls, Exception)

    def test_config_validation_is_config_error(self) -> None:
        assert issubclass(ConfigValidationError, ConfigError)
        assert issubclass(ConfigValidationError, DNSightError)


class TestCapabilityError:
    def test_stores_attributes(self) -> None:
        err = CapabilityError("caa", "generate")
        assert err.check_name == "caa"
        assert err.capability == "generate"

    def test_message_format(self) -> None:
        err = CapabilityError("dmarc", "flatten")
        assert "dmarc" in str(err)
        assert "flatten" in str(err)

    def test_catchable_as_dnsight_error(self) -> None:
        with pytest.raises(DNSightError):
            raise CapabilityError("mx", "check")


class TestCatchability:
    def test_check_error_caught_as_parent(self) -> None:
        with pytest.raises(DNSightError):
            raise CheckError("boom")

    def test_config_validation_caught_as_config_error(self) -> None:
        with pytest.raises(ConfigError):
            raise ConfigValidationError("bad schema")

    def test_check_not_found_caught_as_parent(self) -> None:
        with pytest.raises(DNSightError):
            raise CheckNotFoundError("nonexistent")
