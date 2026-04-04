"""Shared fixtures for the dnsight test suite."""

from __future__ import annotations

import logging

import pytest

import dnsight.core.registry as registry
from dnsight.utils.dns import reset_resolver
from dnsight.utils.http import reset_http_client
from dnsight.utils.smtp import reset_starttls_probe


@pytest.fixture(autouse=True)
def _clean_registry(request: pytest.FixtureRequest) -> None:  # noqa: PT004
    """Clear the check registry before each test so registrations don't leak."""
    if request.node.get_closest_marker("registry_builtins"):
        yield  # type: ignore[misc]
        return
    saved = dict(registry._CHECKS)
    registry._CHECKS.clear()
    yield  # type: ignore[misc]
    registry._CHECKS.clear()
    registry._CHECKS.update(saved)


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:  # noqa: PT004
    """Reset DNS resolver and HTTP client singletons after each test."""
    yield  # type: ignore[misc]
    reset_resolver()
    reset_http_client()
    reset_starttls_probe()


@pytest.fixture(autouse=True)
def _reset_dnsight_package_logger() -> None:  # noqa: PT004
    """Clear CLI-configured handlers so tests do not leak logging state."""
    log = logging.getLogger("dnsight")
    log.handlers.clear()
    log.setLevel(logging.NOTSET)
    yield  # type: ignore[misc]
    log.handlers.clear()
    log.setLevel(logging.NOTSET)
