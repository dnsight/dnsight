"""Tests for core runtime."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from dnsight.core.concurrency import ConcurrencyManager, NoopConcurrencyManager
from dnsight.core.config import Config, ResolvedTargetConfig, TargetChecks
from dnsight.core.runtime import Runtime
from dnsight.core.throttle import NoopThrottleManager, ThrottleManager


class TestRuntime:
    def test_construction(self) -> None:
        config = ResolvedTargetConfig(checks=TargetChecks(), config=Config())
        throttle = ThrottleManager(max_rps=50.0)
        concurrency = ConcurrencyManager(limit=10)
        rt = Runtime(config=config, throttle=throttle, concurrency=concurrency)
        assert rt.config is config
        assert rt.throttle is throttle
        assert rt.concurrency is concurrency

    def test_construction_with_noops(self) -> None:
        config = ResolvedTargetConfig(checks=TargetChecks(), config=Config())
        rt = Runtime(
            config=config,
            throttle=NoopThrottleManager(),
            concurrency=NoopConcurrencyManager(),
        )
        assert isinstance(rt.throttle, NoopThrottleManager)
        assert isinstance(rt.concurrency, NoopConcurrencyManager)

    def test_frozen(self) -> None:
        config = ResolvedTargetConfig(checks=TargetChecks(), config=Config())
        rt = Runtime(
            config=config,
            throttle=NoopThrottleManager(),
            concurrency=NoopConcurrencyManager(),
        )
        with pytest.raises(FrozenInstanceError):
            rt.config = config  # type: ignore[misc]
