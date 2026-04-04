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
        rt = Runtime(
            config=config,
            throttle=throttle,
            concurrency=concurrency,
            effective_max_rps=50.0,
            effective_max_concurrency=10,
        )
        assert rt.config is config
        assert rt.throttle is throttle
        assert rt.concurrency is concurrency
        assert rt.effective_max_rps == 50.0
        assert rt.effective_max_concurrency == 10

    def test_construction_with_noops(self) -> None:
        config = ResolvedTargetConfig(checks=TargetChecks(), config=Config())
        rt = Runtime(
            config=config,
            throttle=NoopThrottleManager(),
            concurrency=NoopConcurrencyManager(),
            effective_max_rps=1.0,
            effective_max_concurrency=20,
        )
        assert isinstance(rt.throttle, NoopThrottleManager)
        assert isinstance(rt.concurrency, NoopConcurrencyManager)

    def test_frozen(self) -> None:
        config = ResolvedTargetConfig(checks=TargetChecks(), config=Config())
        rt = Runtime(
            config=config,
            throttle=NoopThrottleManager(),
            concurrency=NoopConcurrencyManager(),
            effective_max_rps=1.0,
            effective_max_concurrency=20,
        )
        with pytest.raises(FrozenInstanceError):
            rt.config = config  # type: ignore[misc]
