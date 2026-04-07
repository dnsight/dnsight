"""Tests for core throttle."""

from __future__ import annotations

import time

from dnsight.core.throttle import NoopThrottleManager, ThrottleManager


class TestNoopThrottleManager:
    async def test_wait_returns_immediately(self) -> None:
        noop = NoopThrottleManager()
        start = time.monotonic()
        await noop.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    async def test_child_returns_self(self) -> None:
        noop = NoopThrottleManager()
        child = noop.child()
        assert child is noop

    async def test_child_with_rate_returns_self(self) -> None:
        noop = NoopThrottleManager()
        child = noop.child(max_rps=10.0)
        assert child is noop


class TestThrottleManager:
    async def test_single_wait(self) -> None:
        tm = ThrottleManager(max_rps=100.0)
        await tm.wait()

    async def test_child_has_parent(self) -> None:
        parent = ThrottleManager(max_rps=100.0)
        child = parent.child(max_rps=50.0)
        assert isinstance(child, ThrottleManager)
        assert child._parent is parent

    async def test_child_with_burst(self) -> None:
        parent = ThrottleManager(max_rps=100.0)
        child = parent.child(max_rps=50.0, burst=5)
        assert child._burst == 5

    async def test_rate_limiting_introduces_delay(self) -> None:
        tm = ThrottleManager(max_rps=5.0, burst=1)
        await tm.wait()
        start = time.monotonic()
        await tm.wait()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.1  # 1/5 = 0.2s, allow some tolerance

    async def test_parent_child_chain(self) -> None:
        parent = ThrottleManager(max_rps=5.0, burst=1)
        child = parent.child(max_rps=100.0, burst=1)
        # First call consumes tokens
        await child.wait()
        start = time.monotonic()
        # Second call should be limited by parent (5 rps)
        await child.wait()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.1

    async def test_high_rate_no_significant_delay(self) -> None:
        tm = ThrottleManager(max_rps=1000.0, burst=10)
        start = time.monotonic()
        for _ in range(5):
            await tm.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1
