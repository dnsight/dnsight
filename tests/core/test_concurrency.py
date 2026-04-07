"""Tests for core concurrency."""

from __future__ import annotations

import asyncio

from dnsight.core.concurrency import ConcurrencyManager, NoopConcurrencyManager


class TestNoopConcurrencyManager:
    async def test_acquire_yields(self) -> None:
        mgr = NoopConcurrencyManager()
        async with mgr.acquire():
            pass


class TestConcurrencyManager:
    async def test_acquire_basic(self) -> None:
        mgr = ConcurrencyManager(limit=5)
        async with mgr.acquire():
            pass

    async def test_limits_parallelism(self) -> None:
        mgr = ConcurrencyManager(limit=2)
        max_concurrent = 0
        current = 0
        lock = asyncio.Lock()

        async def task() -> None:
            nonlocal max_concurrent, current
            async with mgr.acquire():
                async with lock:
                    current += 1
                    if current > max_concurrent:
                        max_concurrent = current
                await asyncio.sleep(0.05)
                async with lock:
                    current -= 1

        await asyncio.gather(task(), task(), task(), task())
        assert max_concurrent <= 2

    async def test_all_tasks_complete(self) -> None:
        mgr = ConcurrencyManager(limit=1)
        results: list[int] = []

        async def task(n: int) -> None:
            async with mgr.acquire():
                results.append(n)

        await asyncio.gather(task(1), task(2), task(3))
        assert sorted(results) == [1, 2, 3]
