"""Global concurrency limiter for dnsight.

A single semaphore that caps the total number of concurrent tasks to
protect system resources (open file descriptors, memory, CPU). Rate
limiting per-domain or per-check is handled by the throttle hierarchy
instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


__all__ = ["ConcurrencyManager", "NoopConcurrencyManager"]


class ConcurrencyManager:
    """Global semaphore that bounds total in-flight tasks.

    Args:
        limit: Maximum concurrent tasks across the entire audit.
    """

    def __init__(self, limit: int = 20) -> None:
        self._sem = asyncio.Semaphore(limit)

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[None]:
        """Acquire the global semaphore before yielding."""
        async with self._sem:
            yield


class NoopConcurrencyManager:
    """No-op concurrency manager for tests or when limiting is disabled."""

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[None]:
        """Yield immediately without acquiring any semaphore."""
        yield
