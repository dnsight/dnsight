"""Hierarchical token-bucket throttle for rate-limiting I/O.

Each ``ThrottleManager`` instance is a single token bucket with an
optional parent. Calling ``wait()`` acquires a token from the entire
parent chain (global -> domain -> check), so the effective rate is
naturally ``min(global_rps, domain_rps, check_rps)`` without explicit
calculation.

The orchestrator builds the hierarchy; checks call ``wait()`` before
each I/O operation if a throttler was provided.
"""

from __future__ import annotations

import asyncio
import time


__all__ = ["ThrottleManager", "NoopThrottleManager"]


class ThrottleManager:
    """Hierarchical token-bucket rate limiter.

    Each instance has its own bucket (``max_rps``, ``burst``). If a
    ``parent`` is supplied, ``wait()`` acquires a token from the parent
    first, then from this bucket — so the effective rate can never exceed
    the parent's.

    Args:
        max_rps: Maximum requests per second for this bucket.
        burst: Maximum burst size (tokens). Defaults to 1.
        parent: Optional parent throttler. ``wait()`` calls
            ``parent.wait()`` before acquiring a local token.
    """

    def __init__(
        self, max_rps: float, burst: int = 1, parent: ThrottleManager | None = None
    ) -> None:
        if max_rps <= 0.0:
            raise ValueError("max_rps must be greater than 0.0")
        if burst < 1:
            raise ValueError("burst must be greater than or equal to 1")
        self._max_rps = max_rps
        self._burst = burst
        self._parent = parent
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        """Wait until a token is available, respecting the full parent chain.

        Parent tokens are acquired first (global before domain before
        check) so that the tightest limit in the chain always governs.
        """
        if self._parent is not None:
            await self._parent.wait()
        await self._acquire()

    async def _acquire(self) -> None:
        """Acquire one local token, sleeping if necessary."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                delay = (1.0 - self._tokens) / self._max_rps
            await asyncio.sleep(delay)

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill."""
        now = time.monotonic()
        self._tokens = min(
            float(self._burst), self._tokens + (now - self._last_refill) * self._max_rps
        )
        self._last_refill = now

    def child(self, max_rps: float = float("inf"), burst: int = 1) -> ThrottleManager:
        """Create a child throttler that respects this throttler's limits.

        Args:
            max_rps: Maximum requests per second for the child bucket.
                Defaults to an effectively unlimited rate if not provided.
            burst: Maximum burst size for the child. Defaults to 1.

        Returns:
            A new ``ThrottleManager`` whose ``wait()`` acquires a token
            from *this* instance before acquiring its own.
        """
        return ThrottleManager(max_rps=max_rps, burst=burst, parent=self)


class NoopThrottleManager(ThrottleManager):
    """Throttle implementation that never waits.

    Use in tests or when throttling is disabled. ``child()`` returns
    ``self`` so the entire hierarchy is no-op.
    """

    def __init__(self) -> None:
        super().__init__(max_rps=1.0)

    async def wait(self) -> None:
        """No-op: returns immediately without rate limiting."""

    def child(self, max_rps: float = 0.0, burst: int = 1) -> NoopThrottleManager:
        """Return self — children of a noop throttler are also noop."""
        return self
