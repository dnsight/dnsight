"""Runtime for dnsight.

One ``Runtime`` is created per audit by the orchestrator and holds the
shared infrastructure for the run. Checks do **not** import or receive
Runtime — the orchestrator uses it to build throttle hierarchies and
concurrency wrappers around check calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from dnsight.core.concurrency import ConcurrencyLimiter
from dnsight.core.config import ResolvedConfig
from dnsight.core.throttle import ThrottleManager


__all__ = ["Runtime"]


@dataclass(frozen=True)
class Runtime:
    """Shared state for a single audit run.

    Created once by the orchestrator and never passed to checks.
    The orchestrator uses ``throttle`` and ``concurrency`` to wrap
    check invocations; ``config`` provides resolved settings.

    Attributes:
        config: Resolved configuration for this run.
        throttle: Root (global) throttle manager. The orchestrator
            calls ``throttle.child(...)`` to create per-domain and
            per-check throttlers.
        concurrency: Global concurrency limiter.
    """

    config: ResolvedConfig
    throttle: ThrottleManager
    concurrency: ConcurrencyLimiter
