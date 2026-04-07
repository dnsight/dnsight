"""Per-run throttle and concurrency bundle for the orchestrator."""

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

    ``effective_max_rps`` and ``effective_max_concurrency`` mirror the
    limits used to construct ``throttle`` and ``concurrency`` so nested
    helpers (e.g. per-zone runs, recursion) can build child throttlers
    without threading extra arguments.

    Attributes:
        config: Resolved configuration for this run.
        throttle: Root (global) throttle manager. The orchestrator
            calls ``throttle.child(...)`` to create per-domain and
            per-check throttlers.
        concurrency: Global concurrency limiter.
        effective_max_rps: Combined global RPS limit used for this run.
        effective_max_concurrency: Combined concurrency limit for this run.
    """

    config: ResolvedConfig
    throttle: ThrottleManager
    concurrency: ConcurrencyLimiter
    effective_max_rps: float
    effective_max_concurrency: int
