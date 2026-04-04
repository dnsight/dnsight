"""Run checks for a domain concurrently and assemble :class:`DomainResult`.

Uses the check registry only (no imports from ``dnsight.checks`` by module path).
Delegated child zones (optional) are inferred from in-bailiwick NS targets.

Batch runs over :attr:`ConfigManager.targets` are **sequential**: each target may
merge different resolver settings; :func:`build_runtime` applies the process-wide
resolver, so concurrent target runs would race.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any

from dnsight.core.concurrency import ConcurrencyManager
from dnsight.core.config import ConfigManager, ResolvedConfig
from dnsight.core.config.blocks import ResolverConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.logger import get_logger
from dnsight.core.models import CheckResult, DomainResult, ZoneResult
from dnsight.core.registry import get
from dnsight.core.runtime import Runtime
from dnsight.core.throttle import ThrottleManager
from dnsight.core.types import Status
from dnsight.utils.dns import AsyncDNSResolver, get_resolver, set_resolver


logger = get_logger(__name__)

__all__ = [
    "RunAuditOptions",
    "apply_resolver_config",
    "build_runtime",
    "child_zone_names_from_ns",
    "discover_child_zone_names",
    "run_check_for_target",
    "run_config_targets",
    "run_domain",
    "run_domain_stream",
    "run_zone",
]


@dataclass(frozen=True)
class RunAuditOptions:
    """Options shared by :func:`run_domain`, :func:`run_domain_stream`, and :func:`run_config_targets`.

    When passed, overrides the individual ``checks`` / ``exclude`` / ``recursive`` /
    ``depth`` keyword arguments for that call.
    """

    checks: list[str] | None = None
    exclude: list[str] | None = None
    recursive: bool = False
    depth: int = 3


def _resolve_audit_params(
    options: RunAuditOptions | None,
    *,
    checks: list[str] | None,
    exclude: list[str] | None,
    recursive: bool,
    depth: int,
) -> tuple[list[str] | None, list[str] | None, bool, int]:
    if options is not None:
        return options.checks, options.exclude, options.recursive, options.depth
    return checks, exclude, recursive, depth


_IN_PARENT_ZONE_NS_LABEL = re.compile(r"^ns\d*$|^dns\d*$", re.IGNORECASE)


def child_zone_names_from_ns(apex: str, ns_hostnames: list[str]) -> list[str]:
    """Infer delegated child zone names from NS targets at *apex*."""
    apex = apex.rstrip(".").lower()
    apex_labels = apex.split(".")
    n = len(apex_labels)
    found: set[str] = set()
    for raw in ns_hostnames:
        h = raw.rstrip(".").lower()
        if not h or h == apex:
            continue
        parts = h.split(".")
        if len(parts) <= n:
            continue
        if parts[-n:] != apex_labels:
            continue
        extra = len(parts) - n
        if extra >= 2:
            child = ".".join(parts[-(n + 1) :])
            found.add(child)
        elif extra == 1:
            if _IN_PARENT_ZONE_NS_LABEL.match(parts[0]):
                continue
            found.add(h)
    return sorted(found)


async def discover_child_zone_names(apex: str) -> list[str]:
    """Return delegated child zones under *apex* using NS at the zone apex."""
    try:
        targets = await get_resolver().resolve_ns(apex)
    except CheckError:
        return []
    return child_zone_names_from_ns(apex, targets)


def apply_resolver_config(resolver_config: ResolverConfig) -> None:
    """Set the process-wide async resolver from merged config."""
    nameservers = resolver_config.resolved_nameservers()
    set_resolver(AsyncDNSResolver(nameservers=nameservers))


def _effective_limits(
    mgr: ConfigManager, resolved: ResolvedConfig
) -> tuple[float, int]:
    """Combine file-level limits with merged per-target throttle config."""
    cfg = resolved.config.throttle
    rps = min(mgr.global_max_rps, cfg.global_max_rps)
    conc = min(mgr.global_max_concurrency, cfg.global_max_concurrency)
    return rps, conc


def build_runtime(mgr: ConfigManager, resolved: ResolvedConfig) -> Runtime:
    """Configure DNS, then build throttle, concurrency, and :class:`Runtime`."""
    apply_resolver_config(resolved.config.resolver)
    rps, conc = _effective_limits(mgr, resolved)
    logger.debug("Runtime limits: max_rps=%s max_concurrency=%s", rps, conc)
    throttle = ThrottleManager(max_rps=rps)
    concurrency = ConcurrencyManager(limit=conc)
    return Runtime(
        config=resolved,
        throttle=throttle,
        concurrency=concurrency,
        effective_max_rps=rps,
        effective_max_concurrency=conc,
    )


def _failed_check_result(exc: BaseException) -> CheckResult[Any]:
    """Surface an unexpected exception as a failed check result."""
    return CheckResult(
        status=Status.FAILED,
        data=None,
        raw=None,
        error=f"{type(exc).__name__}: {exc}",
        issues=[],
        recommendations=[],
    )


def _resolved_check_names(
    mgr: ConfigManager,
    domain: str,
    *,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[str]:
    """Resolve enabled check names for *domain*, applying *checks* and *exclude*."""
    target = mgr.target_string(domain)
    names = (
        list(checks)
        if checks is not None
        else mgr.resolve(target).checks.enabled_names()
    )
    skip = set(exclude) if exclude else set()
    return [n for n in names if n not in skip]


def _apex_from_domain_arg(mgr: ConfigManager, domain: str) -> str:
    target = mgr.target_string(domain)
    return target.split("/", maxsplit=1)[0] if target else target


async def run_zone(
    domain: str, runtime: Runtime, checks: list[str], *, parent: str | None = None
) -> ZoneResult:
    """Run *checks* for *domain* concurrently and return a :class:`ZoneResult`."""
    resolved = runtime.config
    rps = runtime.effective_max_rps
    domain_throttle = runtime.throttle.child(max_rps=rps)
    logger.debug(
        "Running zone %r with %d check(s): %s",
        domain,
        len(checks),
        ", ".join(checks) if checks else "(none)",
    )

    async def _run_one(name: str) -> tuple[str, CheckResult[Any]]:
        check_throttle = domain_throttle.child(max_rps=rps)
        defn = get(name)
        inst = defn.cls()
        async with runtime.concurrency.acquire():
            try:
                res = await inst.check(
                    domain, config=resolved.config, throttler=check_throttle
                )
            except BaseException as exc:
                logger.error(
                    "Check %r raised %s for zone %r",
                    name,
                    type(exc).__name__,
                    domain,
                    exc_info=True,
                )
                res = _failed_check_result(exc)
            return name, res

    pairs = await asyncio.gather(*(_run_one(name) for name in checks))
    return ZoneResult(zone=domain, parent=parent, results=dict(pairs), children=[])


async def _run_zone_tree(
    apex: str,
    mgr: ConfigManager,
    checks: list[str],
    parent: str | None,
    *,
    recursive: bool,
    remaining_depth: int,
) -> ZoneResult:
    """Run checks for *apex* and optionally recurse into delegated children."""
    target = mgr.target_string(apex)
    resolved = mgr.resolve(target)
    runtime = build_runtime(mgr, resolved)
    leaf = await run_zone(apex, runtime, checks, parent=parent)
    if not recursive or remaining_depth <= 0:
        return leaf
    child_names = await discover_child_zone_names(apex)
    children = [
        await _run_zone_tree(
            ch, mgr, checks, apex, recursive=True, remaining_depth=remaining_depth - 1
        )
        for ch in child_names
    ]
    return ZoneResult(
        zone=leaf.zone, parent=leaf.parent, results=leaf.results, children=children
    )


async def run_domain(
    domain: str,
    *,
    mgr: ConfigManager,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> DomainResult:
    """Resolve config, run checks for *domain*, return :class:`DomainResult`."""
    import dnsight.checks  # noqa: F401

    checks, exclude, recursive, depth = _resolve_audit_params(
        options, checks=checks, exclude=exclude, recursive=recursive, depth=depth
    )
    apex = _apex_from_domain_arg(mgr, domain)
    names = _resolved_check_names(mgr, domain, checks=checks, exclude=exclude)
    logger.info("Running audit for %s", apex)
    root = await _run_zone_tree(
        apex, mgr, names, None, recursive=recursive, remaining_depth=depth
    )
    return DomainResult(
        domain=apex,
        timestamp=datetime.now(UTC),
        config_version=mgr.config_schema_version,
        zones=[root],
        partial=root.partial,
    )


async def _stream_zones_dfs(
    apex: str,
    mgr: ConfigManager,
    checks: list[str],
    parent: str | None,
    *,
    recursive: bool,
    remaining_depth: int,
) -> AsyncIterator[ZoneResult]:
    """Yield one :class:`ZoneResult` per zone (depth-first)."""
    target = mgr.target_string(apex)
    resolved = mgr.resolve(target)
    runtime = build_runtime(mgr, resolved)
    yield await run_zone(apex, runtime, checks, parent=parent)
    if not recursive or remaining_depth <= 0:
        return
    for ch in await discover_child_zone_names(apex):
        async for z in _stream_zones_dfs(
            ch, mgr, checks, apex, recursive=True, remaining_depth=remaining_depth - 1
        ):
            yield z


async def run_domain_stream(
    domain: str,
    *,
    mgr: ConfigManager,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> AsyncIterator[ZoneResult]:
    """Yield each zone’s result depth-first (root first); not a nested tree."""
    import dnsight.checks  # noqa: F401

    checks, exclude, recursive, depth = _resolve_audit_params(
        options, checks=checks, exclude=exclude, recursive=recursive, depth=depth
    )
    apex = _apex_from_domain_arg(mgr, domain)
    names = _resolved_check_names(mgr, domain, checks=checks, exclude=exclude)
    logger.info("Running audit for %s", apex)
    async for z in _stream_zones_dfs(
        apex, mgr, names, None, recursive=recursive, remaining_depth=depth
    ):
        yield z


async def run_check_for_target(
    check_name: str, domain: str, *, mgr: ConfigManager
) -> CheckResult[Any]:
    """Run a single registered check for *domain* using merged config and :class:`Runtime`."""
    import dnsight.checks  # noqa: F401

    apex = _apex_from_domain_arg(mgr, domain)
    target = mgr.target_string(domain)
    logger.info("Running check %r for %s", check_name, target)
    resolved = mgr.resolve(target)
    runtime = build_runtime(mgr, resolved)
    zone_result = await run_zone(apex, runtime, [check_name])
    out = zone_result.results.get(check_name)
    if out is not None:
        return out
    logger.error("Check %r did not produce a result for target %s", check_name, target)
    return CheckResult(
        status=Status.FAILED,
        data=None,
        raw=None,
        error=f"Check {check_name!r} did not produce a result",
        issues=[],
        recommendations=[],
    )


async def run_config_targets(
    *,
    mgr: ConfigManager,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> list[DomainResult]:
    """Run a domain audit for each entry in :attr:`ConfigManager.targets` in order.

    Returns an empty list when ``targets`` is empty. Runs are sequential so each
    target’s merged resolver config is applied before the next audit.
    """
    import dnsight.checks  # noqa: F401

    checks, exclude, recursive, depth = _resolve_audit_params(
        options, checks=checks, exclude=exclude, recursive=recursive, depth=depth
    )
    if not mgr.targets:
        return []
    results: list[DomainResult] = []
    for t in mgr.targets:
        key = mgr.target_string(t)
        results.append(
            await run_domain(
                key,
                mgr=mgr,
                checks=checks,
                exclude=exclude,
                recursive=recursive,
                depth=depth,
            )
        )
    return results
