"""SDK run API: resolve config, then call audit orchestration (single-check, domain, targets, streams)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
import warnings

from dnsight.core.config import Config, ConfigManager
from dnsight.core.models import CheckResult
from dnsight.sdk._manager import config_manager, resolve_run_manager
from dnsight.sdk.audit import (
    AuditResult,
    DomainResult,
    RunAuditOptions,
    ZoneResult,
    run_check_for_target,
)
from dnsight.sdk.audit import run_config_targets as audit_run_config_targets
from dnsight.sdk.audit import run_domain as audit_run_domain
from dnsight.sdk.audit import run_domain_stream as audit_run_domain_stream


__all__ = [
    "run_batch",
    "run_batch_sync",
    "run_check",
    "run_check_sync",
    "run_domain",
    "run_domain_stream",
    "run_domain_stream_sync",
    "run_domain_sync",
    "run_targets",
    "run_targets_sync",
]


async def run_check(
    check_name: str,
    domain: str,
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    config: Config | None = None,
) -> CheckResult[Any]:
    """Run one registered check for *domain* using merged config and runtime."""
    import dnsight.checks  # noqa: F401

    m = resolve_run_manager(
        domain=domain,
        mgr=mgr,
        config_path=config_path,
        program_config=config,
        single_check=check_name,
    )
    return await run_check_for_target(check_name, domain, mgr=m)


def run_check_sync(
    check_name: str,
    domain: str,
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    config: Config | None = None,
) -> CheckResult[Any]:
    """Synchronously run :func:`run_check`."""
    return asyncio.run(
        run_check(check_name, domain, config_path=config_path, mgr=mgr, config=config)
    )


async def run_domain(
    domain: str,
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> DomainResult:
    """Asynchronously run checks for *domain* and return a :class:`DomainResult`."""
    import dnsight.checks  # noqa: F401

    m = config_manager(mgr=mgr, config_path=config_path)
    return await audit_run_domain(
        domain,
        mgr=m,
        checks=checks,
        exclude=exclude,
        recursive=recursive,
        depth=depth,
        options=options,
    )


def run_domain_sync(
    domain: str,
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> DomainResult:
    """Synchronously run checks for *domain* and return a :class:`DomainResult`."""
    return asyncio.run(
        run_domain(
            domain,
            config_path=config_path,
            mgr=mgr,
            checks=checks,
            exclude=exclude,
            recursive=recursive,
            depth=depth,
            options=options,
        )
    )


async def run_domain_stream(
    domain: str,
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> AsyncIterator[ZoneResult]:
    """Yield each zone's result depth-first (root first); not a nested tree."""
    import dnsight.checks  # noqa: F401

    m = config_manager(mgr=mgr, config_path=config_path)
    async for z in audit_run_domain_stream(
        domain,
        mgr=m,
        checks=checks,
        exclude=exclude,
        recursive=recursive,
        depth=depth,
        options=options,
    ):
        yield z


def run_domain_stream_sync(
    domain: str,
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> list[ZoneResult]:
    """Synchronously collect all zone results depth-first (root first); not a nested tree."""

    async def _collect() -> list[ZoneResult]:
        return [
            z
            async for z in run_domain_stream(
                domain,
                config_path=config_path,
                mgr=mgr,
                checks=checks,
                exclude=exclude,
                recursive=recursive,
                depth=depth,
                options=options,
            )
        ]

    return asyncio.run(_collect())


async def run_targets(
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> AuditResult:
    """Run a domain audit for each manifest ``targets`` row; returns :class:`AuditResult`."""
    import dnsight.checks  # noqa: F401

    m = config_manager(mgr=mgr, config_path=config_path)
    return await audit_run_config_targets(
        mgr=m,
        checks=checks,
        exclude=exclude,
        recursive=recursive,
        depth=depth,
        options=options,
    )


def run_targets_sync(
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> AuditResult:
    """Synchronously run :func:`run_targets`."""
    return asyncio.run(
        run_targets(
            config_path=config_path,
            mgr=mgr,
            checks=checks,
            exclude=exclude,
            recursive=recursive,
            depth=depth,
            options=options,
        )
    )


async def run_batch(
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> AuditResult:
    """Deprecated alias for :func:`run_targets`."""
    warnings.warn(
        "run_batch is deprecated; use run_targets instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return await run_targets(
        config_path=config_path,
        mgr=mgr,
        checks=checks,
        exclude=exclude,
        recursive=recursive,
        depth=depth,
        options=options,
    )


def run_batch_sync(
    *,
    config_path: Path | str | None = None,
    mgr: ConfigManager | None = None,
    checks: list[str] | None = None,
    exclude: list[str] | None = None,
    recursive: bool = False,
    depth: int = 3,
    options: RunAuditOptions | None = None,
) -> AuditResult:
    """Deprecated alias for :func:`run_targets_sync`."""
    warnings.warn(
        "run_batch_sync is deprecated; use run_targets_sync instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return run_targets_sync(
        config_path=config_path,
        mgr=mgr,
        checks=checks,
        exclude=exclude,
        recursive=recursive,
        depth=depth,
        options=options,
    )
