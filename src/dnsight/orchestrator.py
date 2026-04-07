"""Compatibility shim: audit orchestration lives in :mod:`dnsight.sdk.audit`.

New code should import from ``dnsight.sdk.audit`` (or ``dnsight.sdk`` public API).
"""

from __future__ import annotations

from dnsight.sdk.audit import (
    RunAuditOptions,
    apply_resolver_config,
    build_runtime,
    child_zone_names_from_ns,
    discover_child_zone_names,
    run_check_for_target,
    run_config_targets,
    run_domain,
    run_domain_stream,
    run_zone,
)


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
