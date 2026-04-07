"""Audit orchestration: run checks across zones/domains and manifest targets."""

from __future__ import annotations

from dnsight.sdk.audit.models import AuditResult, DomainResult, ZoneResult
from dnsight.sdk.audit.options import RunAuditOptions, resolve_audit_params
from dnsight.sdk.audit.run import (
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
    "AuditResult",
    "DomainResult",
    "RunAuditOptions",
    "ZoneResult",
    "apply_resolver_config",
    "build_runtime",
    "child_zone_names_from_ns",
    "discover_child_zone_names",
    "resolve_audit_params",
    "run_check_for_target",
    "run_config_targets",
    "run_domain",
    "run_domain_stream",
    "run_zone",
]
