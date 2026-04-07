"""Stable SDK: config resolution, domain audits, single checks, generate records.

Use :func:`run_check` / :func:`run_domain` / :func:`run_targets` with registry names
from :func:`dnsight.core.registry.all_checks`. Optional aliases in
:mod:`dnsight.sdk.aliases` provide async ``check_<name>``, ``check_<name>_sync``, and
``generate_*`` for ergonomics. CLI should parse argv into the same keyword arguments
as these SDK functions.
"""

from __future__ import annotations

from dnsight.sdk.aliases import (
    check_caa,
    check_caa_sync,
    check_dkim,
    check_dkim_sync,
    check_dmarc,
    check_dmarc_sync,
    check_dnssec,
    check_dnssec_sync,
    check_headers,
    check_headers_sync,
    check_mx,
    check_mx_sync,
    check_spf,
    check_spf_sync,
    generate_caa,
    generate_dmarc,
    generate_headers,
    generate_mx,
    generate_spf,
)
from dnsight.sdk.audit import AuditResult, RunAuditOptions
from dnsight.sdk.generate import generate
from dnsight.sdk.run import (
    run_batch,
    run_batch_sync,
    run_check,
    run_check_sync,
    run_domain,
    run_domain_stream,
    run_domain_stream_sync,
    run_domain_sync,
    run_targets,
    run_targets_sync,
)
from dnsight.sdk.types import (
    BaseGenerateParams,
    CaaGenerateParams,
    CspGenerateParams,
    DMARCGenerateParams,
    HeadersGenerateParams,
    HstsGenerateParams,
    MXGenerateParams,
    MXGenerateTarget,
    SPFGenerateParams,
)


__all__ = [
    "AuditResult",
    "RunAuditOptions",
    "check_caa",
    "check_caa_sync",
    "check_dkim",
    "check_dkim_sync",
    "check_dmarc",
    "check_dmarc_sync",
    "check_dnssec",
    "check_dnssec_sync",
    "check_headers",
    "check_headers_sync",
    "check_mx",
    "check_mx_sync",
    "check_spf",
    "check_spf_sync",
    "generate",
    "generate_caa",
    "generate_dmarc",
    "generate_headers",
    "generate_mx",
    "generate_spf",
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
    "BaseGenerateParams",
    "CaaGenerateParams",
    "CspGenerateParams",
    "DMARCGenerateParams",
    "HeadersGenerateParams",
    "HstsGenerateParams",
    "MXGenerateParams",
    "MXGenerateTarget",
    "SPFGenerateParams",
]
