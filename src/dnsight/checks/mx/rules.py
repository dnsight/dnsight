"""MX resolution, PTR/STARTTLS collection, and validation rules."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from dnsight.checks.mx.models import (
    MXData,
    MXHostResult,
    MXIssueId,
    MXRecommendationId,
    issue_descriptor,
)
from dnsight.core.config.blocks import Config, MxConfig
from dnsight.core.models import Issue, Recommendation
from dnsight.utils.smtp import StartTLSOutcome, StartTLSProbe, StartTLSProbeResult


if TYPE_CHECKING:
    from dnsight.utils.dns import DNSResolver


__all__ = [
    "collect_mx_data",
    "extract_mx_config",
    "normalise_config",
    "normalise_hostname",
    "validate_mx_results",
]


def extract_mx_config(config: Config | MxConfig | None) -> MxConfig:
    """Return the MxConfig slice from full Config or bare MxConfig."""
    if config is None:
        return MxConfig()
    if isinstance(config, Config):
        return config.mx
    return config


def normalise_config(config: Config | MxConfig | None) -> tuple[MxConfig, bool]:
    """MxConfig and strict_recommendations when config is root Config."""
    if config is None:
        return MxConfig(), False
    if isinstance(config, Config):
        return config.mx, config.strict_recommendations
    return config, False


def normalise_hostname(host: str) -> str:
    """Lowercase and strip trailing dots for FQDN comparison."""
    return (host or "").strip().lower().rstrip(".")


async def collect_mx_data(
    domain: str, resolver: DNSResolver, probe: StartTLSProbe, mx_cfg: MxConfig
) -> MXData:
    """Resolve MX and optionally PTR and STARTTLS for each exchange host.

    MX rows follow the resolver contract (preference order). PTR uses the
    first IPv4 from ``resolve_a``; ``ptr_matches`` is True if any PTR target
    equals the MX hostname after :func:`normalise_hostname`.
    """
    dom = normalise_hostname(domain)
    if not dom:
        return MXData(mx_hosts=[])

    mx_rows = await resolver.resolve_mx(dom)
    hosts: list[MXHostResult] = []
    for priority, hostname in mx_rows:
        ptr_val: str | None = None
        ptr_matches: bool | None = None
        st_sup: bool | None = None
        st_err: str | None = None

        if mx_cfg.check_ptr:
            a_list = await resolver.resolve_a(hostname)
            if not a_list:
                ptr_matches = False
            else:
                ip = a_list[0]
                ptr_list = await resolver.resolve_ptr(ip)
                if ptr_list:
                    ptr_val = ptr_list[0]
                    hn = normalise_hostname(hostname)
                    ptr_matches = any(normalise_hostname(p) == hn for p in ptr_list)
                else:
                    ptr_matches = False

        if mx_cfg.check_starttls:
            pr: StartTLSProbeResult = await probe.probe(
                hostname, port=25, timeout_seconds=mx_cfg.starttls_timeout_seconds
            )
            if pr.outcome == StartTLSOutcome.OK:
                st_sup = True
                st_err = None
            else:
                st_sup = False
                st_err = pr.detail

        hosts.append(
            MXHostResult(
                hostname=hostname,
                priority=priority,
                ptr=ptr_val,
                ptr_matches=ptr_matches,
                starttls_supported=st_sup,
                starttls_error=st_err,
            )
        )
    return MXData(mx_hosts=hosts)


def _starttls_error_is_not_supported(err: str | None) -> bool:
    """Classify probe error text from :mod:`dnsight.utils.smtp` probes."""
    if not err:
        return False
    return err.startswith("STARTTLS not advertised") or err.startswith(
        "STARTTLS rejected"
    )


def validate_mx_results(
    data: MXData, domain: str, mx_cfg: MxConfig
) -> tuple[list[Issue], list[Recommendation]]:
    """Validate MX data and produce issues and recommendations."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    dom = normalise_hostname(domain)

    if not data.mx_hosts:
        desc = issue_descriptor(MXIssueId.RECORD_MISSING)
        issues.append(
            Issue(
                id=MXIssueId.RECORD_MISSING,
                severity=desc.severity,
                title="No MX records",
                description=f"No MX records found for {dom!r}.",
                remediation="Publish at least one MX record for mail delivery.",
            )
        )
        return issues, recommendations

    prios = [h.priority for h in data.mx_hosts]
    dup_counts = [p for p, n in Counter(prios).items() if n > 1]
    if dup_counts:
        dup_desc = issue_descriptor(MXIssueId.DUPLICATE_PRIORITY)
        issues.append(
            Issue(
                id=MXIssueId.DUPLICATE_PRIORITY,
                severity=dup_desc.severity,
                title="Duplicate MX priorities",
                description=(
                    f"Multiple MX records share the same preference value(s): "
                    f"{sorted(dup_counts)!r}."
                ),
                remediation="Use distinct preference values unless load-balancing is intentional.",
            )
        )

    want_ptr_rec = False
    want_starttls_rec = False

    for row in data.mx_hosts:
        if mx_cfg.check_ptr and row.ptr_matches is False:
            want_ptr_rec = True
            ptr_desc = issue_descriptor(MXIssueId.PTR_MISSING)
            issues.append(
                Issue(
                    id=MXIssueId.PTR_MISSING,
                    severity=ptr_desc.severity,
                    title="PTR missing or does not match MX host",
                    description=(
                        f"MX host {row.hostname!r} (priority {row.priority}): "
                        f"forward-confirmed reverse DNS check failed."
                    ),
                    remediation="Publish a PTR record for the sending IP that matches this MX hostname.",
                )
            )

        if mx_cfg.check_starttls and row.starttls_supported is False:
            err = row.starttls_error
            if _starttls_error_is_not_supported(err):
                want_starttls_rec = True
                ns_desc = issue_descriptor(MXIssueId.STARTTLS_NOT_SUPPORTED)
                issues.append(
                    Issue(
                        id=MXIssueId.STARTTLS_NOT_SUPPORTED,
                        severity=ns_desc.severity,
                        title="SMTP STARTTLS not available",
                        description=(
                            f"MX host {row.hostname!r} (priority {row.priority}): "
                            f"{err or 'STARTTLS not supported'}."
                        ),
                        remediation="Enable STARTTLS on the mail server (port 25).",
                    )
                )
            else:
                want_starttls_rec = True
                fl_desc = issue_descriptor(MXIssueId.STARTTLS_FAILED)
                issues.append(
                    Issue(
                        id=MXIssueId.STARTTLS_FAILED,
                        severity=fl_desc.severity,
                        title="SMTP STARTTLS probe failed",
                        description=(
                            f"MX host {row.hostname!r} (priority {row.priority}): "
                            f"{err or 'connection or TLS error'}."
                        ),
                        remediation="Fix connectivity or TLS configuration for SMTP on port 25.",
                    )
                )

    if want_ptr_rec:
        recommendations.append(
            Recommendation(
                id=MXRecommendationId.ADD_PTR,
                title="Add matching PTR records",
                description="Ensure each MX host's IP reverse-resolves to that hostname.",
            )
        )

    if want_starttls_rec:
        recommendations.append(
            Recommendation(
                id=MXRecommendationId.ENABLE_STARTTLS,
                title="Enable SMTP STARTTLS",
                description="Advertise and accept STARTTLS on port 25 for inbound mail.",
            )
        )

    return issues, recommendations
