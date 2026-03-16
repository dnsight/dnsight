"""Pydantic config blocks: resolver, throttle, DMARC, and root Config."""

from __future__ import annotations

from pydantic import Field

import dnsight.core.config.defaults as defaults
from dnsight.core.config.mergeable import MergeableConfig
from dnsight.core.schema import DmarcSchema
from dnsight.core.types import DNSProvider


__all__ = ["Config", "DmarcConfig", "ResolverConfig", "ThrottleConfig"]


class ResolverConfig(MergeableConfig):
    """DNS resolver config.

    Choose a well-known provider preset.  ``"system"`` (the default)
    uses whatever the OS is configured with.
    """

    provider: DNSProvider = Field(
        default=DNSProvider(defaults.DEFAULT_DNS_PROVIDER),
        description="DNS provider preset: system, google, cloudflare, quad9, or opendns.",
    )

    def resolved_nameservers(self) -> list[str] | None:
        """Return the concrete nameserver IPs for this config.

        Returns:
            A list of IP strings for named providers, or ``None`` for
            ``"system"`` (meaning use OS defaults).
        """
        if self.provider == DNSProvider.SYSTEM:
            return None
        return defaults.DNS_PROVIDER_NAMESERVERS.get(self.provider, None)


class ThrottleConfig(MergeableConfig):
    """Throttle limits config."""

    global_max_rps: float = Field(
        default=defaults.DEFAULT_GLOBAL_MAX_RPS,
        description="The maximum number of requests per second for the global scope.",
    )
    global_max_concurrency: int = Field(
        default=defaults.DEFAULT_GLOBAL_CONCURRENCY_LIMIT,
        description="The maximum number of concurrent requests for the global scope.",
    )


class DmarcConfig(MergeableConfig):
    """DMARC policy and validation config.

    policy is the minimum required policy (validation passes when actual >= this).
    target_policy is used for recommendations when strict_recommendations is False.
    """

    policy: DmarcSchema.PolicyStr = Field(
        default=defaults.DEFAULT_DMARC_POLICY,
        description="Minimum required policy (none < quarantine < reject). Validation passes when actual >= this.",
    )
    target_policy: str | None = Field(
        default=defaults.DEFAULT_DMARC_TARGET_POLICY,
        description=(
            "Target policy for recommendations when strict_recommendations is False. "
            "If None, no policy-strength recommendations beyond the minimum policy."
        ),
    )
    rua_required: bool = Field(
        default=defaults.DEFAULT_DMARC_RUA_REQUIRED,
        description="Whether to require at least one rua (aggregate reporting).",
    )
    ruf_required: bool = Field(
        default=defaults.DEFAULT_DMARC_RUF_REQUIRED,
        description="Whether to require at least one ruf (forensic reporting).",
    )
    minimum_pct: DmarcSchema.PercentageInt = Field(
        default=defaults.DEFAULT_DMARC_MINIMUM_PCT,
        description="Minimum acceptable pct (0-100). Issue when data.percentage < this.",
    )
    require_strict_alignment: DmarcSchema.AlignmentStrictnessBool = Field(
        default=defaults.DEFAULT_DMARC_REQUIRE_STRICT_ALIGNMENT,
        description="If True, issue when adkim or aspf is relaxed (r); recommend strict (s).",
    )
    alignment_dkim: DmarcSchema.AlignmentStr = Field(
        default="r", description="adkim= value: r or s"
    )
    alignment_spf: DmarcSchema.AlignmentStr = Field(
        default="r", description="aspf= value: r or s"
    )
    subdomain_policy_minimum: DmarcSchema.SubdomainPolicyStr = Field(
        default=None,
        description="If set, subdomain policy (sp) must be >= this. None = no check.",
    )


class Config(MergeableConfig):
    """Root config."""

    resolver: ResolverConfig = Field(
        default=ResolverConfig(), description="DNS resolver config."
    )
    throttle: ThrottleConfig = Field(
        default=ThrottleConfig(), description="The throttle config."
    )
    dmarc: DmarcConfig = Field(default=DmarcConfig(), description="The DMARC config.")
    strict_recommendations: bool = Field(
        default=defaults.DEFAULT_STRICT_RECOMMENDATIONS,
        description="If true, recommend strictest best practice; if false, recommend alignment to configured policy.",
    )
