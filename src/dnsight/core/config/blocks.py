"""Pydantic config blocks: resolver, throttle, per-check slices, and root Config."""

from __future__ import annotations

from pydantic import Field

import dnsight.core.config.defaults as defaults
from dnsight.core.config.mergeable import MergeableConfig
from dnsight.core.schema import (
    CaaSchema,
    DkimSchema,
    DmarcSchema,
    DnssecSchema,
    HeadersSchema,
    MxSchema,
    SpfSchema,
)
from dnsight.core.types import DNSProvider


__all__ = [
    "CaaConfig",
    "Config",
    "DkimConfig",
    "DmarcConfig",
    "DnssecConfig",
    "HeadersConfig",
    "MxConfig",
    "ResolverConfig",
    "SpfConfig",
    "ThrottleConfig",
]


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
    expected_rua: DmarcSchema.ReportingURIsList = Field(
        default_factory=list,
        description=(
            "When non-empty, the DMARC record rua= URIs must match this set exactly "
            "(after normalization). Used by generate and check."
        ),
    )
    expected_ruf: DmarcSchema.ReportingURIsList = Field(
        default_factory=list,
        description=(
            "When non-empty, the DMARC record ruf= URIs must match this set exactly "
            "(after normalization). Used by generate and check."
        ),
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


class DkimConfig(MergeableConfig):
    """DKIM selector and validation policy."""

    selectors: DkimSchema.SelectorsList = Field(
        default_factory=list,
        description="Selectors to try first; common defaults are merged after.",
    )
    min_key_bits: DkimSchema.MinKeyBitsInt = Field(
        default=defaults.DEFAULT_DKIM_MIN_KEY_BITS,
        description="Minimum RSA public key size in bits (when measurable).",
    )
    disallowed_algorithms: DkimSchema.DisallowedAlgorithmsList = Field(
        default_factory=list,
        description="k= or hash algorithm tokens that trigger a weak-algorithm issue.",
    )


class SpfConfig(MergeableConfig):
    """SPF validation and generation defaults."""

    required_disposition: SpfSchema.RequiredDispositionLiteral = Field(
        default=defaults.DEFAULT_SPF_REQUIRED_DISPOSITION,
        description="Required terminal policy: usually -all (hard fail).",
    )
    lookup_limit: SpfSchema.LookupLimitInt = Field(
        default=defaults.DEFAULT_SPF_LOOKUP_LIMIT,
        description="Maximum DNS lookups during SPF evaluation (RFC 7208: 10).",
    )
    max_includes: int | None = Field(
        default=defaults.DEFAULT_SPF_MAX_INCLUDES,
        description=(
            "Optional cap on expanded include traversals (each include: followed in flatten)."
        ),
    )
    allow_redirect: bool = Field(
        default=defaults.DEFAULT_SPF_ALLOW_REDIRECT,
        description="If False, redirect= triggers an issue.",
    )


class HeadersConfig(MergeableConfig):
    """HTTP security headers probe and validation."""

    require: HeadersSchema.RequireList = Field(
        default_factory=lambda: list(defaults.DEFAULT_HEADERS_REQUIRE),
        description="Required header tokens (HSTS, CSP, X-Frame-Options, etc.).",
    )
    urls: HeadersSchema.UrlsList = Field(
        default_factory=list,
        description="URLs to GET; when empty, probes https://<domain> and https://www.<domain>.",
    )


class MxConfig(MergeableConfig):
    """MX validation: optional PTR and SMTP STARTTLS probes."""

    check_ptr: MxSchema.CheckPtrBool = Field(
        default=defaults.DEFAULT_MX_CHECK_PTR,
        description="If True, resolve A and PTR for each MX hostname and verify FCrDNS match.",
    )
    check_starttls: MxSchema.CheckStarttlsBool = Field(
        default=defaults.DEFAULT_MX_CHECK_STARTTLS,
        description="If True, probe port 25 for STARTTLS support.",
    )
    starttls_timeout_seconds: MxSchema.StarttlsTimeoutSeconds = Field(
        default=defaults.DEFAULT_MX_STARTTLS_TIMEOUT_SECONDS,
        description="Timeout for TCP connect and SMTP read phases during STARTTLS probe.",
    )


class CaaConfig(MergeableConfig):
    """CAA validation and generation: per-name checks, issuer policy, optional crt.sh."""

    require_caa: bool = Field(
        default=defaults.DEFAULT_CAA_REQUIRE_CAA,
        description="If True, require effective CAA with issue/issuewild tags.",
    )
    required_issuers: CaaSchema.RequiredIssuersList = Field(
        default_factory=list,
        description="Each CA issuer domain must appear in an effective issue tag for that name.",
    )
    check_issuewild: bool = Field(
        default=defaults.DEFAULT_CAA_CHECK_ISSUEWILD,
        description="If True, validate issuewild vs issue consistency.",
    )
    restrict_wildcard_issuance: bool = Field(
        default=defaults.DEFAULT_CAA_RESTRICT_WILDCARD_ISSUANCE,
        description="If True, wildcard issuance must be restricted via issuewild (issuewild ';' or subset of issue).",
    )
    cross_reference_crt_sh: bool = Field(
        default=defaults.DEFAULT_CAA_CROSS_REFERENCE_CRT_SH,
        description="If True, query crt.sh and flag certs whose issuers are not allowed by CAA.",
    )
    names: CaaSchema.NamesList = Field(
        default_factory=list,
        description="Extra hostnames (FQDN or single label under the audited zone) to check.",
    )
    enumerate_names: bool = Field(
        default=defaults.DEFAULT_CAA_ENUMERATE_NAMES,
        description="If True, discover names via A/AAAA/CNAME (and optional DNAME) walk.",
    )
    max_enumeration_depth: CaaSchema.MaxEnumerationDepthInt = Field(
        default=defaults.DEFAULT_CAA_MAX_ENUMERATION_DEPTH,
        description="Max depth when following CNAME/DNAME during enumeration.",
    )
    max_names: CaaSchema.MaxNamesInt = Field(
        default=defaults.DEFAULT_CAA_MAX_NAMES,
        description="Max distinct names to enumerate and check.",
    )
    include_www: bool = Field(
        default=defaults.DEFAULT_CAA_INCLUDE_WWW,
        description="Seed www.<zone> in addition to the zone apex.",
    )
    include_mx_targets: bool = Field(
        default=defaults.DEFAULT_CAA_INCLUDE_MX_TARGETS,
        description="Include MX exchange hostnames in discovered names.",
    )
    include_srv_targets: bool = Field(
        default=defaults.DEFAULT_CAA_INCLUDE_SRV_TARGETS,
        description="Include SRV targets from _service._proto names under the zone.",
    )
    enumerate_dname: bool = Field(
        default=defaults.DEFAULT_CAA_ENUMERATE_DNAME,
        description="If True, follow DNAME targets during enumeration.",
    )
    reporting_email: str | None = Field(
        default=None, description="If set, GENERATE may emit an iodef mailto: CAA line."
    )


class DnssecConfig(MergeableConfig):
    """DNSSEC chain and negative-response validation."""

    require_ds: bool = Field(
        default=defaults.DEFAULT_DNSSEC_REQUIRE_DS,
        description="If True, missing DS at the parent delegation is CRITICAL.",
    )
    signature_expiry_days_warning: DnssecSchema.SignatureExpiryDaysWarningInt = Field(
        default=defaults.DEFAULT_DNSSEC_SIGNATURE_EXPIRY_DAYS_WARNING,
        description="Warn when an RRSIG expires within this many days.",
    )
    disallowed_algorithms: DnssecSchema.DisallowedAlgorithmsList = Field(
        default_factory=list,
        description="Algorithm numbers or names that trigger a weak-algorithm issue.",
    )
    validate_negative_responses: bool = Field(
        default=defaults.DEFAULT_DNSSEC_VALIDATE_NEGATIVE,
        description="If True, probe NXDOMAIN and verify NSEC/NSEC3 proofs.",
    )
    validate_nodata_proofs: bool = Field(
        default=defaults.DEFAULT_DNSSEC_VALIDATE_NODATA,
        description="If True, probe NODATA (empty type) and verify proofs.",
    )
    nxdomain_probe_label: str | None = Field(
        default=None,
        description=(
            "Optional leftmost label for NXDOMAIN probe (under the zone apex). "
            "If unset, a random label is used."
        ),
    )
    require_ns: bool = Field(
        default=defaults.DEFAULT_DNSSEC_REQUIRE_NS,
        description="If True, require at least one NS at the zone apex.",
    )
    nodata_probe_name: str | None = Field(
        default=None,
        description=(
            "FQDN under the zone for NODATA proof (must exist; queried type absent). "
            "If unset, uses www.<apex> when present."
        ),
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
    dkim: DkimConfig = Field(default=DkimConfig(), description="The DKIM config.")
    spf: SpfConfig = Field(default=SpfConfig(), description="The SPF config.")
    mx: MxConfig = Field(default=MxConfig(), description="The MX check config.")
    headers: HeadersConfig = Field(
        default_factory=HeadersConfig, description="HTTP security headers check config."
    )
    caa: CaaConfig = Field(default_factory=CaaConfig, description="CAA check config.")
    dnssec: DnssecConfig = Field(
        default_factory=DnssecConfig, description="DNSSEC check config."
    )
    strict_recommendations: bool = Field(
        default=defaults.DEFAULT_STRICT_RECOMMENDATIONS,
        description="If true, recommend strictest best practice; if false, recommend alignment to configured policy.",
    )
