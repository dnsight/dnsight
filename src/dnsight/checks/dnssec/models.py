"""DNSSEC check: issue/rec IDs, descriptors, and data models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from dnsight.checks.base import BaseCheckData
from dnsight.core.config.blocks import DnssecConfig
from dnsight.core.types import (
    IssueDescriptor,
    IssueId,
    RecommendationDescriptor,
    RecommendationId,
    Severity,
)


__all__ = [
    "DNSKEYRecord",
    "DNSSECData",
    "DNSSECIssueId",
    "DNSSECRecommendationId",
    "DSRecord",
    "NegativeValidationAttempt",
    "NodataValidationAttempt",
    "issue_descriptor",
    "recommendation_descriptor",
]


class DNSSECIssueId(IssueId):
    """Issue IDs for the DNSSEC check."""

    DS_MISSING = "dnssec.ds.missing"
    DNSKEY_MISSING = "dnssec.dnskey.missing"
    SIGNATURE_EXPIRED = "dnssec.signature.expired"
    SIGNATURE_NEAR_EXPIRY = "dnssec.signature.near_expiry"
    ALGORITHM_WEAK = "dnssec.algorithm.weak"
    CHAIN_MISMATCH = "dnssec.chain.mismatch"
    NO_RRSIG = "dnssec.no_rrsig"
    NSEC_INVALID = "dnssec.nsec.invalid"
    NSEC3_INVALID = "dnssec.nsec3.invalid"
    NEGATIVE_UNPROVEN = "dnssec.negative.unproven"
    NS_MISSING = "dnssec.ns.missing"


class DNSSECRecommendationId(RecommendationId):
    """Recommendation IDs for the DNSSEC check."""

    ENABLE = "dnssec.enable"
    ROTATE_ALGORITHM = "dnssec.rotate_algorithm"
    EXTEND_SIGNATURE = "dnssec.extend_signature"


_DNSSEC_ISSUE_DESCRIPTORS: dict[DNSSECIssueId, IssueDescriptor] = {
    DNSSECIssueId.DS_MISSING: IssueDescriptor(
        DNSSECIssueId.DS_MISSING, Severity.CRITICAL
    ),
    DNSSECIssueId.DNSKEY_MISSING: IssueDescriptor(
        DNSSECIssueId.DNSKEY_MISSING, Severity.CRITICAL
    ),
    DNSSECIssueId.SIGNATURE_EXPIRED: IssueDescriptor(
        DNSSECIssueId.SIGNATURE_EXPIRED, Severity.HIGH
    ),
    DNSSECIssueId.SIGNATURE_NEAR_EXPIRY: IssueDescriptor(
        DNSSECIssueId.SIGNATURE_NEAR_EXPIRY, Severity.MEDIUM
    ),
    DNSSECIssueId.ALGORITHM_WEAK: IssueDescriptor(
        DNSSECIssueId.ALGORITHM_WEAK, Severity.MEDIUM
    ),
    DNSSECIssueId.CHAIN_MISMATCH: IssueDescriptor(
        DNSSECIssueId.CHAIN_MISMATCH, Severity.CRITICAL
    ),
    DNSSECIssueId.NO_RRSIG: IssueDescriptor(DNSSECIssueId.NO_RRSIG, Severity.HIGH),
    DNSSECIssueId.NSEC_INVALID: IssueDescriptor(
        DNSSECIssueId.NSEC_INVALID, Severity.HIGH
    ),
    DNSSECIssueId.NSEC3_INVALID: IssueDescriptor(
        DNSSECIssueId.NSEC3_INVALID, Severity.HIGH
    ),
    DNSSECIssueId.NEGATIVE_UNPROVEN: IssueDescriptor(
        DNSSECIssueId.NEGATIVE_UNPROVEN, Severity.HIGH
    ),
    DNSSECIssueId.NS_MISSING: IssueDescriptor(DNSSECIssueId.NS_MISSING, Severity.HIGH),
}

_DNSSEC_REC_DESCRIPTORS: dict[DNSSECRecommendationId, RecommendationDescriptor] = {
    DNSSECRecommendationId.ENABLE: RecommendationDescriptor(
        DNSSECRecommendationId.ENABLE
    ),
    DNSSECRecommendationId.ROTATE_ALGORITHM: RecommendationDescriptor(
        DNSSECRecommendationId.ROTATE_ALGORITHM
    ),
    DNSSECRecommendationId.EXTEND_SIGNATURE: RecommendationDescriptor(
        DNSSECRecommendationId.EXTEND_SIGNATURE
    ),
}


def issue_descriptor(member_or_id: DNSSECIssueId | str) -> IssueDescriptor:
    """Return the descriptor for an issue enum member or raw id string."""
    if isinstance(member_or_id, DNSSECIssueId):
        return _DNSSEC_ISSUE_DESCRIPTORS[member_or_id]
    for _member, desc in _DNSSEC_ISSUE_DESCRIPTORS.items():
        if desc.id.value == member_or_id:
            return desc
    raise KeyError(member_or_id)


def recommendation_descriptor(
    member_or_id: DNSSECRecommendationId | str,
) -> RecommendationDescriptor:
    """Return the descriptor for a recommendation enum member or raw id."""
    if isinstance(member_or_id, DNSSECRecommendationId):
        return _DNSSEC_REC_DESCRIPTORS[member_or_id]
    for _member, desc in _DNSSEC_REC_DESCRIPTORS.items():
        if desc.id.value == member_or_id:
            return desc
    raise KeyError(member_or_id)


class DSRecord(BaseModel):
    """Delegation signer record at the parent (RFC 4034)."""

    model_config = ConfigDict(frozen=True)

    key_tag: int
    algorithm: int
    digest_type: int
    digest_hex: str


class DNSKEYRecord(BaseModel):
    """DNSKEY at the zone apex."""

    model_config = ConfigDict(frozen=True)

    flags: int
    protocol: int
    algorithm: int
    public_key_b64: str


class NegativeValidationAttempt(BaseModel):
    """NXDOMAIN proof probe result."""

    model_config = ConfigDict(frozen=True)

    query_name: str
    query_type: str
    rcode: int | None = None
    proof_ok: bool | None = None
    detail: str | None = None


class NodataValidationAttempt(BaseModel):
    """NODATA proof probe result."""

    model_config = ConfigDict(frozen=True)

    query_name: str
    query_type: str
    proof_ok: bool | None = None
    detail: str | None = None


class DNSSECData(BaseCheckData):
    """Observed DNSSEC material for a zone apex."""

    ds_records: list[DSRecord] = Field(default_factory=list)
    dnskey_records: list[DNSKEYRecord] = Field(default_factory=list)
    ns_hostnames: list[str] = Field(default_factory=list)
    chain_valid: bool = False
    ad_flag_dnskey: bool | None = None
    earliest_signature_expiration_posix: float | None = None
    negative_attempt: NegativeValidationAttempt | None = None
    nodata_attempt: NodataValidationAttempt | None = None


def extract_dnssec_config(config: object | None) -> DnssecConfig:
    """Return DnssecConfig from full Config or bare DnssecConfig."""
    if config is None:
        return DnssecConfig()
    if isinstance(config, DnssecConfig):
        return config
    return getattr(config, "dnssec", DnssecConfig())
