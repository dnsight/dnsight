"""DNSSEC check: validation rules."""

from __future__ import annotations

import base64
import contextlib
import logging
import secrets
import time

import dns.dnssec
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from dnsight.checks.dnssec.models import (
    DNSKEYRecord,
    DNSSECData,
    DNSSECIssueId,
    DNSSECRecommendationId,
    DSRecord,
    NegativeValidationAttempt,
    NodataValidationAttempt,
    issue_descriptor,
    recommendation_descriptor,
)
from dnsight.core.config.blocks import DnssecConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.models import Issue, Recommendation
from dnsight.utils.dns import DNSKEYDict, DNSResolver
from dnsight.utils.dnssec_support import (
    ds_matches_published,
    earliest_rrsig_expiration,
    is_ksk_flags,
    rrsig_expired_or_near,
    to_dnskey_rdata,
    validate_nsec_negative_proof,
    validate_signed_rrset_in_message,
)


__all__: list[str] = []

logger = logging.getLogger(__name__)


def _apex_name(domain: str) -> str:
    return domain.strip().rstrip(".")


def _dnskey_rrset_from_answer(msg: dns.message.Message) -> dns.rrset.RRset | None:
    for rrset in msg.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            return rrset
    return None


def _algorithm_flagged(alg: int, disallowed: list[str]) -> bool:
    try:
        txt = dns.dnssec.algorithm_to_text(alg).upper().replace("-", "")
    except Exception:
        txt = ""
    s = str(alg)
    for d in disallowed:
        d_norm = d.strip().upper().replace("-", "")
        if d_norm == s or (txt and d_norm == txt):
            return True
    return False


def _classify_negative_failure(
    msg: dns.message.Message, detail: str | None
) -> DNSSECIssueId:
    d = detail or ""
    has_nsec3 = any(rs.rdtype == dns.rdatatype.NSEC3 for rs in msg.authority)
    has_nsec = any(rs.rdtype == dns.rdatatype.NSEC for rs in msg.authority)
    if has_nsec3 and ("NSEC3" in d or "nsec3" in d.lower()):
        return DNSSECIssueId.NSEC3_INVALID
    if has_nsec and "NSEC" in d:
        return DNSSECIssueId.NSEC_INVALID
    if has_nsec3:
        return DNSSECIssueId.NSEC3_INVALID
    if has_nsec:
        return DNSSECIssueId.NSEC_INVALID
    return DNSSECIssueId.NEGATIVE_UNPROVEN


async def collect_dnssec_data(  # NOSONAR S3776
    domain: str, resolver: DNSResolver, cfg: DnssecConfig
) -> tuple[
    DNSSECData,
    dns.message.Message | None,
    dns.message.Message | None,
    dns.message.Message | None,
]:
    """Fetch DS, DNSKEY, NS, and DNSSEC query results for *domain* apex.

    Returns:
        Parsed data, DNSKEY message, NS message, and NXDOMAIN probe message (if any).
    """
    apex = _apex_name(domain)
    zone_name = dns.name.from_text(apex, dns.name.root)

    ds_raw: list[tuple[int, int, int, bytes]] = []
    with contextlib.suppress(CheckError):
        ds_raw = await resolver.resolve_ds(apex)

    dnskey_raw: list[DNSKEYDict] = []
    with contextlib.suppress(CheckError):
        dnskey_raw = await resolver.resolve_dnskey(apex)

    ns_hostnames: list[str] = []
    with contextlib.suppress(CheckError):
        ns_hostnames = await resolver.resolve_ns(apex)

    dk_msg: dns.message.Message | None = None
    ad_flag: bool | None = None
    try:
        dk_q = await resolver.query_dnssec(apex, "DNSKEY")
        dk_msg = dk_q.message
        ad_flag = dk_q.ad
    except CheckError:
        # Expected failure for some zones; continue without DNSKEY message / AD flag.
        logger.debug(
            "DNSSEC DNSKEY query failed for %s; proceeding without AD flag", apex
        )

    ns_msg: dns.message.Message | None = None
    try:
        ns_q = await resolver.query_dnssec(apex, "NS")
        ns_msg = ns_q.message
    except CheckError as exc:
        # Expected failure for some zones; proceed without NS DNSSEC message.
        logger.debug(
            "DNSSEC NS query failed for %s; proceeding without NS DNSSEC data: %s",
            apex,
            exc,
        )

    neg: NegativeValidationAttempt | None = None
    nod: NodataValidationAttempt | None = None
    nx_msg: dns.message.Message | None = None

    dnskey_rrset = _dnskey_rrset_from_answer(dk_msg) if dk_msg else None

    if cfg.validate_negative_responses and dnskey_rrset is not None:
        label = cfg.nxdomain_probe_label or f"nx-{secrets.token_hex(8)}"
        probe_fqdn = f"{label}.{apex}"
        try:
            nx_q = await resolver.query_dnssec(probe_fqdn, "A")
            nx_msg = nx_q.message
            probe_name = dns.name.from_text(probe_fqdn, dns.name.root)
            ok, detail = validate_nsec_negative_proof(
                nx_msg, zone_name, probe_name, dnskey_rrset, nodata_type=None
            )
            neg = NegativeValidationAttempt(
                query_name=probe_fqdn,
                query_type="A",
                rcode=nx_msg.rcode(),
                proof_ok=ok,
                detail=detail,
            )
        except CheckError as exc:
            neg = NegativeValidationAttempt(
                query_name=probe_fqdn,
                query_type="A",
                rcode=None,
                proof_ok=False,
                detail=str(exc),
            )

    if cfg.validate_nodata_proofs and dnskey_rrset is not None:
        target = cfg.nodata_probe_name or f"www.{apex}"
        try:
            nd_q = await resolver.query_dnssec(target, "TXT")
            nd_msg = nd_q.message
            if nd_msg.rcode() == dns.rcode.NOERROR and not nd_msg.answer:
                ok, detail = validate_nsec_negative_proof(
                    nd_msg,
                    zone_name,
                    dns.name.from_text(target, dns.name.root),
                    dnskey_rrset,
                    nodata_type=dns.rdatatype.TXT,
                )
                nod = NodataValidationAttempt(
                    query_name=target, query_type="TXT", proof_ok=ok, detail=detail
                )
            else:
                nod = NodataValidationAttempt(
                    query_name=target,
                    query_type="TXT",
                    proof_ok=None,
                    detail="answer not empty or not NOERROR; skipped NODATA proof",
                )
        except CheckError as exc:
            nod = NodataValidationAttempt(
                query_name=target, query_type="TXT", proof_ok=False, detail=str(exc)
            )

    ds_models = [
        DSRecord(key_tag=t[0], algorithm=t[1], digest_type=t[2], digest_hex=t[3].hex())
        for t in ds_raw
    ]
    dk_models = [
        DNSKEYRecord(
            flags=d["flags"],
            protocol=d["protocol"],
            algorithm=d["algorithm"],
            public_key_b64=base64.b64encode(d["key"]).decode("ascii"),
        )
        for d in dnskey_raw
    ]

    chain_valid = False
    ksks = [to_dnskey_rdata(d) for d in dnskey_raw if is_ksk_flags(d["flags"])]
    if ds_raw and ksks:
        for ds_t in ds_raw:
            for ksk in ksks:
                if ds_matches_published(zone_name, ds_t, ksk):
                    chain_valid = True
                    break
            if chain_valid:
                break

    exp: float | None = None
    if dk_msg:
        exp = earliest_rrsig_expiration(dk_msg, dns.rdatatype.DNSKEY)

    data = DNSSECData(
        ds_records=ds_models,
        dnskey_records=dk_models,
        ns_hostnames=ns_hostnames,
        chain_valid=chain_valid,
        ad_flag_dnskey=ad_flag,
        earliest_signature_expiration_posix=exp,
        negative_attempt=neg,
        nodata_attempt=nod,
    )
    return data, dk_msg, ns_msg, nx_msg


def validate_dnssec_results(  # NOSONAR S3776
    data: DNSSECData,
    cfg: DnssecConfig,
    zone_name: dns.name.Name,
    dk_msg: dns.message.Message | None,
    ns_msg: dns.message.Message | None,
    nx_msg: dns.message.Message | None = None,
) -> tuple[list[Issue], list[Recommendation]]:
    """Build issues and recommendations from collected DNSSEC data."""
    issues: list[Issue] = []
    recs: list[Recommendation] = []
    now = time.time()
    warn_sec = float(cfg.signature_expiry_days_warning) * 86400.0

    if cfg.require_ds and not data.ds_records:
        desc = issue_descriptor(DNSSECIssueId.DS_MISSING)
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="DS record missing at parent",
                description=(
                    "No DS records were found for this zone at the delegation point. "
                    "DNSSEC is not delegated from the parent."
                ),
                remediation="Publish DS records at the parent zone for your KSK.",
            )
        )

    if not data.dnskey_records:
        desc = issue_descriptor(DNSSECIssueId.DNSKEY_MISSING)
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="DNSKEY missing at zone apex",
                description="No DNSKEY records were returned for the zone apex.",
                remediation="Publish DNSKEY records for the zone and sign the zone.",
            )
        )

    if data.ds_records and data.dnskey_records and not data.chain_valid:
        desc = issue_descriptor(DNSSECIssueId.CHAIN_MISMATCH)
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="DS does not match any KSK",
                description=(
                    "No published DS digest matches a derived digest from any KSK DNSKEY."
                ),
                remediation="Align DS at the parent with the zone KSK DNSKEY.",
            )
        )

    for ds in data.ds_records:
        if _algorithm_flagged(ds.algorithm, list(cfg.disallowed_algorithms)):
            desc = issue_descriptor(DNSSECIssueId.ALGORITHM_WEAK)
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="Weak DS algorithm",
                    description=f"DS record uses algorithm {ds.algorithm}.",
                    remediation="Use a stronger algorithm per your DNS operator policy.",
                )
            )
            break

    for dk in data.dnskey_records:
        if _algorithm_flagged(dk.algorithm, list(cfg.disallowed_algorithms)):
            desc = issue_descriptor(DNSSECIssueId.ALGORITHM_WEAK)
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="Weak DNSKEY algorithm",
                    description=f"DNSKEY uses algorithm {dk.algorithm}.",
                    remediation="Rotate to a stronger DNSKEY algorithm.",
                )
            )
            break

    dnskey_rrset = _dnskey_rrset_from_answer(dk_msg) if dk_msg else None
    if dk_msg and dnskey_rrset:
        ok, err = validate_signed_rrset_in_message(
            dk_msg, 0, zone_name, dns.rdatatype.DNSKEY, dnskey_rrset
        )
        if not ok:
            desc = issue_descriptor(DNSSECIssueId.NO_RRSIG)
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="DNSKEY RRset is not DNSSEC-valid",
                    description=err or "RRSIG validation failed for DNSKEY.",
                    remediation="Ensure the zone is signed and RRSIGs are published.",
                )
            )
        exp_dk, near_dk = rrsig_expired_or_near(
            dk_msg, dns.rdatatype.DNSKEY, now, warn_sec
        )
        if exp_dk:
            desc = issue_descriptor(DNSSECIssueId.SIGNATURE_EXPIRED)
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="DNSKEY RRSIG expired",
                    description="At least one RRSIG covering DNSKEY is past its expiration.",
                    remediation="Re-sign the zone or refresh signatures.",
                )
            )
        elif near_dk:
            desc = issue_descriptor(DNSSECIssueId.SIGNATURE_NEAR_EXPIRY)
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="DNSKEY RRSIG near expiry",
                    description=(
                        f"An RRSIG expires within {cfg.signature_expiry_days_warning} days."
                    ),
                    remediation="Re-sign the zone before signatures expire.",
                )
            )
            rdesc = recommendation_descriptor(DNSSECRecommendationId.EXTEND_SIGNATURE)
            recs.append(
                Recommendation(
                    id=rdesc.id.value,
                    title="Extend DNSKEY signature lifetime",
                    description="Increase signature validity or refresh signing automation.",
                )
            )

    if ns_msg:
        ns_rrset: dns.rrset.RRset | None = None
        for rrset in ns_msg.answer:
            if rrset.rdtype == dns.rdatatype.NS:
                ns_rrset = rrset
                break
        if ns_rrset and dnskey_rrset:
            ok, err = validate_signed_rrset_in_message(
                ns_msg, 0, zone_name, dns.rdatatype.NS, dnskey_rrset
            )
            if not ok:
                desc = issue_descriptor(DNSSECIssueId.NO_RRSIG)
                issues.append(
                    Issue(
                        id=desc.id.value,
                        severity=desc.severity,
                        title="NS RRset is not DNSSEC-valid",
                        description=err or "RRSIG validation failed for NS.",
                        remediation="Ensure NS is signed consistently with the zone keys.",
                    )
                )
            exp_ns, near_ns = rrsig_expired_or_near(
                ns_msg, dns.rdatatype.NS, now, warn_sec
            )
            if exp_ns:
                desc = issue_descriptor(DNSSECIssueId.SIGNATURE_EXPIRED)
                issues.append(
                    Issue(
                        id=desc.id.value,
                        severity=desc.severity,
                        title="NS RRSIG expired",
                        description="At least one RRSIG covering NS is past its expiration.",
                        remediation="Re-sign the zone.",
                    )
                )
            elif near_ns:
                desc = issue_descriptor(DNSSECIssueId.SIGNATURE_NEAR_EXPIRY)
                issues.append(
                    Issue(
                        id=desc.id.value,
                        severity=desc.severity,
                        title="NS RRSIG near expiry",
                        description=(
                            f"An NS RRSIG expires within {cfg.signature_expiry_days_warning} days."
                        ),
                        remediation="Re-sign the zone before signatures expire.",
                    )
                )

    if cfg.require_ns and not data.ns_hostnames:
        desc = issue_descriptor(DNSSECIssueId.NS_MISSING)
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="NS records missing",
                description="No NS records were found at the zone apex.",
                remediation="Publish NS records for the zone.",
            )
        )

    if data.negative_attempt and data.negative_attempt.proof_ok is False:
        msg = nx_msg
        if msg is None:
            iid = DNSSECIssueId.NEGATIVE_UNPROVEN
        else:
            iid = _classify_negative_failure(msg, data.negative_attempt.detail)
        desc = issue_descriptor(iid)
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="NXDOMAIN negative proof failed",
                description=data.negative_attempt.detail or "Proof validation failed.",
                remediation="Ensure NSEC/NSEC3 proofs and RRSIGs are correct for the zone.",
            )
        )

    if (
        data.nodata_attempt
        and data.nodata_attempt.proof_ok is False
        and data.nodata_attempt.detail
        and "skipped" not in data.nodata_attempt.detail
    ):
        desc = issue_descriptor(DNSSECIssueId.NEGATIVE_UNPROVEN)
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="NODATA negative proof failed",
                description=data.nodata_attempt.detail,
                remediation="Ensure NSEC proofs cover NODATA for the probed name and type.",
            )
        )

    if not data.ds_records and not data.dnskey_records:
        rdesc = recommendation_descriptor(DNSSECRecommendationId.ENABLE)
        recs.append(
            Recommendation(
                id=rdesc.id.value,
                title="Enable DNSSEC",
                description="No DS or DNSKEY found; consider DNSSEC signing for the zone.",
            )
        )

    weak_alg_issue = any(i.id == DNSSECIssueId.ALGORITHM_WEAK.value for i in issues)
    if weak_alg_issue:
        rdesc = recommendation_descriptor(DNSSECRecommendationId.ROTATE_ALGORITHM)
        recs.append(
            Recommendation(
                id=rdesc.id.value,
                title="Rotate to a stronger algorithm",
                description="Prefer algorithms recommended by RFC 8624.",
            )
        )

    return issues, recs
