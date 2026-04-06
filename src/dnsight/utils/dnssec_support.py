"""DNSSEC validation helpers using dnspython (cryptography-backed).

Used by the DNSSEC check; keeps ``dns.dnssec`` usage out of ``checks/``.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from typing import cast

import dns.dnssec
from dns.exception import ValidationFailure
import dns.message
import dns.name
import dns.node
import dns.rcode
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.NSEC import NSEC
from dns.rdtypes.ANY.NSEC3 import NSEC3
from dns.rdtypes.ANY.RRSIG import RRSIG
from dns.rdtypes.util import Bitmap
import dns.rrset

from dnsight.utils.dns import DNSKEYDict


_B32_NORMAL_TO_HEX = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", b"0123456789ABCDEFGHIJKLMNOPQRSTUV"
)

__all__ = [
    "bitmap_has_rdtype",
    "digest_type_to_dsdigest_name",
    "ds_matches_published",
    "earliest_rrsig_expiration",
    "is_ksk_flags",
    "nsec3_hash_covers_query",
    "nsec_covers_name",
    "rrsig_expired_or_near",
    "to_dnskey_rdata",
    "validate_nsec_negative_proof",
    "validate_signed_rrset_in_message",
]


def to_dnskey_rdata(d: DNSKEYDict) -> DNSKEY:
    """Build a DNSKEY rdata from resolver-shaped dict."""
    return DNSKEY(  # type: ignore[no-untyped-call]
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        d["flags"],
        d["protocol"],
        d["algorithm"],
        d["key"],
    )


def is_ksk_flags(flags: int) -> bool:
    """Return True if flags indicate a KSK (ZONE + SEP)."""
    import dns.rdtypes.dnskeybase as kb

    f = kb.Flag(flags & 0xFFFF)
    return kb.Flag.ZONE in f and kb.Flag.SEP in f


def digest_type_to_dsdigest_name(digest_type: int) -> str | None:
    """Map DS digest type integer to name accepted by :func:`dns.dnssec.make_ds`."""
    mapping: dict[int, str] = {1: "SHA1", 2: "SHA256", 4: "SHA384"}
    return mapping.get(digest_type)


def ds_matches_published(
    zone_name: dns.name.Name, ds_tuple: tuple[int, int, int, bytes], ksk: DNSKEY
) -> bool:
    """Return True if a published DS matches the digest derived from *ksk*."""
    _key_tag, _alg, digest_type, digest = ds_tuple
    name = digest_type_to_dsdigest_name(digest_type)
    if name is None:
        return False
    try:
        ds = dns.dnssec.make_ds(zone_name, ksk, name)
    except (dns.exception.DNSException, ValueError, TypeError):
        return False
    return ds.digest == digest and ds.key_tag == dns.dnssec.key_id(ksk)


def _keys_dict(dnskey_rrset: dns.rrset.RRset) -> dict[dns.name.Name, dns.rrset.RRset]:
    return {dnskey_rrset.name.canonicalize(): dnskey_rrset}


def validate_signed_rrset_in_message(
    msg: dns.message.Message,
    section: int,
    origin: dns.name.Name,
    cover_rdtype: dns.rdatatype.RdataType,
    dnskey_rrset: dns.rrset.RRset,
) -> tuple[bool, str | None]:
    """Validate RRSIG over an RRset of *cover_rdtype* in *section* using *dnskey_rrset*."""
    keys = _keys_dict(dnskey_rrset)
    target_rrset: dns.rrset.RRset | None = None
    rrsig_rrset: dns.rrset.RRset | None = None

    for rrset in msg.sections[section]:
        if rrset.rdtype == cover_rdtype:
            target_rrset = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            for rrsig in rrset:
                if isinstance(rrsig, RRSIG) and rrsig.type_covered == cover_rdtype:
                    rrsig_rrset = rrset
                    break

    if target_rrset is None:
        return False, f"no {dns.rdatatype.to_text(cover_rdtype)} rrset in response"
    if rrsig_rrset is None:
        return False, "no covering RRSIG"

    try:
        dns.dnssec.validate(
            target_rrset,
            rrsig_rrset,
            cast(dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset], keys),
            origin=origin,
        )
    except (ValidationFailure, dns.exception.UnsupportedAlgorithm) as exc:
        return False, str(exc)
    return True, None


def earliest_rrsig_expiration(
    msg: dns.message.Message, cover_rdtype: dns.rdatatype.RdataType
) -> float | None:
    """Earliest RRSIG expiration (POSIX) for signatures covering *cover_rdtype*."""
    best: float | None = None
    for rrset in msg.answer + msg.authority + msg.additional:
        if rrset.rdtype != dns.rdatatype.RRSIG:
            continue
        for rrsig in rrset:
            if isinstance(rrsig, RRSIG) and rrsig.type_covered == cover_rdtype:
                exp = float(rrsig.expiration)
                if best is None or exp < best:
                    best = exp
    return best


def rrsig_expired_or_near(
    msg: dns.message.Message,
    cover_rdtype: dns.rdatatype.RdataType,
    now: float,
    warn_seconds: float,
) -> tuple[bool, bool]:
    """Return (expired, near_expiry) for RRSIGs covering *cover_rdtype*."""
    expired = False
    near = False
    for rrset in msg.answer + msg.authority + msg.additional:
        if rrset.rdtype != dns.rdatatype.RRSIG:
            continue
        for rrsig in rrset:
            if not isinstance(rrsig, RRSIG) or rrsig.type_covered != cover_rdtype:
                continue
            if rrsig.expiration < now:
                expired = True
            elif rrsig.expiration <= now + warn_seconds:
                near = True
    return expired, near


def nsec_covers_name(
    qname: dns.name.Name, nsec_owner: dns.name.Name, nsec_next: dns.name.Name
) -> bool:
    """True if *qname* lies strictly between *nsec_owner* and *nsec_next* (canonical)."""
    q = qname.canonicalize()
    owner = nsec_owner.canonicalize()
    nxt = nsec_next.canonicalize()
    return bool(owner < q < nxt)


def nsec3_hash_covers_query(
    qname: dns.name.Name,
    zone_origin: dns.name.Name,
    nsec3_rdata: NSEC3,
    nsec3_owner: dns.name.Name,
) -> bool:
    """Whether *nsec3_rdata*'s interval covers the NSEC3 hash of *qname*."""
    h = dns.dnssec.nsec3_hash(
        qname, nsec3_rdata.salt, nsec3_rdata.iterations, nsec3_rdata.algorithm
    )
    rel = nsec3_owner.relativize(zone_origin)
    if rel == dns.name.empty:
        return False
    owner_h = rel.to_text(omit_final_dot=True).split(".")[0].upper()
    next_h = _nsec3_next_hash_text(nsec3_rdata.next).upper()
    return _hash_in_nsec3_range(h.upper(), owner_h, next_h)


def _nsec3_next_hash_text(next_bytes: bytes) -> str:
    """Base32hex text for NSEC3 next hashed owner (RFC 5155)."""
    out = base64.b32encode(next_bytes).translate(_B32_NORMAL_TO_HEX).lower().decode()
    return out.rstrip("=")


def _hash_in_nsec3_range(h: str, start: str, end: str) -> bool:
    """Circular ordering on fixed-length base32hex hashes."""
    if len(h) != len(start) or len(h) != len(end):
        return False
    if start < end:
        return start < h < end
    return h > start or h < end


def bitmap_has_rdtype(
    windows: Sequence[tuple[int, bytes]], rdtype: dns.rdatatype.RdataType
) -> bool:
    """True if an NSEC/NSEC3 type bitmap includes *rdtype*."""
    b = Bitmap(windows)
    want = int(rdtype)
    window = want // 256
    offset = want % 256
    for w, bmap in b.windows:
        if w != window:
            continue
        byte_i = offset // 8
        bit = offset % 8
        if byte_i < len(bmap):
            return bool(bmap[byte_i] & (0x80 >> bit))
    return False


def validate_nsec_negative_proof(  # NOSONAR S3776
    msg: dns.message.Message,
    zone_origin: dns.name.Name,
    qname: dns.name.Name,
    dnskey_rrset: dns.rrset.RRset,
    *,
    nodata_type: dns.rdatatype.RdataType | None,
) -> tuple[bool, str | None]:
    """Validate NSEC/NSEC3 + RRSIG for NXDOMAIN or NODATA (authority section)."""
    keys = _keys_dict(dnskey_rrset)
    keys_typed = cast(dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset], keys)
    rc = msg.rcode()
    is_nx = rc == dns.rcode.NXDOMAIN
    is_nodata = rc == dns.rcode.NOERROR and nodata_type is not None

    if not is_nx and not is_nodata:
        return False, "response is not NXDOMAIN or NODATA"

    has_nsec = any(rs.rdtype == dns.rdatatype.NSEC for rs in msg.authority)
    has_nsec3 = any(rs.rdtype == dns.rdatatype.NSEC3 for rs in msg.authority)
    if not has_nsec and not has_nsec3:
        return False, "no NSEC or NSEC3 in authority"

    for rrset in msg.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            rrsig_rrset = _find_rrsig_covering(msg.authority, dns.rdatatype.NSEC)
            if rrsig_rrset is None:
                return False, "no RRSIG for NSEC"
            try:
                dns.dnssec.validate(rrset, rrsig_rrset, keys_typed, origin=zone_origin)
            except (ValidationFailure, dns.exception.UnsupportedAlgorithm) as exc:
                return False, f"NSEC RRSIG: {exc}"
            for rdata in rrset:
                if not isinstance(rdata, NSEC):
                    continue
                if is_nx and nsec_covers_name(qname, rrset.name, rdata.next):
                    return True, None
                if (
                    is_nodata
                    and nodata_type is not None
                    and rrset.name.canonicalize() == qname.canonicalize()
                    and not bitmap_has_rdtype(rdata.windows, nodata_type)
                ):
                    return True, None

        if rrset.rdtype == dns.rdatatype.NSEC3:
            rrsig_rrset = _find_rrsig_covering(msg.authority, dns.rdatatype.NSEC3)
            if rrsig_rrset is None:
                return False, "no RRSIG for NSEC3"
            try:
                dns.dnssec.validate(rrset, rrsig_rrset, keys_typed, origin=zone_origin)
            except (ValidationFailure, dns.exception.UnsupportedAlgorithm) as exc:
                return False, f"NSEC3 RRSIG: {exc}"
            for rdata in rrset:
                if not isinstance(rdata, NSEC3):
                    continue
                if is_nx and nsec3_hash_covers_query(
                    qname, zone_origin, rdata, rrset.name
                ):
                    return True, None

    return False, "NSEC/NSEC3 chain does not prove non-existence"


def _find_rrsig_covering(
    authority: list[dns.rrset.RRset], covered: dns.rdatatype.RdataType
) -> dns.rrset.RRset | None:
    for rrset in authority:
        if rrset.rdtype != dns.rdatatype.RRSIG:
            continue
        for sig in rrset:
            if isinstance(sig, RRSIG) and sig.type_covered == covered:
                return rrset
    return None
