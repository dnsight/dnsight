"""DKIM TXT parsing, RSA key size, and validation rules."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import re
from typing import TYPE_CHECKING

from dnsight.checks.dkim.models import (
    DKIMData,
    DKIMIssueId,
    DKIMRecommendationId,
    DKIMSelectorResult,
    issue_descriptor,
)
from dnsight.core.config.blocks import Config, DkimConfig
import dnsight.core.config.defaults as defaults
from dnsight.core.exceptions import CheckError
from dnsight.core.models import Issue, Recommendation


if TYPE_CHECKING:
    from dnsight.utils.dns import DNSResolver


__all__ = [
    "ParsedDKIMRecord",
    "build_selector_fqdn",
    "collect_dkim_data",
    "dkim_query_plan",
    "extract_dkim_config",
    "merge_selector_names",
    "normalise_config",
    "parse_dkim_txt",
    "public_key_bits",
    "rsa_modulus_bits_from_der",
    "validate_dkim_results",
]


DKIM1_PREFIX = "v=DKIM1"

_TAG_SPLIT = re.compile(r"\s*;\s*")  # noqa: S5852


@dataclass(frozen=True)
class ParsedDKIMRecord:
    """Tags extracted from a DKIM TXT string."""

    version_ok: bool
    key_type: str | None
    public_key_b64: str | None
    hash_algorithms: tuple[str, ...]
    raw: str


def extract_dkim_config(config: Config | DkimConfig | None) -> DkimConfig:
    """Return the DkimConfig slice from full Config or bare DkimConfig."""
    if config is None:
        return DkimConfig()
    if isinstance(config, Config):
        return config.dkim
    return config


def normalise_config(config: Config | DkimConfig | None) -> tuple[DkimConfig, bool]:
    """DkimConfig and strict_recommendations when config is root Config."""
    if config is None:
        return DkimConfig(), False
    if isinstance(config, Config):
        return config.dkim, config.strict_recommendations
    return config, False


def merge_selector_names(user: list[str]) -> list[str]:
    """Return stripped, deduplicated selector names from config (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for s in user:
        t = (s or "").strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def dkim_query_plan(dkim_cfg: DkimConfig) -> tuple[list[str], tuple[str, ...]]:
    """Build selector DNS query list and explicit allowlist metadata.

    * **Discovery** (``dkim.selectors`` empty): query
      :data:`~dnsight.core.config.defaults.DEFAULT_DKIM_COMMON_SELECTORS` only;
      ``explicit_allowlist`` is empty.
    * **Explicit** (non-empty): query allowlisted selectors first, then any common
      names not in the allowlist (to detect unexpected published keys).
    """
    user = merge_selector_names(list(dkim_cfg.selectors))
    common = list(defaults.DEFAULT_DKIM_COMMON_SELECTORS)
    if not user:
        return common, ()
    user_set = set(user)
    extra = [s for s in common if s not in user_set]
    return user + extra, tuple(user)


def build_selector_fqdn(selector: str, domain: str) -> str:
    """Return ``selector._domainkey.domain`` (trimmed, no trailing dot)."""
    sel = (selector or "").strip().strip(".")
    dom = (domain or "").strip().strip(".")
    return f"{sel}._domainkey.{dom}"


def parse_dkim_txt(raw: str) -> ParsedDKIMRecord:
    """Parse semicolon-separated DKIM tags from a TXT string."""
    s = (raw or "").strip()
    if not s:
        return ParsedDKIMRecord(
            version_ok=False,
            key_type=None,
            public_key_b64=None,
            hash_algorithms=(),
            raw=s,
        )
    tags: dict[str, str] = {}
    for part in _TAG_SPLIT.split(s):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip().lower()
        tags[k] = v.strip()
    v_raw = tags.get("v", "")
    version_ok = v_raw.strip().lower() == "dkim1"
    k_val = tags.get("k")
    p_val = tags.get("p")
    public_key_b64 = p_val.strip() if p_val is not None else None
    key_type = k_val.strip().lower() if k_val else None
    if key_type is None and public_key_b64 is not None:
        key_type = "rsa"
    h_val = tags.get("h")
    hash_algorithms: tuple[str, ...] = ()
    if h_val:
        hash_algorithms = tuple(
            x.strip().lower() for x in h_val.split(":") if x.strip()
        )
    return ParsedDKIMRecord(
        version_ok=version_ok,
        key_type=key_type,
        public_key_b64=public_key_b64,
        hash_algorithms=hash_algorithms,
        raw=s,
    )


def rsa_modulus_bits_from_der(der: bytes) -> int | None:
    """Return RSA modulus bit length from PKCS#1 RSAPublicKey DER, or None."""
    try:
        seq = _der_read_sequence(der, 0)
        if seq is None:
            return None
        _, inner = seq
        int1 = _der_read_integer(inner, 0)
        if int1 is None:
            return None
        modulus, _rest = int1
        if modulus <= 0:
            return None
        return modulus.bit_length()
    except (IndexError, ValueError, TypeError):
        return None


def _der_read_length(data: bytes, i: int) -> tuple[int, int] | None:
    if i >= len(data):
        return None
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    if n == 0 or n > 4 or i + n > len(data):
        return None
    length = 0
    for _ in range(n):
        length = (length << 8) | data[i]
        i += 1
    return length, i


def _der_read_sequence(data: bytes, start: int) -> tuple[bytes, bytes] | None:
    if start >= len(data) or data[start] != 0x30:
        return None
    i = start + 1
    ln = _der_read_length(data, i)
    if ln is None:
        return None
    length, i = ln
    if i + length > len(data):
        return None
    return data[start : i + length], data[i : i + length]


def _der_read_integer(data: bytes, start: int) -> tuple[int, bytes] | None:
    if start >= len(data) or data[start] != 0x02:
        return None
    i = start + 1
    ln = _der_read_length(data, i)
    if ln is None:
        return None
    length, i = ln
    end = i + length
    if end > len(data):
        return None
    raw = data[i:end]
    if not raw:
        return None
    value = int.from_bytes(raw, "big", signed=False)
    return value, data[end:]


def _der_element_span(data: bytes, start: int) -> tuple[int, int] | None:
    """Return ``(start, end)`` indices of one DER element (end exclusive)."""
    if start >= len(data):
        return None
    i = start + 1
    ln = _der_read_length(data, i)
    if ln is None:
        return None
    length, j = ln
    end = j + length
    if end > len(data):
        return None
    return start, end


def _subject_public_key_info_to_rsa_bits(der: bytes) -> int | None:
    """Extract RSA modulus bits from SubjectPublicKeyInfo DER."""
    outer = _der_read_sequence(der, 0)
    if outer is None:
        return None
    _, body = outer
    algo_sp = _der_element_span(body, 0)
    if algo_sp is None:
        return None
    _, algo_end = algo_sp
    if algo_end >= len(body):
        return None
    bs_sp = _der_element_span(body, algo_end)
    if bs_sp is None:
        return None
    bs_start, bs_end = bs_sp
    elem = body[bs_start:bs_end]
    if not elem or elem[0] != 0x03:
        return None
    i = 1
    ln = _der_read_length(elem, i)
    if ln is None:
        return None
    blen, j = ln
    bit_payload = elem[j : j + blen]
    if not bit_payload:
        return None
    unused = bit_payload[0]
    key_der = bit_payload[1 + unused :]
    return rsa_modulus_bits_from_der(key_der)


def public_key_bits(key_type: str | None, public_key_b64: str | None) -> int | None:
    """Derive key size in bits for DKIM ``k=`` / ``p=``."""
    if not public_key_b64:
        return None
    kt = (key_type or "rsa").lower()
    try:
        raw = base64.b64decode("".join(public_key_b64.split()), validate=True)
    except (ValueError, TypeError):
        return None
    if kt == "rsa":
        bits = _subject_public_key_info_to_rsa_bits(raw)
        if bits is not None:
            return bits
        return rsa_modulus_bits_from_der(raw)
    if kt in ("ed25519", "ed448"):
        return 256 if kt == "ed25519" else 448
    return None


def _disallowed_hit(
    key_type: str | None, hash_algorithms: tuple[str, ...], disallowed: list[str]
) -> str | None:
    """Return first disallowed token matched, or None."""
    dlow = {x.strip().lower() for x in disallowed if x.strip()}
    if not dlow:
        return None
    kt = (key_type or "").lower()
    if kt and kt in dlow:
        return kt
    for h in hash_algorithms:
        if h in dlow:
            return h
    # composite checks like rsa-sha1
    composite = f"{kt}-{(hash_algorithms[0] if hash_algorithms else '')}"
    if composite in dlow:
        return composite
    return None


async def collect_dkim_data(
    domain: str, resolver: DNSResolver, dkim_cfg: DkimConfig
) -> DKIMData:
    """Resolve TXT for each planned selector; build DKIMData (no validation issues)."""
    names, allow = dkim_query_plan(dkim_cfg)
    results: list[DKIMSelectorResult] = []
    for sel in names:
        fqdn = build_selector_fqdn(sel, domain)
        raw_list: list[str] = []
        try:
            raw_list = await resolver.resolve_txt(fqdn)
        except CheckError:
            raw_list = []
        if not raw_list:
            results.append(
                DKIMSelectorResult(
                    selector=sel,
                    found=False,
                    algorithm=None,
                    key_bits=None,
                    raw_record=None,
                )
            )
            continue
        combined = " ".join((x or "").strip() for x in raw_list)
        parsed = parse_dkim_txt(combined)
        kt = parsed.key_type
        bits = public_key_bits(kt, parsed.public_key_b64)
        results.append(
            DKIMSelectorResult(
                selector=sel,
                found=True,
                algorithm=kt,
                key_bits=bits,
                raw_record=combined,
            )
        )
    return DKIMData(
        selectors_tried=names, selectors_found=results, explicit_allowlist=allow
    )


def _parsed_for_row(row: DKIMSelectorResult) -> ParsedDKIMRecord:
    if row.raw_record:
        return parse_dkim_txt(row.raw_record)
    return ParsedDKIMRecord(
        version_ok=False, key_type=None, public_key_b64=None, hash_algorithms=(), raw=""
    )


def _evaluate_found_dkim_selector(
    row: DKIMSelectorResult,
    parsed: ParsedDKIMRecord,
    *,
    disallowed: list[str],
    min_bits: int,
    stronger_rec_emitted: list[bool],
) -> tuple[bool, list[Issue], list[Recommendation]]:
    """Return (policy_valid_key, issues, recommendations) for a row with TXT."""
    issues: list[Issue] = []
    recs: list[Recommendation] = []
    sel = row.selector

    if not parsed.version_ok:
        syn = issue_descriptor(DKIMIssueId.SYNTAX_INVALID)
        issues.append(
            Issue(
                id=DKIMIssueId.SYNTAX_INVALID,
                severity=syn.severity,
                title="Invalid DKIM version",
                description=f"Selector {sel!r}: expected v=DKIM1.",
                remediation="Publish a valid DKIM record starting with v=DKIM1.",
            )
        )
        return False, issues, recs

    if parsed.public_key_b64 is not None and parsed.public_key_b64.strip() == "":
        km = issue_descriptor(DKIMIssueId.KEY_MISSING)
        issues.append(
            Issue(
                id=DKIMIssueId.KEY_MISSING,
                severity=km.severity,
                title="DKIM key revoked or empty",
                description=f"Selector {sel!r}: p= is empty (key revoked).",
                remediation="Publish a valid public key in p= or rotate the selector.",
            )
        )
        return False, issues, recs

    if not parsed.key_type:
        syn = issue_descriptor(DKIMIssueId.SYNTAX_INVALID)
        issues.append(
            Issue(
                id=DKIMIssueId.SYNTAX_INVALID,
                severity=syn.severity,
                title="DKIM record missing key type",
                description=f"Selector {sel!r}: missing k= tag.",
                remediation="Set k= (e.g. rsa or ed25519) in the DKIM record.",
            )
        )
        return False, issues, recs

    if parsed.public_key_b64 is None:
        km = issue_descriptor(DKIMIssueId.KEY_MISSING)
        issues.append(
            Issue(
                id=DKIMIssueId.KEY_MISSING,
                severity=km.severity,
                title="DKIM public key missing",
                description=f"Selector {sel!r}: missing p= tag.",
                remediation="Publish the base64-encoded public key in p=.",
            )
        )
        return False, issues, recs

    bits = public_key_bits(parsed.key_type, parsed.public_key_b64)
    if bits is None and parsed.key_type.lower() == "rsa":
        syn = issue_descriptor(DKIMIssueId.SYNTAX_INVALID)
        issues.append(
            Issue(
                id=DKIMIssueId.SYNTAX_INVALID,
                severity=syn.severity,
                title="DKIM RSA key could not be decoded",
                description=f"Selector {sel!r}: p= is not valid RSA DER.",
                remediation="Regenerate the DKIM key and publish a valid p= value.",
            )
        )
        return False, issues, recs

    hit = _disallowed_hit(parsed.key_type, parsed.hash_algorithms, disallowed)
    if hit is not None:
        aw = issue_descriptor(DKIMIssueId.ALGORITHM_WEAK)
        issues.append(
            Issue(
                id=DKIMIssueId.ALGORITHM_WEAK,
                severity=aw.severity,
                title="Weak or disallowed DKIM algorithm",
                description=(
                    f"Selector {sel!r}: algorithm or hash matches "
                    f"disallowed list ({hit!r})."
                ),
                remediation="Use a stronger key type or hash (e.g. rsa-sha256, ed25519).",
            )
        )
        if not stronger_rec_emitted[0]:
            stronger_rec_emitted[0] = True
            recs.append(
                Recommendation(
                    id=DKIMRecommendationId.STRONGER_ALGORITHM,
                    title="Use a stronger DKIM algorithm",
                    description=(
                        "Prefer rsa-sha256 or ed25519 and avoid deprecated algorithms. "
                        "Rotate DKIM keys and update signing configuration."
                    ),
                )
            )
        return False, issues, recs

    if bits is not None and bits < min_bits:
        ks = issue_descriptor(DKIMIssueId.KEY_TOO_SHORT)
        issues.append(
            Issue(
                id=DKIMIssueId.KEY_TOO_SHORT,
                severity=ks.severity,
                title="DKIM key shorter than minimum",
                description=(
                    f"Selector {sel!r}: key is {bits} bits; "
                    f"minimum configured is {min_bits}."
                ),
                remediation="Generate a longer RSA key or use ed25519.",
            )
        )
        return False, issues, recs

    return True, [], []


def _validate_dkim_discovery_rows(
    data: DKIMData, disallowed: list[str], min_bits: int, stronger_flag: list[bool]
) -> tuple[list[Issue], list[Recommendation], bool]:
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    any_valid_key = False
    for row in data.selectors_found:
        if not row.found:
            continue
        parsed = _parsed_for_row(row)
        ok, row_issues, row_recs = _evaluate_found_dkim_selector(
            row,
            parsed,
            disallowed=disallowed,
            min_bits=min_bits,
            stronger_rec_emitted=stronger_flag,
        )
        issues.extend(row_issues)
        recommendations.extend(row_recs)
        if ok:
            any_valid_key = True
    return issues, recommendations, any_valid_key


def _validate_dkim_explicit_rows(
    data: DKIMData,
    domain: str,
    allow: frozenset[str],
    disallowed: list[str],
    min_bits: int,
    stronger_flag: list[bool],
) -> tuple[list[Issue], list[Recommendation], bool]:
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    any_valid_key = False
    for row in data.selectors_found:
        if row.selector in allow:
            if not row.found:
                desc = issue_descriptor(DKIMIssueId.SELECTOR_NOT_FOUND)
                issues.append(
                    Issue(
                        id=DKIMIssueId.SELECTOR_NOT_FOUND,
                        severity=desc.severity,
                        title="DKIM TXT not found",
                        description=(
                            f"No TXT at {build_selector_fqdn(row.selector, domain)} "
                            f"(selector {row.selector!r})."
                        ),
                        remediation=(
                            "Publish a DKIM TXT record at selector._domainkey for this domain."
                        ),
                    )
                )
                continue
            parsed = _parsed_for_row(row)
            ok, row_issues, row_recs = _evaluate_found_dkim_selector(
                row,
                parsed,
                disallowed=disallowed,
                min_bits=min_bits,
                stronger_rec_emitted=stronger_flag,
            )
            issues.extend(row_issues)
            recommendations.extend(row_recs)
            if ok:
                any_valid_key = True
            continue

        if row.found:
            ex = issue_descriptor(DKIMIssueId.EXTRA_SELECTOR_PUBLISHED)
            issues.append(
                Issue(
                    id=DKIMIssueId.EXTRA_SELECTOR_PUBLISHED,
                    severity=ex.severity,
                    title="DKIM published for selector outside allowlist",
                    description=(
                        f"TXT exists at {build_selector_fqdn(row.selector, domain)} "
                        f"(selector {row.selector!r}), which is not listed under "
                        f"`dkim.selectors`. Either remove the record or add this name to "
                        f"the allowlist if it is intentional."
                    ),
                    remediation=(
                        "Align DNS with `dkim.selectors`, or remove stale DKIM records."
                    ),
                )
            )

    return issues, recommendations, any_valid_key


def validate_dkim_results(
    data: DKIMData, domain: str, dkim_cfg: DkimConfig, _strict_recommendations: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Classify selector results into issues and recommendations.

    Discovery mode (empty ``explicit_allowlist``): probe-only; missing TXT on a name is
    not an issue. The check passes if at least one selector yields a policy-valid key.
    Invalid published records still produce issues.

    Explicit mode (non-empty allowlist): every allowlisted name must have a valid key;
    missing TXT is an issue. Any TXT at a probed name *outside* the allowlist is an
    **extra selector** issue.
    """
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []
    if not data.selectors_tried:
        return issues, recommendations

    disallowed = list(dkim_cfg.disallowed_algorithms)
    min_bits = dkim_cfg.min_key_bits
    allow = frozenset(data.explicit_allowlist)
    discovery = not allow
    stronger_flag = [False]

    if discovery:
        d_issues, d_recs, any_valid_key = _validate_dkim_discovery_rows(
            data, disallowed, min_bits, stronger_flag
        )
        issues.extend(d_issues)
        recommendations.extend(d_recs)
    else:
        e_issues, e_recs, any_valid_key = _validate_dkim_explicit_rows(
            data, domain, allow, disallowed, min_bits, stronger_flag
        )
        issues.extend(e_issues)
        recommendations.extend(e_recs)

    if discovery and not any_valid_key:
        d0 = issue_descriptor(DKIMIssueId.DISCOVERY_NO_VALID_KEY)
        tried = ", ".join(repr(s) for s in data.selectors_tried)
        issues.append(
            Issue(
                id=DKIMIssueId.DISCOVERY_NO_VALID_KEY,
                severity=d0.severity,
                title="No valid DKIM key among discovered selectors",
                description=(
                    "dnsight probed common selector names "
                    f"({tried}) and found no usable DKIM public key for this domain."
                ),
                remediation=(
                    "Publish a valid DKIM TXT at the selector your mail uses, or set "
                    "`dkim.selectors` to the exact names you use so dnsight checks only those."
                ),
            )
        )
        any_txt_found = any(r.found for r in data.selectors_found)
        if not any_txt_found:
            recommendations.append(
                Recommendation(
                    id=DKIMRecommendationId.ADD_COMMON_SELECTORS,
                    title="Configure DKIM selectors",
                    description=(
                        "No DKIM TXT was returned for the probed names. Use provider "
                        "documentation or a signed message's DKIM-Signature (`s=`) to "
                        "choose selectors; add them under `dkim.selectors` for strict checks."
                    ),
                )
            )

    return issues, recommendations
