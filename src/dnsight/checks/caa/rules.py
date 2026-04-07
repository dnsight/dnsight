"""CAA name discovery, RFC 8659 effective policy, and validation rules.

Name enumeration walks A/AAAA/CNAME (and optional DNAME) with depth and count
limits. Effective CAA follows RFC 8659: walk from the candidate FQDN toward
the zone apex until a non-empty CAA RRset is found or the apex is exhausted.
"""

from __future__ import annotations

from collections import deque
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import quote

from dnsight.checks.caa.models import (
    CAAData,
    CaaGenerateParams,
    CaaIssueId,
    CaaNameResult,
    CaaRecommendationId,
    CaaRecord,
    DiscoveryLimitReason,
    NameDiscoveryKind,
    issue_descriptor,
    recommendation_descriptor,
)
from dnsight.core.config.blocks import CaaConfig, Config
from dnsight.core.exceptions import CheckError
from dnsight.core.models import Issue, Recommendation


if TYPE_CHECKING:
    from dnsight.utils.dns import DNSResolver
    from dnsight.utils.http import HTTPClient

__all__: list[str] = []

_TAG_RE = re.compile(r"^[a-zA-Z0-9-]{1,255}$")
_SRV_PROBE_NAMES: tuple[str, ...] = (
    "_smtp._tcp",
    "_submission._tcp",
    "_imap._tcp",
    "_pop3._tcp",
)

# FQDN-shaped tokens in crt.sh ``issuer_name`` (often an X.509 DN). Used only to
# avoid naive substring false positives (e.g. ``evil-letsencrypt.org`` vs ``letsencrypt.org``).
_CRTSH_HOSTNAME_RE = re.compile(
    r"(?<![a-z0-9.*_-])"
    r"(?:\*\.)?"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?![a-z0-9.*_-])",
    re.IGNORECASE,
)


def extract_caa_config(config: Config | CaaConfig | None) -> CaaConfig:
    """Return the CaaConfig slice from full Config or bare CaaConfig."""
    if config is None:
        return CaaConfig()
    if isinstance(config, Config):
        return config.caa
    return config


def canonical_fqdn(name: str) -> str:
    """Lowercase FQDN without trailing dot."""
    s = (name or "").strip().lower().rstrip(".")
    return s


def _is_subdomain_or_equal(name: str, zone_apex: str) -> bool:
    n = canonical_fqdn(name)
    z = canonical_fqdn(zone_apex)
    return n == z or n.endswith("." + z)


def qualify_hostname(label_or_fqdn: str, zone_apex: str) -> str:
    """Turn a config entry into an FQDN under *zone_apex*."""
    raw = (label_or_fqdn or "").strip()
    if not raw:
        return canonical_fqdn(zone_apex)
    if "." in raw:
        return canonical_fqdn(raw)
    return canonical_fqdn(f"{raw}.{zone_apex}")


def parse_caa_wire(
    tuples: list[tuple[int, str, str]],
) -> tuple[list[CaaRecord], list[Issue]]:
    """Parse resolver CAA tuples; emit syntax issues for malformed tags."""
    records: list[CaaRecord] = []
    issues: list[Issue] = []
    desc = issue_descriptor(CaaIssueId.SYNTAX_INVALID)
    for flags, tag, value in tuples:
        if flags < 0 or flags > 255 or not _TAG_RE.match(tag):
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="Invalid CAA record",
                    description=f"Malformed CAA tag or flags: tag={tag!r}, flags={flags}.",
                    remediation="Fix CAA RDATA at the DNS host per RFC 8659.",
                )
            )
            continue
        records.append(CaaRecord(flags=flags, tag=tag, value=value))
    return records, issues


def _strip_value(value: str) -> str:
    s = value.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s.strip()


def _caa_issue_hostname_from_value(value: str) -> str:
    """Return the issuer hostname token from an issue/issuewild value (RFC 8659).

    Property values are a domain name optionally followed by ``;`` and
    additional parameters; only the hostname part is used for authorization
    comparisons.
    """
    s = _strip_value(value)
    return s.split(";", 1)[0].strip()


def issue_domains(records: list[CaaRecord]) -> set[str]:
    """Normalized issue tag issuer hostnames (RFC 8659 parameters after ``;`` ignored)."""
    out: set[str] = set()
    for r in records:
        if r.tag.lower() != "issue":
            continue
        v = _caa_issue_hostname_from_value(r.value).lower().rstrip(".")
        if not v or v == ";":
            continue
        out.add(v)
    return out


def issuewild_domains(records: list[CaaRecord]) -> set[str]:
    """Normalized issuewild tag issuer hostnames (parameters after ``;`` ignored)."""
    out: set[str] = set()
    for r in records:
        if r.tag.lower() != "issuewild":
            continue
        v = _caa_issue_hostname_from_value(r.value).lower().rstrip(".")
        if not v or v == ";":
            continue
        out.add(v)
    return out


def has_issue_forbidden_semicolon(records: list[CaaRecord]) -> bool:
    """True if any issue tag has value ';' (RFC 8659 issuance restriction)."""
    for r in records:
        if r.tag.lower() != "issue":
            continue
        v = _strip_value(r.value)
        if v == ";":
            return True
    return False


def has_issuewild_forbidden_semicolon(records: list[CaaRecord]) -> bool:
    """True if any issuewild tag has value ';'."""
    for r in records:
        if r.tag.lower() != "issuewild":
            continue
        v = _strip_value(r.value)
        if v == ";":
            return True
    return False


def has_issue_or_issuewild_tags(records: list[CaaRecord]) -> bool:
    for r in records:
        t = r.tag.lower()
        if t in ("issue", "issuewild"):
            return True
    return False


def issuer_allowed(required: str, issue_domains_set: set[str]) -> bool:
    """Return True if *required* is authorized by an issue tag (exact match)."""
    req = _strip_value(required).lower().rstrip(".")
    return req in issue_domains_set


async def effective_caa_rrset(
    name: str, zone_apex: str, resolver: DNSResolver
) -> tuple[list[CaaRecord], str, list[tuple[int, str, str]]]:
    """Return effective CAA records, effective node name, and raw tuples.

    Walks from *name* toward *zone_apex* per RFC 8659 until a non-empty
    CAA RRset is found or the zone apex is queried with no CAA.
    """
    current = canonical_fqdn(name)
    z = canonical_fqdn(zone_apex)
    if not _is_subdomain_or_equal(current, z):
        return [], z, []

    while True:
        raw = await resolver.resolve_caa(current)
        parsed, _ = parse_caa_wire(raw)
        if parsed:
            return parsed, current, raw
        if current == z:
            break
        parts = current.split(".", 1)
        if len(parts) < 2:
            break
        current = parts[1]
    return [], z, []


async def _expand_cname(
    resolver: DNSResolver, name: str, depth: int, max_depth: int
) -> list[tuple[str, int]]:
    """Return (target, new_depth) for CNAME targets within depth."""
    if depth >= max_depth:
        return []
    try:
        targets = await resolver.resolve_cname(name)
    except CheckError:
        return []
    return [(t, depth + 1) for t in targets]


async def _expand_dname(
    resolver: DNSResolver, name: str, depth: int, max_depth: int
) -> list[tuple[str, int]]:
    if depth >= max_depth:
        return []
    try:
        targets = await resolver.resolve_dname(name)
    except CheckError:
        return []
    return [(t, depth + 1) for t in targets]


async def discover_names(  # NOSONAR S3776
    zone_apex: str, cfg: CaaConfig, resolver: DNSResolver
) -> tuple[dict[str, set[NameDiscoveryKind]], bool, DiscoveryLimitReason]:
    """Seed and optionally enumerate hostnames; return discovery map + limits."""
    z = canonical_fqdn(zone_apex)
    seen: dict[str, set[NameDiscoveryKind]] = {}

    def add(name: str, kind: NameDiscoveryKind) -> None:
        seen.setdefault(canonical_fqdn(name), set()).add(kind)

    add(z, NameDiscoveryKind.APEX)
    if cfg.include_www:
        add(f"www.{z}", NameDiscoveryKind.WWW)

    for entry in cfg.names:
        add(qualify_hostname(entry, z), NameDiscoveryKind.CONFIG)

    if cfg.include_mx_targets:
        try:
            mx = await resolver.resolve_mx(z)
        except CheckError:
            mx = []
        for _pref, host in mx:
            add(host, NameDiscoveryKind.ENUM_MX)

    if cfg.include_srv_targets:
        for prefix in _SRV_PROBE_NAMES:
            srv_name = f"{prefix}.{z}"
            try:
                srv = await resolver.resolve_srv(srv_name)
            except CheckError:
                continue
            for _p, _w, _port, target in srv:
                add(target, NameDiscoveryKind.ENUM_SRV)

    if not cfg.enumerate_names:
        return seen, False, DiscoveryLimitReason.NONE

    truncated = False
    limit_reason = DiscoveryLimitReason.NONE
    queue: deque[tuple[str, int]] = deque()
    expanded: set[str] = set()

    for name in list(seen.keys()):
        queue.append((name, 0))

    while queue:
        name, depth = queue.popleft()
        if depth >= cfg.max_enumeration_depth:
            truncated = True
            limit_reason = DiscoveryLimitReason.MAX_DEPTH
            continue
        if name in expanded:
            continue
        expanded.add(name)

        for target, d2 in await _expand_cname(
            resolver, name, depth, cfg.max_enumeration_depth
        ):
            if len(seen) >= cfg.max_names:
                truncated = True
                limit_reason = DiscoveryLimitReason.MAX_NAMES
                break
            add(target, NameDiscoveryKind.ENUM_CNAME)
            queue.append((target, d2))
        if truncated and limit_reason == DiscoveryLimitReason.MAX_NAMES:
            break

        if cfg.enumerate_dname:
            for target, d2 in await _expand_dname(
                resolver, name, depth, cfg.max_enumeration_depth
            ):
                if len(seen) >= cfg.max_names:
                    truncated = True
                    limit_reason = DiscoveryLimitReason.MAX_NAMES
                    break
                add(target, NameDiscoveryKind.ENUM_DNAME)
                queue.append((target, d2))
            if truncated and limit_reason == DiscoveryLimitReason.MAX_NAMES:
                break

        # A/AAAA: mark the name as host-bearing (already enumerated; no new names)
        for meth, kind in (
            (resolver.resolve_a, NameDiscoveryKind.ENUM_A),
            (resolver.resolve_aaaa, NameDiscoveryKind.ENUM_AAAA),
        ):
            try:
                vals = await meth(name)
            except CheckError:
                vals = []
            if vals:
                add(name, kind)

    return seen, truncated, limit_reason


def _validate_name(  # NOSONAR S3776
    name: str,
    _zone_apex: str,
    effective: list[CaaRecord],
    eff_node: str,
    cfg: CaaConfig,
    strict_recommendations: bool,
) -> tuple[CaaNameResult, list[Issue], list[Recommendation]]:
    """Build CaaNameResult and per-name issues/recommendations."""
    issues: list[Issue] = []
    recs: list[Recommendation] = []
    missing: list[str] = []

    desc_rec = issue_descriptor(CaaIssueId.RECORD_MISSING)
    desc_issue = issue_descriptor(CaaIssueId.ISSUE_MISSING)
    desc_iss = issue_descriptor(CaaIssueId.ISSUER_MISSING)
    desc_iw_p = issue_descriptor(CaaIssueId.ISSUEWILD_PERMISSIVE)
    desc_iw_r = issue_descriptor(CaaIssueId.ISSUEWILD_RESTRICT)

    if not effective:
        issues.append(
            Issue(
                id=desc_rec.id.value,
                severity=desc_rec.severity,
                title="No CAA records",
                description=f"No CAA RRset found in the tree for {name!r}.",
                remediation="Publish CAA records at or above this hostname per RFC 8659.",
            )
        )
    elif cfg.require_caa and not has_issue_or_issuewild_tags(effective):
        issues.append(
            Issue(
                id=desc_issue.id.value,
                severity=desc_issue.severity,
                title="CAA missing issue/issuewild",
                description="CAA is required but no issue or issuewild property is present.",
                remediation='Add issue "..." and optionally issuewild "..." tags.',
            )
        )

    iss_set = issue_domains(effective)
    iw_set = issuewild_domains(effective)

    for req in cfg.required_issuers:
        if not issuer_allowed(req, iss_set):
            missing.append(req)
            issues.append(
                Issue(
                    id=desc_iss.id.value,
                    severity=desc_iss.severity,
                    title="Required issuer not allowed by CAA",
                    description=(
                        f"Required issuer {req!r} is not authorized by an "
                        f"issue tag for {name!r} (effective node {eff_node!r})."
                    ),
                    remediation='Add an issue tag matching this CA (e.g. issue "ca.example").',
                )
            )

    if cfg.check_issuewild and iss_set and iw_set:
        extra = iw_set - iss_set
        if extra:
            issues.append(
                Issue(
                    id=desc_iw_p.id.value,
                    severity=desc_iw_p.severity,
                    title="issuewild is broader than issue",
                    description=(
                        f"issuewild authorizes CAs not present in issue for {name!r}: "
                        f"{sorted(extra)!r}."
                    ),
                    remediation="Align issuewild with issue or restrict issuewild to the same CAs.",
                )
            )

    if cfg.restrict_wildcard_issuance:
        if iss_set and iw_set and (iw_set - iss_set):
            issues.append(
                Issue(
                    id=desc_iw_r.id.value,
                    severity=desc_iw_r.severity,
                    title="Wildcard issuance not restricted",
                    description=(
                        "restrict_wildcard_issuance is enabled but issuewild allows CAs "
                        f"not covered by issue for {name!r}."
                    ),
                    remediation='Add issuewild ";" or match issuewild CAs to issue.',
                )
            )
        if (
            not iss_set
            and has_issue_forbidden_semicolon(effective)
            and iw_set
            and not has_issuewild_forbidden_semicolon(effective)
        ):
            issues.append(
                Issue(
                    id=desc_iw_r.id.value,
                    severity=desc_iw_r.severity,
                    title="Wildcard issuance should be restricted",
                    description=(
                        "issue forbids hostname issuance (';') but issuewild still allows "
                        f"wildcard issuance for {name!r}."
                    ),
                    remediation='Add issuewild ";" to forbid wildcard issuance.',
                )
            )

    if strict_recommendations and effective and not iss_set:
        rd = recommendation_descriptor(CaaRecommendationId.ADD_ISSUE)
        recs.append(
            Recommendation(
                id=rd.id.value,
                title="Add issue tag",
                description="No issue tag is present; define which CAs may issue for this name.",
            )
        )
    if (
        strict_recommendations
        and effective
        and iss_set
        and not iw_set
        and cfg.check_issuewild
    ):
        rd = recommendation_descriptor(CaaRecommendationId.ADD_ISSUEWILD)
        recs.append(
            Recommendation(
                id=rd.id.value,
                title="Add issuewild tag",
                description="issue is present but issuewild is absent; define wildcard policy explicitly.",
            )
        )

    result = CaaNameResult(
        name=name,
        discovery=tuple(),  # filled by caller
        records_at_node=[CaaRecord(**r.model_dump()) for r in effective],
        effective_node=eff_node,
        effective_records=[CaaRecord(**r.model_dump()) for r in effective],
        missing_issuers=missing,
    )
    return result, issues, recs


async def gather_caa_data(
    zone_apex: str, cfg: CaaConfig, resolver: DNSResolver
) -> tuple[CAAData, list[Issue]]:
    """Discover names, resolve effective CAA per name, and parse syntax (no policy rules)."""
    discovery, truncated, limit_reason = await discover_names(zone_apex, cfg, resolver)
    names_results: list[CaaNameResult] = []
    issues: list[Issue] = []

    if truncated:
        d = issue_descriptor(CaaIssueId.ENUMERATION_LIMIT_REACHED)
        issues.append(
            Issue(
                id=d.id.value,
                severity=d.severity,
                title="Name enumeration limit reached",
                description=(
                    f"Stopped at {limit_reason.value} "
                    f"(max_names={cfg.max_names}, max_depth={cfg.max_enumeration_depth})."
                ),
                remediation="Raise limits or narrow discovery via config.names.",
            )
        )

    for name in sorted(discovery.keys()):
        kinds = tuple(sorted(discovery[name], key=lambda k: k.value))
        eff, eff_node, raw_tuples = await effective_caa_rrset(name, zone_apex, resolver)
        _, syntax_issues = parse_caa_wire(raw_tuples)
        issues.extend(syntax_issues)
        nr = CaaNameResult(
            name=name,
            discovery=kinds,
            records_at_node=list(eff),
            effective_node=eff_node,
            effective_records=list(eff),
            missing_issuers=[],
        )
        names_results.append(nr)

    data = CAAData(
        zone_apex=canonical_fqdn(zone_apex),
        names_checked=names_results,
        enumeration_truncated=truncated,
        discovery_limit_reason=limit_reason,
        names_discovered_count=len(discovery),
    )
    return data, issues


def apply_caa_validation(
    data: CAAData, cfg: CaaConfig, *, strict_recommendations: bool
) -> tuple[list[Issue], list[Recommendation]]:
    """Run policy validation on gathered CAA inventory."""
    issues: list[Issue] = []
    recs: list[Recommendation] = []
    for nr in data.names_checked:
        nr2, n_issues, n_recs = _validate_name(
            nr.name,
            data.zone_apex,
            list(nr.effective_records),
            nr.effective_node,
            cfg,
            strict_recommendations,
        )
        issues.extend(n_issues)
        recs.extend(n_recs)
        _ = nr2  # same shape as nr
    return issues, recs


def _labels_for_crtsh_host(host: str) -> tuple[str, ...]:
    """Split a hostname into lowercase labels; strip leading ``*.`` if present."""
    h = canonical_fqdn(host)
    if h.startswith("*."):
        h = h[2:]
    return tuple(p.lower() for p in h.split(".") if p)


def _dns_suffix_matches(
    host_labels: tuple[str, ...], ca_labels: tuple[str, ...]
) -> bool:
    """True if *host_labels* is *ca_labels* or a subdomain thereof (DNS tree)."""
    if not ca_labels or len(host_labels) < len(ca_labels):
        return False
    return host_labels[-len(ca_labels) :] == ca_labels


def _issuer_hostname_label_sets(issuer_name: str) -> frozenset[tuple[str, ...]]:
    """Extract distinct hostname label-tuples from an issuer string."""
    found: set[tuple[str, ...]] = set()
    for m in _CRTSH_HOSTNAME_RE.finditer(issuer_name.lower()):
        raw = (m.group(0) or "").strip().strip(".")
        labs = _labels_for_crtsh_host(raw)
        if len(labs) >= 2:
            found.add(labs)
    return frozenset(found)


def _issuer_matches_crt_row(issuer_name: str | None, allowed: set[str]) -> bool:
    """Heuristic: a hostname token in the issuer string matches an allowed CAA ``issue`` domain.

    Tokens are FQDN-shaped substrings from the crt.sh ``issuer_name`` field (often a DN).
    A match requires DNS label suffix equality (e.g. ``www.letsencrypt.org`` matches
    ``letsencrypt.org``). This is not X.509 path validation; issuer text without
    parseable hostnames never matches here.
    """
    if not issuer_name or not allowed:
        return False
    candidates = _issuer_hostname_label_sets(issuer_name)
    if not candidates:
        return False
    for a in allowed:
        if not a.strip():
            continue
        ca_labels = _labels_for_crtsh_host(a)
        if len(ca_labels) < 2:
            continue
        for host_labels in candidates:
            if _dns_suffix_matches(host_labels, ca_labels):
                return True
    return False


async def crt_sh_issues(  # NOSONAR S3776
    zone_apex: str, names_checked: list[CaaNameResult], cfg: CaaConfig, http: HTTPClient
) -> list[Issue]:
    """Optional crt.sh cross-check using JSON API."""
    if not cfg.cross_reference_crt_sh:
        return []
    z = canonical_fqdn(zone_apex)
    url = f"https://crt.sh/?q={quote('%.' + z)}&output=json"
    try:
        resp = await http.get(url)
    except CheckError:
        return []
    if resp.status_code != 200:
        return []
    try:
        rows = json.loads(resp.text)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []

    issues: list[Issue] = []
    desc = issue_descriptor(CaaIssueId.CRT_SH_VIOLATION)
    by_name = {n.name: n for n in names_checked}

    for row in rows:
        if not isinstance(row, dict):
            continue
        name_val = row.get("name_value")
        issuer_name = row.get("issuer_name")
        if not isinstance(name_val, str):
            continue
        nv = canonical_fqdn(name_val)
        if nv not in by_name:
            continue
        target = by_name[nv]
        allowed = issue_domains(target.effective_records)
        if not isinstance(issuer_name, str):
            continue
        if allowed and _issuer_matches_crt_row(issuer_name, allowed):
            continue
        if not allowed:
            issues.append(
                Issue(
                    id=desc.id.value,
                    severity=desc.severity,
                    title="Certificate issuer may not match CAA",
                    description=(
                        f"crt.sh lists a certificate for {name_val!r} from "
                        f"{issuer_name!r} but no issue tags authorize issuance."
                    ),
                    remediation="Align public certificates with CAA or update CAA records.",
                )
            )
            continue
        issues.append(
            Issue(
                id=desc.id.value,
                severity=desc.severity,
                title="Certificate issuer may not match CAA",
                description=(
                    f"crt.sh lists a certificate for {name_val!r} from "
                    f"{issuer_name!r} that may not match effective CAA issue tags "
                    "(hostnames parsed from the issuer field only; not full PKI validation)."
                ),
                remediation="Align public certificates with CAA or update CAA records.",
            )
        )
    return issues


def build_generated_value(params: CaaGenerateParams) -> str:
    """Build newline-separated CAA RDATA lines for a zone file."""
    lines: list[str] = []
    for issuer in params.issuers:
        dom = _strip_value(issuer)
        if dom:
            lines.append(f'0 issue "{dom}"')
    if params.emit_issuewild:
        for issuer in params.issuers:
            dom = _strip_value(issuer)
            if dom:
                lines.append(f'0 issuewild "{dom}"')
    if params.iodef_mailto:
        addr = params.iodef_mailto.strip()
        if addr.startswith("mailto:"):
            lines.append(f'0 iodef "{addr}"')
        else:
            lines.append(f'0 iodef "mailto:{addr}"')
    return "\n".join(lines)
