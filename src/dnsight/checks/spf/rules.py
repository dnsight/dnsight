"""SPF parsing, flattening, and validation rules.

DNS lookup accounting for ``effective_lookup_count`` (RFC 7208 limit of 10):

- One lookup for each ``resolve_txt`` during evaluation (apex, each
  ``include:`` target, ``redirect=`` target, and nested records).
- One additional lookup per mechanism that triggers DNS during SPF
  evaluation: ``a``, ``mx``, ``ptr``, ``exists``, and their ``:domain``
  forms (counted once per token, after stripping SPF qualifiers).
- ``ip4:`` / ``ip6:`` do not add DNS lookups.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING

from dnsight.checks.spf.models import (
    FlattenedSPF,
    SPFData,
    SPFIssueId,
    SPFRecommendationId,
    issue_descriptor,
)
from dnsight.core.config.blocks import Config, SpfConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.models import Issue, Recommendation
from dnsight.core.types import Severity


if TYPE_CHECKING:
    from dnsight.utils.dns import DNSResolver

__all__: list[str] = []

SPF1_PREFIX = "v=spf1"
_TOKEN_SPLIT = re.compile(r"\s+")
_MODIFIER_REDIRECT = re.compile(r"^redirect=([^=]+)$", re.IGNORECASE)


def extract_spf_config(config: Config | SpfConfig | None) -> SpfConfig:
    """Return the SpfConfig slice from full Config or bare SpfConfig."""
    if config is None:
        return SpfConfig()
    if isinstance(config, Config):
        return config.spf
    return config


def normalise_config(config: Config | SpfConfig | None) -> tuple[SpfConfig, bool]:
    """SpfConfig and strict_recommendations flag when config is root Config."""
    if config is None:
        return SpfConfig(), False
    if isinstance(config, Config):
        return config.spf, config.strict_recommendations
    return config, False


def _tokens_after_version(record: str) -> list[str]:
    """Split SPF mechanisms/modifiers after v=spf1."""
    s = (record or "").strip()
    if not s.lower().startswith(SPF1_PREFIX):
        return []
    rest = s[len(SPF1_PREFIX) :].strip()
    if not rest:
        return []
    return [t for t in _TOKEN_SPLIT.split(rest) if t]


def _strip_spf_qualifier(token: str) -> str:
    """Strip a single leading SPF qualifier (+, -, ~, ?) if present."""
    t = token.strip()
    if len(t) >= 2 and t[0] in "+-~?":
        return t[1:]
    return t


def _redirect_target(token: str) -> str | None:
    m = _MODIFIER_REDIRECT.match(token.strip())
    if m:
        return m.group(1).rstrip(".")
    return None


def _include_target(token: str) -> str | None:
    rest = _strip_spf_qualifier(token)
    if rest.lower().startswith("include:"):
        return rest.split(":", 1)[1].rstrip(".")
    return None


def _terminal_all(tokens: list[str]) -> str | None:
    """Return qualifier+all for the last all mechanism, if any."""
    last: str | None = None
    for t in tokens:
        rest = _strip_spf_qualifier(t).lower()
        if rest == "all":
            last = t
    return last


def _normalise_all_token(tok: str) -> str:
    t = tok.strip().lower()
    if t == "all":
        return "+all"
    return tok.strip()


def parse_spf_record(raw: str) -> tuple[list[str], str, list[str]]:
    """Parse record into tokens, disposition string, include domains."""
    tokens = _tokens_after_version(raw)
    includes: list[str] = []
    for t in tokens:
        inc = _include_target(t)
        if inc:
            includes.append(inc)
    term = _terminal_all(tokens)
    disp = _normalise_all_token(term) if term else ""
    return tokens, disp, includes


def _mechanism_dns_lookup_increment(rest: str) -> int:
    """Return 1 if this mechanism triggers an SPF DNS lookup, else 0."""
    r = rest.lower()
    if r in {"a", "mx", "ptr"}:
        return 1
    if r.startswith(("a:", "mx:", "ptr:", "exists:")):
        return 1
    return 0


def _collect_ip_literals(token: str, ip4: list[str], ip6: list[str]) -> None:
    rest = _strip_spf_qualifier(token)
    rl = rest.lower()
    if rl.startswith("ip4:"):
        ip4.append(rest.split(":", 1)[1])
    elif rl.startswith("ip6:"):
        ip6.append(rest.split(":", 1)[1])


@dataclass
class FlattenOutcome:
    """Result of ``flatten_spf`` — flattened data plus policy flags."""

    flat: FlattenedSPF
    redirect_disallowed: bool = False
    include_resolution_errors: list[str] = field(default_factory=list)


async def flatten_spf(
    domain: str,
    resolver: DNSResolver,
    *,
    allow_redirect: bool = True,
    lookup_limit: int = 10,
) -> FlattenOutcome:
    """Resolve and flatten SPF for *domain* (follow include / redirect per RFC 7208)."""
    lookup_count = 0
    visited: set[str] = set()
    resolved_mechanisms: list[str] = []
    ip4: list[str] = []
    ip6: list[str] = []
    redirect_disallowed = False
    include_resolution_errors: list[str] = []

    async def visit(name: str, *, is_root: bool = False) -> None:
        nonlocal lookup_count, redirect_disallowed
        if name in visited:
            return
        visited.add(name)
        if lookup_count >= lookup_limit:
            return
        try:
            txts = await resolver.resolve_txt(name)
        except CheckError:
            if is_root:
                raise
            include_resolution_errors.append(name)
            return

        lookup_count += 1
        spf_strings = [
            x.strip() for x in txts if x.strip().lower().startswith(SPF1_PREFIX)
        ]
        if not spf_strings:
            return
        raw = spf_strings[0]
        tokens = _tokens_after_version(raw)

        redirect_idx: int | None = None
        redir: str | None = None
        for i, t in enumerate(tokens):
            r = _redirect_target(t)
            if r:
                redirect_idx = i
                redir = r
                break

        tokens_effective = tokens[:redirect_idx] if redirect_idx is not None else tokens

        for t in tokens_effective:
            if lookup_count >= lookup_limit:
                return
            rest = _strip_spf_qualifier(t)
            inc = _include_target(t)
            if inc:
                resolved_mechanisms.append(f"include:{inc}")
                await visit(inc, is_root=False)
            _collect_ip_literals(t, ip4, ip6)
            n = _mechanism_dns_lookup_increment(rest)
            if n and lookup_count < lookup_limit:
                lookup_count += n

        if redir is not None:
            if not allow_redirect:
                redirect_disallowed = True
            elif lookup_count < lookup_limit:
                await visit(redir, is_root=False)

    await visit(domain.rstrip("."), is_root=True)
    flat = FlattenedSPF(
        effective_lookup_count=lookup_count,
        resolved_mechanisms=resolved_mechanisms,
        ip4_ranges=ip4,
        ip6_ranges=ip6,
    )
    return FlattenOutcome(
        flat=flat,
        redirect_disallowed=redirect_disallowed,
        include_resolution_errors=include_resolution_errors,
    )


def _disposition_rank(disp: str) -> int:
    """Higher = stricter / safer for receivers (rough ordering)."""
    d = disp.lower()
    if d == "+all":
        return 0
    if d == "?all":
        return 1
    if d == "~all":
        return 2
    if d == "-all":
        return 3
    return -1


def _required_rank(req: str) -> int:
    return _disposition_rank(req + "all" if not req.endswith("all") else req)


def validate_spf_data(
    data: SPFData,
    flat: FlattenedSPF | None,
    spf_config: SpfConfig,
    strict_recommendations: bool,
) -> tuple[list[Issue], list[Recommendation]]:
    """Apply policy rules; assumes DNS and parse already succeeded."""
    issues: list[Issue] = []
    recommendations: list[Recommendation] = []

    req = spf_config.required_disposition
    req_rank = _required_rank(req)

    disp = (data.disposition or "").lower()
    disp_rank = _disposition_rank(disp)
    weaker = bool(disp) and req_rank > disp_rank

    specific_disposition_issue = False

    if disp == "+all":
        d = issue_descriptor(SPFIssueId.DISPOSITION_PASS_ALL)
        issues.append(
            Issue(
                id=SPFIssueId.DISPOSITION_PASS_ALL,
                severity=d.severity,
                title="SPF passes all senders",
                description="The SPF record ends with +all, allowing any host to send as this domain.",
                remediation="Replace +all with -all or at least ~all after listing legitimate senders.",
            )
        )
        specific_disposition_issue = True
    elif disp == "?all":
        d = issue_descriptor(SPFIssueId.DISPOSITION_NEUTRAL)
        issues.append(
            Issue(
                id=SPFIssueId.DISPOSITION_NEUTRAL,
                severity=d.severity,
                title="SPF neutral default (?all)",
                description="?all does not instruct receivers to reject or mark forged mail.",
                remediation="Use -all when all legitimate senders are listed.",
            )
        )
        specific_disposition_issue = True
    elif disp == "~all":
        d = issue_descriptor(SPFIssueId.DISPOSITION_SOFTFAIL)
        if req_rank > _disposition_rank("~all"):
            issues.append(
                Issue(
                    id=SPFIssueId.DISPOSITION_SOFTFAIL,
                    severity=d.severity,
                    title="SPF soft fail (~all)",
                    description="~all is weaker than the configured required disposition.",
                    remediation=f"Use {req} if all legitimate mail sources are included.",
                )
            )
            specific_disposition_issue = True
        elif strict_recommendations:
            recommendations.append(
                Recommendation(
                    id=SPFRecommendationId.USE_DASH_ALL,
                    title="Prefer hard fail",
                    description="Consider -all for stronger protection if all senders are listed.",
                )
            )

    if weaker and not specific_disposition_issue:
        issues.append(
            Issue(
                id=SPFIssueId.SYNTAX_INVALID,
                severity=Severity.HIGH,
                title="SPF disposition weaker than required",
                description=f"Required {req}; found terminal mechanism {data.disposition!r}.",
                remediation=f"End the SPF record with {req} when all senders are listed.",
            )
        )

    if flat is not None and flat.effective_lookup_count > spf_config.lookup_limit:
        d = issue_descriptor(SPFIssueId.LOOKUP_LIMIT_EXCEEDED)
        issues.append(
            Issue(
                id=SPFIssueId.LOOKUP_LIMIT_EXCEEDED,
                severity=d.severity,
                title="SPF DNS lookup limit exceeded",
                description=(
                    f"Effective DNS lookups ({flat.effective_lookup_count}) exceed "
                    f"the configured limit ({spf_config.lookup_limit})."
                ),
                remediation="Reduce include: chains and mechanisms that trigger DNS lookups.",
            )
        )
        recommendations.append(
            Recommendation(
                id=SPFRecommendationId.REDUCE_LOOKUPS,
                title="Reduce SPF lookups",
                description="Flatten vendors into ip4/ip6 or fewer includes.",
            )
        )

    include_count = (
        len(flat.resolved_mechanisms) if flat is not None else len(data.includes)
    )
    if spf_config.max_includes is not None and include_count > spf_config.max_includes:
        issues.append(
            Issue(
                id=SPFIssueId.SYNTAX_INVALID,
                severity=Severity.HIGH,
                title="Too many include mechanisms",
                description=(
                    f"Found {include_count} expanded include traversals; "
                    f"max is {spf_config.max_includes}."
                ),
                remediation="Consolidate includes or raise max_includes in config if intentional.",
            )
        )

    return issues, recommendations


def build_suggested_record(includes: list[str], disposition: str) -> str:
    """Build a minimal suggested TXT string."""
    parts = [SPF1_PREFIX]
    for d in includes:
        parts.append(f"include:{d.rstrip('.')}")
    parts.append(disposition if disposition.endswith("all") else f"{disposition}all")
    return " ".join(parts)
