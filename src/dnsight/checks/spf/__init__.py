"""SPF check: check class and public API."""

from __future__ import annotations

from typing import Any

from dnsight.checks.base import BaseCheck
from dnsight.checks.spf.models import (
    FlattenedSPF,
    SPFData,
    SPFGenerateParams,
    SPFIssueId,
    SPFRecommendationId,
    issue_descriptor,
)
from dnsight.checks.spf.rules import (
    FlattenOutcome,
    build_suggested_record,
    extract_spf_config,
    flatten_spf,
    normalise_config,
    parse_spf_record,
    validate_spf_data,
)
from dnsight.core.config.blocks import Config, SpfConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.models import CheckResult, GeneratedRecord, Issue, Recommendation
from dnsight.core.registry import register
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.dns import get_resolver


__all__ = [
    "SPFCheck",
    "SPFData",
    "SPFGenerateParams",
    "SPFIssueId",
    "SPFRecommendationId",
    "FlattenOutcome",
    "check_spf",
    "flatten_spf",
    "generate_spf",
    "get_spf",
    "parse_spf_record",
]


@register
class SPFCheck(BaseCheck[SPFData, SPFGenerateParams]):
    """SPF check: CHECK + GENERATE; flatten via ``flatten_spf``."""

    name = "spf"
    capabilities = frozenset({Capability.CHECK, Capability.GENERATE})

    @staticmethod
    def parse_spf_record(raw: str) -> tuple[list[str], str, list[str]]:
        """Parse an SPF TXT string into tokens, disposition, and includes.

        See ``dnsight.checks.spf.rules.parse_spf_record``.
        """
        return parse_spf_record(raw)

    @staticmethod
    async def get_spf(
        domain: str, *, config: Config | SpfConfig | None = None
    ) -> SPFData:
        """Fetch and parse SPF for *domain* (apex TXT).

        Use ``flatten_spf`` from ``dnsight.checks.spf.rules`` if you need
        ``FlattenOutcome`` (include resolution errors, redirect flags).
        This method only stores ``SPFData.flattened`` (the ``FlattenedSPF`` view).

        Args:
            domain: Domain to query (e.g. ``"example.com"``).
            config: Optional full Config or SpfConfig.

        Returns:
            Parsed ``SPFData`` including flattened lookup view when DNS succeeds.

        Raises:
            CheckError: When the apex TXT lookup fails (same pattern as
                ``get_dmarc``).
        """
        spf_cfg = extract_spf_config(config)
        resolver = get_resolver()
        raw_list = await resolver.resolve_txt(domain)
        spf_records = [
            (s or "").strip()
            for s in raw_list
            if (s or "").strip().lower().startswith("v=spf1")
        ]
        if not spf_records:
            return SPFData(
                raw_record="",
                disposition="",
                lookup_count=0,
                includes=[],
                mechanisms=[],
                flattened=None,
                suggested_record=None,
            )
        raw = spf_records[0]
        tokens, disp, includes = parse_spf_record(raw)
        outcome = await flatten_spf(
            domain,
            resolver,
            allow_redirect=spf_cfg.allow_redirect,
            lookup_limit=spf_cfg.lookup_limit,
        )
        suggested = build_suggested_record(includes, spf_cfg.required_disposition)
        return SPFData(
            raw_record=raw,
            disposition=disp,
            lookup_count=outcome.flat.effective_lookup_count,
            includes=includes,
            mechanisms=tokens,
            flattened=outcome.flat,
            suggested_record=suggested,
        )

    @staticmethod
    async def check_spf(  # NOSONAR S3776
        domain: str, *, config: Config | SpfConfig | None = None
    ) -> CheckResult[SPFData]:
        spf_cfg, strict = normalise_config(config)
        resolver = get_resolver()
        try:
            raw_list = await resolver.resolve_txt(domain)
        except CheckError as exc:
            return CheckResult(
                status=Status.FAILED,
                data=None,
                raw=None,
                issues=[],
                recommendations=[],
                error=str(exc),
            )

        spf_records = [
            (s or "").strip()
            for s in raw_list
            if (s or "").strip().lower().startswith("v=spf1")
        ]

        if len(spf_records) > 1:
            raw = spf_records[0]
            tokens, disp, includes = parse_spf_record(raw)
            try:
                multi_outcome = await flatten_spf(
                    domain,
                    resolver,
                    allow_redirect=spf_cfg.allow_redirect,
                    lookup_limit=spf_cfg.lookup_limit,
                )
            except CheckError:
                multi_outcome = FlattenOutcome(
                    flat=FlattenedSPF(effective_lookup_count=0, resolved_mechanisms=[])
                )
            data = SPFData(
                raw_record=raw,
                disposition=disp,
                lookup_count=multi_outcome.flat.effective_lookup_count,
                includes=includes,
                mechanisms=tokens,
                flattened=multi_outcome.flat,
                suggested_record=build_suggested_record(
                    includes, spf_cfg.required_disposition
                ),
            )
            multiple_issues = [
                Issue(
                    id=SPFIssueId.MULTIPLE_RECORDS,
                    severity=issue_descriptor(SPFIssueId.MULTIPLE_RECORDS).severity,
                    title="Multiple SPF TXT records",
                    description="More than one TXT record contains v=spf1; only one SPF policy is valid.",
                    remediation="Publish a single SPF TXT at the domain apex.",
                )
            ]
            return CheckResult(
                status=Status.COMPLETED,
                data=data,
                raw=raw,
                issues=multiple_issues,
                recommendations=[],
                error=None,
            )

        if not spf_records:
            return CheckResult(
                status=Status.COMPLETED,
                data=None,
                raw=None,
                issues=[
                    Issue(
                        id=SPFIssueId.RECORD_MISSING,
                        severity=issue_descriptor(SPFIssueId.RECORD_MISSING).severity,
                        title="SPF record missing",
                        description="No v=spf1 TXT record found at the domain apex.",
                        remediation="Publish an SPF TXT record (v=spf1 ...) for this domain.",
                    )
                ],
                recommendations=[],
                error=None,
            )

        raw = spf_records[0]
        tokens, disp, includes = parse_spf_record(raw)

        spf_outcome: FlattenOutcome | None
        try:
            spf_outcome = await flatten_spf(
                domain,
                resolver,
                allow_redirect=spf_cfg.allow_redirect,
                lookup_limit=spf_cfg.lookup_limit,
            )
        except CheckError:
            spf_outcome = None

        flat = spf_outcome.flat if spf_outcome else None
        data = SPFData(
            raw_record=raw,
            disposition=disp,
            lookup_count=flat.effective_lookup_count if flat else 0,
            includes=includes,
            mechanisms=tokens,
            flattened=flat,
            suggested_record=build_suggested_record(
                includes, spf_cfg.required_disposition
            ),
        )

        issues: list[Issue] = []
        recommendations: list[Recommendation] = []

        if spf_outcome is not None:
            if spf_outcome.redirect_disallowed:
                rd = issue_descriptor(SPFIssueId.REDIRECT_NOT_ALLOWED)
                issues.append(
                    Issue(
                        id=SPFIssueId.REDIRECT_NOT_ALLOWED,
                        severity=rd.severity,
                        title="SPF redirect not allowed by config",
                        description=(
                            "This record uses redirect= but allow_redirect is false in config."
                        ),
                        remediation="Remove redirect= or set spf.allow_redirect to true.",
                    )
                )
            for failed_domain in spf_outcome.include_resolution_errors:
                syn = issue_descriptor(SPFIssueId.SYNTAX_INVALID)
                issues.append(
                    Issue(
                        id=SPFIssueId.SYNTAX_INVALID,
                        severity=syn.severity,
                        title="SPF include could not be resolved",
                        description=f"DNS lookup failed for include target {failed_domain!r}.",
                        remediation="Fix or remove the broken include: reference.",
                    )
                )
            if flat is not None:
                vi, vr = validate_spf_data(data, flat, spf_cfg, strict)
                issues.extend(vi)
                recommendations.extend(vr)
        else:
            syn = issue_descriptor(SPFIssueId.SYNTAX_INVALID)
            issues.append(
                Issue(
                    id=SPFIssueId.SYNTAX_INVALID,
                    severity=syn.severity,
                    title="SPF flatten failed",
                    description="Could not complete SPF expansion (DNS error at apex).",
                    remediation="Ensure the domain resolves and TXT records are reachable.",
                )
            )

        if not disp:
            issues.append(
                Issue(
                    id=SPFIssueId.SYNTAX_INVALID,
                    severity=issue_descriptor(SPFIssueId.SYNTAX_INVALID).severity,
                    title="SPF missing terminal all mechanism",
                    description="The record should end with +all, -all, ~all, or ?all.",
                    remediation="Add a default result mechanism such as -all.",
                )
            )

        return CheckResult(
            status=Status.COMPLETED,
            data=data,
            raw=raw,
            issues=issues,
            recommendations=recommendations,
            error=None,
        )

    @staticmethod
    def generate_spf(
        *,
        params: SPFGenerateParams | None = None,
        config: Config | SpfConfig | None = None,
    ) -> GeneratedRecord:
        if params is None and config is not None:
            params = SPFGenerateParams.from_config(extract_spf_config(config))
        p = params or SPFGenerateParams()
        value = build_suggested_record(p.includes, p.disposition)
        return GeneratedRecord(record_type=RecordType.TXT, host="@", value=value)

    async def _get(self, domain: str, *, config: Any | None = None) -> SPFData:
        return await self.get_spf(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[SPFData]:
        return await self.check_spf(domain, config=config)

    def _generate(self, *, params: SPFGenerateParams) -> GeneratedRecord:
        return self.generate_spf(params=params)


check_spf = SPFCheck.check_spf
get_spf = SPFCheck.get_spf
generate_spf = SPFCheck.generate_spf
