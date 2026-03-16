"""DMARC check: check class and public API.

The check class provides static methods (get_dmarc, check_dmarc, generate_dmarc,
parse_dmarc_record) as the direct public API, and wires them into BaseCheck for
orchestrator use.
"""

from __future__ import annotations

from typing import Any

from dnsight.checks.base import BaseCheck
from dnsight.checks.dmarc.models import (
    DMARCData,
    DMARCGenerateParams,
    DMARCIssueId,
    DMARCRecommendationId,
)
from dnsight.checks.dmarc.rules import DMARCRules
from dnsight.core.config.blocks import Config, DmarcConfig
from dnsight.core.exceptions import CheckError
from dnsight.core.models import CheckResult, GeneratedRecord, Recommendation
from dnsight.core.registry import register
from dnsight.core.types import Capability, RecordType, Status
from dnsight.utils.dns import get_resolver


__all__ = [
    "DMARCCheck",
    "DMARCData",
    "DMARCGenerateParams",
    "DMARCIssueId",
    "DMARCRecommendationId",
    "check_dmarc",
    "generate_dmarc",
    "get_dmarc",
    "parse_dmarc_record",
]


# ---------------------------------------------------------------------------
# Check class
# ---------------------------------------------------------------------------


@register
class DMARCCheck(BaseCheck[DMARCData, DMARCGenerateParams]):
    """DMARC check implementation.

    Capabilities: CHECK, GENERATE.
    """

    name = "dmarc"
    capabilities = frozenset({Capability.CHECK, Capability.GENERATE})

    # -- Parser (public static for SDK use) --------------------------------

    @staticmethod
    def parse_dmarc_record(raw: str) -> DMARCData:
        """Parse a single DMARC TXT string into DMARCData.

        Uses defaults for missing tags. Safe to call with empty or malformed
        strings; invalid tag values are preserved in raw_record for validation.

        Args:
            raw: The raw TXT record string (e.g. "v=DMARC1; p=reject; pct=100").

        Returns:
            Parsed DMARCData with raw_record set to the input string.
        """
        raw = (raw or "").strip()
        state: dict[str, Any] = {
            "policy": "none",
            "subdomain_policy": None,
            "percentage": 100,
            "alignment_dkim": "r",
            "alignment_spf": "r",
            "rua": [],
            "ruf": [],
        }
        for part in raw.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            tag, _, value = part.partition("=")
            tag = tag.strip().lower()
            value = value.strip()
            if tag == "v":
                continue
            DMARCRules.apply_dmarc_tag(state, tag, value)
        return DMARCData(
            policy=state["policy"],
            subdomain_policy=state["subdomain_policy"],
            percentage=state["percentage"],
            alignment_dkim=state["alignment_dkim"],
            alignment_spf=state["alignment_spf"],
            rua=state["rua"],
            ruf=state["ruf"],
            raw_record=raw,
        )

    # -- Static methods (direct public API) --------------------------------

    @staticmethod
    async def get_dmarc(
        domain: str, *, config: Config | DmarcConfig | None = None
    ) -> DMARCData:
        """Fetch and parse the DMARC record for *domain*.

        Args:
            domain: Domain to query (e.g. ``"example.com"``).
            config: Optional full Config or DmarcConfig (only dmarc slice is used).

        Returns:
            Parsed ``DMARCData``.

        Raises:
            CheckError: When DNS lookup fails (e.g. no TXT record).
        """
        _ = DMARCRules.extract_dmarc_config(
            config
        )  # reserved for future use (e.g. timeout)
        resolver = get_resolver()
        name = f"_dmarc.{domain}"
        raw_list = await resolver.resolve_txt(name)

        record = ""
        for s in raw_list:
            if (s or "").strip().lower().startswith(DMARCRules.DMARC1_PREFIX):
                record = (s or "").strip()
                break
        if not record and raw_list:
            record = (raw_list[0] or "").strip()

        return DMARCCheck.parse_dmarc_record(record)

    @staticmethod
    async def check_dmarc(
        domain: str, *, config: Config | DmarcConfig | None = None
    ) -> CheckResult[DMARCData]:
        """Fetch, parse, and validate DMARC for *domain*.

        When config is a full Config, uses config.dmarc and config.strict_recommendations.
        When config is DmarcConfig or None, uses it (or default) and strict_recommendations=False.

        Args:
            domain: Domain to audit.
            config: Optional full Config or DmarcConfig.

        Returns:
            ``CheckResult[DMARCData]`` with status, data, issues, and recommendations.
        """
        dmarc_config, strict_recommendations = DMARCRules.normalise_config(config)
        try:
            raw_list = await get_resolver().resolve_txt(f"_dmarc.{domain}")
        except CheckError:
            return DMARCRules.result_missing_dns()

        record, issues = DMARCRules.process_raw_records(raw_list)
        if not record or not record.lower().startswith(DMARCRules.DMARC1_PREFIX):
            return DMARCRules.result_no_valid_record(record, issues, [])

        data = DMARCCheck.parse_dmarc_record(record)
        recommendations: list[Recommendation] = []
        for rule in (
            DMARCRules.rule_policy_strength,
            DMARCRules.rule_subdomain_policy,
            DMARCRules.rule_rua,
            DMARCRules.rule_ruf,
            DMARCRules.rule_pct,
            DMARCRules.rule_alignment,
        ):
            i, r = rule(data, dmarc_config, strict_recommendations)
            issues.extend(i)
            recommendations.extend(r)
        return CheckResult(
            status=Status.COMPLETED,
            data=data,
            raw=record,
            issues=issues,
            recommendations=recommendations,
            error=None,
        )

    @staticmethod
    def generate_dmarc(
        *,
        params: DMARCGenerateParams | None = None,
        config: Config | DmarcConfig | None = None,
    ) -> GeneratedRecord:
        """Generate a DMARC TXT record.

        Args:
            params: Generation params (preferred). If None and config is
                provided, params are built from config via ``from_config()``.
            config: Fallback — DmarcConfig or full Config. Used only when
                params is None.

        Returns:
            ``GeneratedRecord`` with record type ``TXT``, host ``_dmarc``.
        """
        if params is None and config is not None:
            dmarc_config = DMARCRules.extract_dmarc_config(config)
            params = DMARCGenerateParams.from_config(dmarc_config)
        p = params or DMARCGenerateParams(subdomain_policy=None)
        parts = ["v=DMARC1", f"p={p.policy}", f"pct={p.percentage}"]
        if p.subdomain_policy is not None:
            parts.append(f"sp={p.subdomain_policy}")
        parts.append(f"adkim={p.alignment_dkim}")
        parts.append(f"aspf={p.alignment_spf}")
        for uri in p.rua:
            parts.append(f"rua={uri}")
        for uri in p.ruf:
            parts.append(f"ruf={uri}")
        return GeneratedRecord(
            record_type=RecordType.TXT, host="_dmarc", value="; ".join(parts)
        )

    # -- Wiring to BaseCheck -----------------------------------------------

    async def _get(self, domain: str, *, config: Any | None = None) -> DMARCData:
        return await self.get_dmarc(domain, config=config)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[DMARCData]:
        return await self.check_dmarc(domain, config=config)

    def _generate(self, *, params: DMARCGenerateParams) -> GeneratedRecord:
        return self.generate_dmarc(params=params)


# ---------------------------------------------------------------------------
# Module-level aliases for convenience
# ---------------------------------------------------------------------------

get_dmarc = DMARCCheck.get_dmarc
check_dmarc = DMARCCheck.check_dmarc
generate_dmarc = DMARCCheck.generate_dmarc
parse_dmarc_record = DMARCCheck.parse_dmarc_record
