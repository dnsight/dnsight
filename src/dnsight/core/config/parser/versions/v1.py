"""V1 config format parser.

Maps the v1 YAML schema (see examples/v1.yaml) into a ConfigManager.

Key v1 field mappings:
- ``dmarc.required_policy`` → ``DmarcConfig.policy``
- ``rps`` / ``concurrency`` at rule level → ``ThrottleConfig``
- ``include: "*"`` with no ``exclude`` → default config + checks
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, TypeVar

from dnsight.core.config.blocks import (
    CaaConfig,
    Config,
    DkimConfig,
    DmarcConfig,
    DnssecConfig,
    HeadersConfig,
    MxConfig,
    ResolverConfig,
    SpfConfig,
    ThrottleConfig,
)
from dnsight.core.config.config_manager import ConfigManager
from dnsight.core.config.defaults import (
    DEFAULT_DNS_PROVIDER,
    DEFAULT_GLOBAL_CONCURRENCY_LIMIT,
    DEFAULT_GLOBAL_MAX_RPS,
)
from dnsight.core.config.targets import (
    ChecksReplace,
    Target,
    TargetChecks,
    TargetConfig,
    parse_checks,
)
from dnsight.core.exceptions import ConfigError
from dnsight.core.logger import get_logger
from dnsight.core.types import DNSProvider


_T = TypeVar("_T")


logger = get_logger(__name__)


__all__ = ["parse_v1"]


def parse_v1(data: dict[str, Any]) -> ConfigManager:
    """Parse a v1 config dict into a ConfigManager."""
    targets = _parse_targets(data.get("targets", []))
    resolver = _parse_resolver(data.get("resolver"))
    global_rps, global_concurrency = _parse_throttle(data.get("throttle"))
    strict_recommendations = data.get("strict_recommendations")
    default_config, default_checks, target_configs = _parse_config_rules(
        data.get("config", []), resolver, strict_recommendations
    )
    return ConfigManager(
        config_schema_version=int(data["version"]),
        targets=targets,
        target_configs=target_configs,
        default_target_config=default_config,
        default_target_checks=default_checks,
        global_max_rps=global_rps,
        global_max_concurrency=global_concurrency,
    )


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def _parse_targets(raw: list[dict[str, Any]]) -> list[Target]:
    """Build Target list. Entries with ``paths`` expand into one Target each."""
    targets: list[Target] = []
    for entry in raw:
        domain: str | None = entry.get("domain")
        if not domain:
            raise ConfigError("Each target must have a 'domain' key")
        paths: list[str] = entry.get("paths", ["/"])
        for path in paths:
            targets.append(Target(domain=domain, path=path))
    return targets


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def _parse_resolver(raw: dict[str, Any] | None) -> ResolverConfig:
    if raw is None:
        return ResolverConfig()
    return ResolverConfig(
        provider=DNSProvider(raw.get("provider", DEFAULT_DNS_PROVIDER))
    )


# ---------------------------------------------------------------------------
# Throttle (global)
# ---------------------------------------------------------------------------


def _parse_throttle(raw: dict[str, Any] | None) -> tuple[float, int]:
    if raw is None:
        return DEFAULT_GLOBAL_MAX_RPS, DEFAULT_GLOBAL_CONCURRENCY_LIMIT
    return (
        float(raw.get("rps", DEFAULT_GLOBAL_MAX_RPS)),
        int(raw.get("concurrency", DEFAULT_GLOBAL_CONCURRENCY_LIMIT)),
    )


# ---------------------------------------------------------------------------
# Config rules → default config/checks + per-pattern TargetConfig
# ---------------------------------------------------------------------------


def _parse_config_rules(
    rules: list[dict[str, Any]],
    resolver: ResolverConfig,
    strict_recommendations: bool | None = None,
) -> tuple[Config, TargetChecks, OrderedDict[str, TargetConfig]]:
    """Parse the ``config:`` list into a default config, default checks, and
    an ordered dict of pattern → TargetConfig.

    A rule with ``include: "*"`` and no ``exclude`` is treated as the default;
    its config is merged into the base and its checks become the default set.
    """
    default_config = Config(resolver=resolver)
    if strict_recommendations is not None:
        default_config = default_config.merge(
            Config(strict_recommendations=strict_recommendations)
        )
    default_checks = TargetChecks()
    target_configs: OrderedDict[str, TargetConfig] = OrderedDict()

    has_default_rule = False

    for idx, rule in enumerate(rules):
        include: str | None = rule.get("include")
        if not include:
            raise ConfigError(f"Config rule {idx} missing 'include'")

        exclude = _normalise_exclude(rule.get("exclude"))
        checks_update = parse_checks(rule.get("checks"))
        config = _build_rule_config(rule)

        is_default = include == "*" and not exclude
        if is_default:
            default_config = default_config.merge(config)
            if isinstance(checks_update, ChecksReplace):
                default_checks = TargetChecks.from_enabled(checks_update.enabled)
            has_default_rule = True
        else:
            target_configs[include] = TargetConfig(
                include=include,
                precedence=idx,
                config=config,
                exclude=exclude,
                checks=checks_update,
            )

    if not has_default_rule:
        logger.warning(
            "No default rule found, using empty default config and checks. It is advised to set global defaults (even if empty)"
        )
    return default_config, default_checks, target_configs


def _normalise_exclude(raw: str | list[str] | None) -> list[str] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return [raw]
    return list(raw)


# ---------------------------------------------------------------------------
# Rule → Config
# ---------------------------------------------------------------------------

_V1_DMARC_FIELD_MAP: dict[str, str] = {
    "required_policy": "policy",
    "rua_required": "rua_required",
    "target_policy": "target_policy",
    "ruf_required": "ruf_required",
    "expected_rua": "expected_rua",
    "expected_ruf": "expected_ruf",
    "minimum_pct": "minimum_pct",
    "require_strict_alignment": "require_strict_alignment",
    "subdomain_policy_minimum": "subdomain_policy_minimum",
}


def _build_rule_config(rule: dict[str, Any]) -> Config:  # NOSONAR S3776
    """Extract config-level keys from a rule dict and return a Config."""
    kwargs: dict[str, Any] = {}

    throttle_kw: dict[str, Any] = {}
    if "rps" in rule:
        throttle_kw["global_max_rps"] = float(rule["rps"])
    if "concurrency" in rule:
        throttle_kw["global_max_concurrency"] = int(rule["concurrency"])
    if throttle_kw:
        kwargs["throttle"] = ThrottleConfig(**throttle_kw)

    if "dmarc" in rule and isinstance(rule["dmarc"], dict):
        kwargs["dmarc"] = _remap_fields(DmarcConfig, rule["dmarc"], _V1_DMARC_FIELD_MAP)

    if "dkim" in rule and isinstance(rule["dkim"], dict):
        kwargs["dkim"] = DkimConfig(**rule["dkim"])

    if "mx" in rule and isinstance(rule["mx"], dict):
        kwargs["mx"] = MxConfig(**rule["mx"])

    if "headers" in rule and isinstance(rule["headers"], dict):
        kwargs["headers"] = HeadersConfig(**rule["headers"])

    if "caa" in rule and isinstance(rule["caa"], dict):
        kwargs["caa"] = CaaConfig(**rule["caa"])

    if "spf" in rule and isinstance(rule["spf"], dict):
        kwargs["spf"] = SpfConfig(**rule["spf"])

    if "dnssec" in rule and isinstance(rule["dnssec"], dict):
        kwargs["dnssec"] = DnssecConfig(**rule["dnssec"])

    return Config(**kwargs) if kwargs else Config()


def _remap_fields(  # NOSONAR S6796
    cls: type[_T], raw: dict[str, Any], field_map: dict[str, str]
) -> _T:
    """Build a config block by remapping v1 YAML keys to model field names."""
    kw: dict[str, Any] = {}
    for yaml_key, model_field in field_map.items():
        if yaml_key in raw:
            kw[model_field] = raw[yaml_key]
    return cls(**kw)
