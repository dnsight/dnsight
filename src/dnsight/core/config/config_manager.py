"""ConfigManager for target-based config resolution.

Provides pattern matching, per-target merged config and checks, and
a per-run cache so each (domain, path) is resolved once.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from dnsight.core.config.blocks import Config
from dnsight.core.config.defaults import (
    DEFAULT_GLOBAL_CONCURRENCY_LIMIT,
    DEFAULT_GLOBAL_MAX_RPS,
)
from dnsight.core.config.pattern import Pattern
from dnsight.core.config.targets import (
    ChecksDelta,
    ChecksReplace,
    ChecksUpdate,
    ResolvedTargetConfig,
    Target,
    TargetChecks,
    TargetConfig,
)


__all__ = ["ConfigManager"]


@dataclass(frozen=True)
class ConfigManager:
    """Config manager for dnsight.

    resolved_configs is a mutable per-instance cache (not thread-safe) used to
    avoid repeated pattern matching and merge when resolving the same target.

    If default_target_checks has no checks enabled, at least one matching rule
    must set checks (e.g. via ChecksReplace) or no checks will run for that target.

    ``config_schema_version`` is ``0`` when the manager was built without a YAML
    file (e.g. programmatic defaults); otherwise it matches the file's ``version``.
    """

    targets: list[Target]
    target_configs: OrderedDict[str, TargetConfig]
    default_target_config: Config
    default_target_checks: TargetChecks
    # Frozen does not prevent mutating this dict; it is a cache.
    resolved_configs: dict[str, ResolvedTargetConfig] = field(default_factory=dict)
    global_max_rps: float = field(default=DEFAULT_GLOBAL_MAX_RPS)
    global_max_concurrency: int = field(default=DEFAULT_GLOBAL_CONCURRENCY_LIMIT)
    config_schema_version: int = field(default=0)

    @staticmethod
    def target_string(domain_or_target: str | Target, path: str | None = None) -> str:
        """Get the string representation of a target (domain/path or Target)."""
        if isinstance(domain_or_target, Target):
            return Pattern.normalise(domain_or_target.domain, domain_or_target.path)
        return Pattern.normalise(domain_or_target, path or "/")

    def _get_matching_configs(self, target: str) -> list[TargetConfig]:
        """All configs that match the target in order of precedence."""
        out: list[TargetConfig] = []
        for pattern, config in self.target_configs.items():
            # If not match then continue
            if not Pattern.matches(pattern, target):
                continue
            # If exclude then skip
            if config.exclude and any(
                Pattern.matches(ex, target) for ex in config.exclude
            ):
                continue
            # Matches and not excluded, add to list
            out.append(config)
        return out

    def _resolve_checks(
        self, base: TargetChecks, update: ChecksUpdate | None
    ) -> TargetChecks:
        """Apply a replace or delta checks update to the current base. No string parsing."""
        if update is None:
            return base
        if isinstance(update, ChecksReplace):
            return TargetChecks.from_enabled(update.enabled)
        if isinstance(update, ChecksDelta):
            return base.apply_delta(add=update.add, remove=update.remove)
        raise AssertionError(f"Unexpected checks update type: {type(update)}")

    def _internal_resolve(self, target: str) -> ResolvedTargetConfig:
        """Internal resolve for a target."""
        if target in self.resolved_configs:
            return self.resolved_configs[target]
        configs = self._get_matching_configs(target)
        base_config = self.default_target_config
        base_checks = self.default_target_checks
        for cfg in configs:
            base_config = base_config.merge(cfg.config)
            base_checks = self._resolve_checks(base_checks, cfg.checks)
        resolved_config = ResolvedTargetConfig(checks=base_checks, config=base_config)
        self.resolved_configs[target] = resolved_config
        return resolved_config

    def resolve(
        self, domain_or_target: str | Target, path: str | None = None
    ) -> ResolvedTargetConfig:
        """Resolve the config for a target.

        Call forms: (Target); (domain: str, path: str | None); or a single
        normalised target string (domain or domain/path).
        """
        if isinstance(domain_or_target, Target):
            return self._internal_resolve(self.target_string(domain_or_target))
        if path is not None:
            return self._internal_resolve(self.target_string(domain_or_target, path))
        return self._internal_resolve(domain_or_target)
