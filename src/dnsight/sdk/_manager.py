"""ConfigManager resolution for SDK entrypoints.

Single precedence rules for :func:`config_manager` (YAML / discovery only) and
:func:`resolve_run_manager` (single-check runs with optional programmatic
:class:`~dnsight.core.config.blocks.Config` overlay).
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

from dnsight.core.config import (
    Config,
    ConfigManager,
    TargetChecks,
    TargetConfig,
    config_manager_from_discovered,
    config_manager_from_file,
    discover_config_path,
)


__all__ = ["config_manager", "minimal_config_manager", "resolve_run_manager"]


def config_manager(
    *, mgr: ConfigManager | None = None, config_path: Path | str | None = None
) -> ConfigManager:
    """Return a :class:`ConfigManager` for SDK runs.

    Precedence:

    1. If *mgr* is set, return it (``config_path`` is ignored).
    2. Else if *config_path* is set, load from that YAML file.
    3. Else discover ``dnsight.yaml`` from the current working directory (or
       built-in defaults when no file exists).

    This is the only place SDK should construct a manager unless the caller
    builds one explicitly and passes *mgr*, except for
    :func:`resolve_run_manager` which also builds **synthetic** managers for
    programmatic single-check runs.

    Args:
        mgr: Pre-built manager.
        config_path: Explicit YAML path.

    Returns:
        The manager to pass to the orchestrator.
    """
    if mgr is not None:
        return mgr
    if config_path is not None:
        return config_manager_from_file(config_path)
    return config_manager_from_discovered()


def minimal_config_manager(
    *, default_target_config: Config, enabled_checks: list[str]
) -> ConfigManager:
    """Build a minimal, synthetic :class:`ConfigManager` for SDK programmatic runs.

    The manager has a single catch-all rule (``include: "*"``), no manifest
    ``targets``, and ``default_target_config`` set to *default_target_config*.
    Enabled checks are exactly *enabled_checks* (typically one name for
    :func:`~dnsight.sdk.run.run_check`).

    This shape matches tests such as ``_mgr_dmarc_only`` in ``test_orchestrator``
    and is **not** equivalent to a full multi-row YAML manifest: pattern nuance
    beyond the catch-all rule is flattened into *default_target_config*.

    Args:
        default_target_config: Merged :class:`~dnsight.core.config.blocks.Config`
            to use as the baseline for every target string.
        enabled_checks: Registry check names to enable for this run.

    Returns:
        A manager suitable for :func:`~dnsight.orchestrator.run_check_for_target`.
    """
    rules: OrderedDict[str, TargetConfig] = OrderedDict()
    rules["*"] = TargetConfig(include="*", precedence=0, config=Config(), checks=None)
    return ConfigManager(
        targets=[],
        target_configs=rules,
        default_target_config=default_target_config,
        default_target_checks=TargetChecks.from_enabled(enabled_checks),
    )


def _base_manager_from_path_or_discovery(
    config_path: Path | str | None,
) -> ConfigManager | None:
    """Load YAML from *config_path* or discovery; return ``None`` if no file."""
    if config_path is not None:
        return config_manager_from_file(config_path)
    discovered = discover_config_path()
    if discovered is None:
        return None
    return config_manager_from_file(discovered)


def resolve_run_manager(
    *,
    domain: str,
    mgr: ConfigManager | None = None,
    config_path: Path | str | None = None,
    program_config: Config | None = None,
    single_check: str | None = None,
) -> ConfigManager:
    """Resolve a :class:`ConfigManager` for single-check SDK entrypoints.

    Used by :func:`~dnsight.sdk.run.run_check` when optional programmatic
    ``config=`` is supplied. :func:`run_domain` and :func:`run_targets` use
    :func:`config_manager` only (no programmatic overlay in v1).

    **Precedence**

    1. **``mgr``** — If set, return it unchanged. Inline ``config=`` is ignored
       for that call (same as passing a pre-built manager today).
    2. **No programmatic config** — If ``program_config`` is ``None``, behave
       like :func:`config_manager` (ignore *domain* and *single_check*).
    3. **Programmatic config** — If ``program_config`` is not ``None``:

       - If there is **no** YAML file (neither explicit *config_path* nor a
         discovered ``dnsight.yaml``), build :func:`minimal_config_manager`
         with ``default_target_config=program_config`` and
         ``enabled_checks=[single_check]``.
       - If a YAML file exists, load it, :meth:`ConfigManager.resolve` the
         *domain* to get merged config, then merge ``program_config`` on top
         (explicit fields in ``program_config`` win). Build
         :func:`minimal_config_manager` with that merged config and
         ``enabled_checks=[single_check]``.

    The synthetic manager from (3) uses a single catch-all rule; multi-pattern
    YAML behaviour is collapsed into one merged :class:`~dnsight.core.config.blocks.Config`
    for that run.

    Args:
        domain: Target string passed to :meth:`ConfigManager.resolve` when a
            YAML base exists.
        mgr: Optional pre-built manager.
        config_path: Explicit YAML path (optional).
        program_config: Inline config overlay; ``None`` means file/discovery only.
        single_check: Registry name for the check being run; required when
            ``program_config`` is not ``None``.

    Returns:
        Manager to pass to :func:`~dnsight.orchestrator.run_check_for_target`.

    Raises:
        ValueError: If ``program_config`` is set but ``single_check`` is ``None``.
    """
    if mgr is not None:
        return mgr
    if program_config is None:
        return config_manager(mgr=None, config_path=config_path)
    if single_check is None:
        msg = "single_check is required when program_config is not None"
        raise ValueError(msg)

    base = _base_manager_from_path_or_discovery(config_path)
    if base is None:
        return minimal_config_manager(
            default_target_config=program_config, enabled_checks=[single_check]
        )
    merged_cfg = base.resolve(domain).config.merge(program_config)
    return minimal_config_manager(
        default_target_config=merged_cfg, enabled_checks=[single_check]
    )
