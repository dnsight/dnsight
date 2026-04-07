"""Generic factories for :mod:`dnsight.sdk.aliases` (orchestrator-backed checks / generate).

Each registered check has a matching attribute on :class:`~dnsight.core.config.blocks.Config`
(``"dmarc"`` → ``Config.dmarc``, etc.). Optional programmatic overrides use the same field
name via ``config_slice=`` merged into ``config=`` (or into a fresh :class:`Config`).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Generic, Protocol, TypeVar

from dnsight.checks.base import BaseCheckData, BaseGenerateParams
from dnsight.core.config import Config, ConfigManager
from dnsight.core.config.mergeable import MergeableConfig
from dnsight.core.models import CheckResult, GeneratedRecord
from dnsight.sdk.generate import generate
from dnsight.sdk.run import run_check, run_check_sync


__all__ = [
    "CheckRunAsyncCallable",
    "CheckRunBinder",
    "CheckRunSyncCallable",
    "GenerateBinder",
    "GenerateCallable",
    "merge_check_programmatic_config",
]

CheckDataT = TypeVar("CheckDataT", bound=BaseCheckData)
# Contravariant: used only as ``config_slice`` on protocol callables (mypy ``misc``).
SliceT = TypeVar("SliceT", bound=MergeableConfig, contravariant=True)
ParamsT = TypeVar("ParamsT", bound=BaseGenerateParams)
ParamsT_contra = TypeVar("ParamsT_contra", bound=BaseGenerateParams, contravariant=True)


def merge_check_programmatic_config(
    config: Config | None, config_slice: MergeableConfig | None, *, config_field: str
) -> Config | None:
    """Merge optional root config and a single slice for programmatic single-check runs.

    Returns:
        ``None`` when both *config* and *config_slice* are ``None`` (YAML / discovery only).
    """
    if config is None and config_slice is None:
        return None
    base = config if config is not None else Config()
    if config_slice is None:
        return base
    return base.model_copy(update={config_field: config_slice})


def _check_run_docstring(
    check_name: str, config_field: str, *, sync: bool, summary: str | None
) -> str:
    """Google-style docstring for check alias callables."""
    head = summary or (
        f'Synchronously run the "{check_name}" check.'
        if sync
        else f'Run the "{check_name}" check.'
    )
    ref = "run_check_sync" if sync else "run_check"
    return f"""{head}

Args:
    domain: Domain or target string passed to :meth:`ConfigManager.resolve`.
    config_path: YAML config path; ignored when *mgr* is set.
    mgr: Pre-built :class:`~dnsight.core.config.config_manager.ConfigManager`;
        wins over *config_path* and programmatic ``config`` / ``config_slice``.
    config: Optional root :class:`~dnsight.core.config.blocks.Config` when *mgr*
        is unset (merged with YAML / discovery when a file applies).
    config_slice: Optional config slice merged into *config* (or a fresh
        :class:`~dnsight.core.config.blocks.Config` when *config* is omitted).
        Sets ``Config.{config_field}`` and overrides that field from *config*
        when both are set.

Returns:
    :class:`~dnsight.core.models.CheckResult` for this check.

See Also:
    :func:`~dnsight.sdk.run.{ref}`.
"""


class CheckRunSyncCallable(Protocol[CheckDataT, SliceT]):
    """Typed sync single-check runner produced by :class:`CheckRunBinder`."""

    __name__: str
    __doc__: str | None

    def __call__(
        self,
        domain: str,
        *,
        config_path: Path | str | None = None,
        mgr: ConfigManager | None = None,
        config: Config | None = None,
        config_slice: SliceT | None = None,
    ) -> CheckResult[CheckDataT]:
        """Run the check synchronously."""
        ...


class CheckRunAsyncCallable(Protocol[CheckDataT, SliceT]):
    """Typed async single-check runner produced by :class:`CheckRunBinder`."""

    __name__: str
    __doc__: str | None

    def __call__(
        self,
        domain: str,
        *,
        config_path: Path | str | None = None,
        mgr: ConfigManager | None = None,
        config: Config | None = None,
        config_slice: SliceT | None = None,
    ) -> Awaitable[CheckResult[CheckDataT]]:
        """Run the check asynchronously."""
        ...


class GenerateCallable(Protocol[ParamsT_contra]):
    """Typed ``generate_<name>`` callable produced by :class:`GenerateBinder`."""

    __name__: str
    __doc__: str | None

    def __call__(self, *, params: ParamsT_contra | None = None) -> GeneratedRecord:
        """Generate a record for the bound check name."""
        ...


def _generate_docstring(
    check_name: str, *, summary: str | None, params_optional: bool
) -> str:
    head = summary or f'Generate output for the "{check_name}" check.'
    if params_optional:
        params_desc = (
            "Generation parameters; may be omitted when this check supplies "
            "a default (e.g. headers → HSTS)."
        )
    else:
        params_desc = "Parameters for :func:`~dnsight.sdk.generate.generate`."
    return f"""{head}

Args:
    params: {params_desc}

Returns:
    :class:`~dnsight.core.models.GeneratedRecord`.

See Also:
    :func:`~dnsight.sdk.generate.generate`.
"""


class CheckRunBinder(Generic[CheckDataT, SliceT]):  # NOSONAR S6792
    """Bind a registry check name to typed :func:`~dnsight.sdk.run.run_check` helpers."""

    __slots__ = ("_check_name", "_config_field", "_summary")

    def __init__(
        self,
        check_name: str,
        *,
        config_field: str | None = None,
        summary: str | None = None,
    ) -> None:
        self._check_name = check_name
        self._config_field = config_field or check_name
        self._summary = summary

    def async_run(self) -> CheckRunAsyncCallable[CheckDataT, SliceT]:
        """Build the async ``check_<name>`` callable."""
        check_name = self._check_name
        field = self._config_field
        doc = _check_run_docstring(check_name, field, sync=False, summary=self._summary)

        async def _run(
            domain: str,
            *,
            config_path: Path | str | None = None,
            mgr: ConfigManager | None = None,
            config: Config | None = None,
            config_slice: SliceT | None = None,
        ) -> CheckResult[CheckDataT]:
            import dnsight.checks  # noqa: F401

            pc: Config | None = None
            if mgr is None:
                pc = merge_check_programmatic_config(
                    config, config_slice, config_field=field
                )
            return await run_check(
                check_name, domain, config_path=config_path, mgr=mgr, config=pc
            )

        _run.__name__ = f"check_{check_name}"
        _run.__doc__ = doc
        return _run

    def sync(self) -> CheckRunSyncCallable[CheckDataT, SliceT]:
        """Build the ``check_<name>_sync`` callable."""
        check_name = self._check_name
        field = self._config_field
        doc = _check_run_docstring(check_name, field, sync=True, summary=self._summary)

        def _sync(
            domain: str,
            *,
            config_path: Path | str | None = None,
            mgr: ConfigManager | None = None,
            config: Config | None = None,
            config_slice: SliceT | None = None,
        ) -> CheckResult[CheckDataT]:
            import dnsight.checks  # noqa: F401

            pc: Config | None = None
            if mgr is None:
                pc = merge_check_programmatic_config(
                    config, config_slice, config_field=field
                )
            return run_check_sync(
                check_name, domain, config_path=config_path, mgr=mgr, config=pc
            )

        _sync.__name__ = f"check_{check_name}_sync"
        _sync.__doc__ = doc
        return _sync


class GenerateBinder(Generic[ParamsT]):  # NOSONAR S6792
    """Bind a registry check name to :func:`~dnsight.sdk.generate.generate`."""

    __slots__ = ("_check_name", "_default_factory", "_summary")

    def __init__(
        self,
        check_name: str,
        *,
        default_factory: Callable[[], ParamsT] | None = None,
        summary: str | None = None,
    ) -> None:
        self._check_name = check_name
        self._default_factory = default_factory
        self._summary = summary

    def build(self) -> GenerateCallable[ParamsT]:
        """Return ``generate_<name>(*, params=...)``."""
        check_name = self._check_name
        default_factory = self._default_factory
        doc = _generate_docstring(
            check_name,
            summary=self._summary,
            params_optional=default_factory is not None,
        )

        def _gen(*, params: ParamsT | None = None) -> GeneratedRecord:
            import dnsight.checks  # noqa: F401

            if params is not None:
                p = params
            elif default_factory is not None:
                p = default_factory()
            else:
                raise TypeError(
                    f"generate_{check_name}() missing required keyword argument 'params'"
                )
            return generate(check_name, params=p)

        _gen.__name__ = f"generate_{check_name}"
        _gen.__doc__ = doc
        return _gen
