"""Base classes for dnsight checks.

``BaseCheckData`` — frozen Pydantic base for all parsed check data.
``BaseGenerateParams`` — frozen Pydantic base for all generation parameter types.
``BaseCheck[CheckDataT, GenerateParamsT]`` — ABC with capability-gated ``get``,
``check``, and ``generate`` methods plus throttle support. Checks that only
implement CHECK (no GENERATE) still use a second type parameter, typically
``BaseGenerateParams``, so the class signature stays uniform—see ``DKIMCheck``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

from dnsight.core.exceptions import CapabilityError
from dnsight.core.models import CheckResult, GeneratedRecord
from dnsight.core.throttle import ThrottleManager
from dnsight.core.types import Capability


__all__ = ["BaseCheck", "BaseCheckData", "CheckDataT"]


class BaseCheckData(BaseModel):
    """Abstract base for all check data types.

    Every check's parsed data model (e.g. ``DMARCData``, ``SPFData``)
    inherits from this. Provides a common type bound for generics and a
    place to add shared behaviour later.
    """

    model_config = ConfigDict(frozen=True)


CheckDataT = TypeVar("CheckDataT", bound=BaseCheckData)


class BaseGenerateParams(BaseModel):
    """Base class for all generation parameter types."""

    model_config = ConfigDict(frozen=True)


GenerateParamsT = TypeVar("GenerateParamsT", bound=BaseGenerateParams)


class BaseCheck(ABC, Generic[CheckDataT, GenerateParamsT]):  # NOSONAR S6792
    """Abstract base for all checks.

    Subclasses declare ``name`` and ``capabilities`` as class variables,
    then implement the ``_get`` and ``_check`` abstract methods (and
    optionally ``_generate``).

    **Type parameters:** ``GenerateParamsT`` is the generation-params type for
    ``generate()`` / ``_generate``. CHECK-only checks use ``BaseGenerateParams``
    (or another concrete placeholder) as the second parameter so the generic
    matches subclasses that do declare GENERATE.

    The public methods ``get()``, ``check()``, and ``generate()`` handle
    capability gating and throttle before delegating to the private
    implementations.

    Concrete checks also provide **static methods** (e.g.
    ``check_dmarc``, ``get_dmarc``) that are the direct public API for
    SDK and CLI callers. The ``_check`` / ``_get`` implementations
    simply delegate to those static methods.
    """

    name: ClassVar[str]
    """Stable lowercase identifier (e.g. ``"dmarc"``, ``"spf"``)."""

    capabilities: ClassVar[frozenset[Capability]]
    """Declared capabilities (CHECK, GENERATE, FLATTEN)."""

    # -- Public API (capability gate + throttle) ---------------------------

    async def get(  # NOSONAR S6796
        self,
        domain: str,
        *,
        config: Any | None = None,
        throttler: ThrottleManager | None = None,
    ) -> CheckDataT:
        """Fetch and parse current record(s) without validation.

        Args:
            domain: Domain to query.
            config: Optional check-specific config.
            throttler: Optional throttler; ``wait()`` is called before I/O.

        Returns:
            Parsed check data.
        """
        if throttler is not None:
            await throttler.wait()
        return await self._get(domain, config=config)

    async def check(  # NOSONAR S6796
        self,
        domain: str,
        *,
        config: Any | None = None,
        throttler: ThrottleManager | None = None,
    ) -> CheckResult[CheckDataT]:
        """Fetch, parse, and validate — returns result with issues.

        Args:
            domain: Domain to audit.
            config: Optional check-specific config.
            throttler: Optional throttler; ``wait()`` is called before I/O.

        Raises:
            CapabilityError: If CHECK is not in this check's capabilities.

        Returns:
            A ``CheckResult`` containing parsed data, issues, and status.
        """
        if Capability.CHECK not in self.capabilities:
            raise CapabilityError(self.name, Capability.CHECK)
        if throttler is not None:
            await throttler.wait()
        return await self._check(domain, config=config)

    def generate(self, *, params: GenerateParamsT) -> GeneratedRecord:
        """Generate a DNS record from config.

        Args:
            params: Parameters for generation.

        Raises:
            CapabilityError: If GENERATE is not in this check's capabilities.

        Returns:
            A ``GeneratedRecord`` with record type, host, and value.
        """
        if Capability.GENERATE not in self.capabilities:
            raise CapabilityError(self.name, Capability.GENERATE)
        return self._generate(params=params)

    # -- Abstract / override methods --------------------------------------

    @abstractmethod
    async def _get(self, domain: str, *, config: Any | None = None) -> CheckDataT:
        """Fetch and parse — implement in subclass."""
        ...

    @abstractmethod
    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[CheckDataT]:
        """Fetch, parse, validate — implement in subclass."""
        ...

    def _generate(self, *, params: GenerateParamsT) -> GeneratedRecord:
        """Generate a record — override in subclass if GENERATE capability.

        This is a missing-override fallback, not capability gating (that is done in generate()).
        """
        # Subclass declares GENERATE but did not override _generate.
        raise NotImplementedError(
            "Subclass declares GENERATE but did not override _generate."
        )
