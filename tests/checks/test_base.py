"""Tests for checks/base.py — BaseCheckData and BaseCheck ABC."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from dnsight.checks.base import BaseCheck, BaseCheckData, BaseGenerateParams
from dnsight.core.exceptions import CapabilityError
from dnsight.core.models import CheckResult, GeneratedRecord, Issue
from dnsight.core.throttle import ThrottleManager
from dnsight.core.types import Capability, RecordType, Severity, Status


# -- Concrete fixtures -------------------------------------------------------


class StubData(BaseCheckData):
    """Minimal concrete check data for testing."""

    value: str = "test"


class StubParams(BaseGenerateParams):
    """Minimal params for FullCheck generate."""

    pass


class FullCheck(BaseCheck[StubData, StubParams]):
    """Concrete check with CHECK + GENERATE capabilities."""

    name: ClassVar[str] = "stub"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.CHECK, Capability.GENERATE}
    )

    async def _get(self, domain: str, *, config: Any | None = None) -> StubData:
        return StubData(value=domain)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[StubData]:
        data = StubData(value=domain)
        issues = []
        if domain == "bad.example.com":
            issues.append(
                Issue(
                    id="stub.bad",
                    severity=Severity.HIGH,
                    title="Bad domain",
                    description="Domain is bad",
                    remediation="Fix it",
                )
            )
        return CheckResult(status=Status.COMPLETED, data=data, issues=issues)

    def _generate(self, *, params: StubParams) -> GeneratedRecord:
        return GeneratedRecord(
            record_type=RecordType.TXT, host="_stub", value="v=STUB1"
        )


class CheckOnlyCheck(BaseCheck[StubData, StubParams]):
    """Concrete check with CHECK capability only (no GENERATE)."""

    name: ClassVar[str] = "checkonly"
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.CHECK})

    async def _get(self, domain: str, *, config: Any | None = None) -> StubData:
        return StubData(value=domain)

    async def _check(
        self, domain: str, *, config: Any | None = None
    ) -> CheckResult[StubData]:
        return CheckResult(status=Status.COMPLETED, data=StubData(value=domain))


# -- BaseCheckData tests -----------------------------------------------------


class TestBaseCheckData:
    def test_frozen(self) -> None:
        from pydantic import ValidationError

        data = StubData(value="hello")
        with pytest.raises(ValidationError):
            data.value = "changed"  # type: ignore[misc]

    def test_fields(self) -> None:
        data = StubData(value="abc")
        assert data.value == "abc"


# -- BaseCheck.get tests -----------------------------------------------------


class TestGet:
    async def test_get_returns_data(self) -> None:
        check = FullCheck()
        result = await check.get("example.com")
        assert isinstance(result, StubData)
        assert result.value == "example.com"

    async def test_get_with_throttler(self) -> None:
        check = FullCheck()
        throttler = ThrottleManager(max_rps=1000.0, burst=10)
        result = await check.get("example.com", throttler=throttler)
        assert result.value == "example.com"

    async def test_get_without_throttler(self) -> None:
        check = FullCheck()
        result = await check.get("example.com", throttler=None)
        assert result.value == "example.com"

    async def test_get_passes_config(self) -> None:
        check = FullCheck()
        result = await check.get("example.com", config="custom")
        assert result.value == "example.com"


# -- BaseCheck.check tests ---------------------------------------------------


class TestCheck:
    async def test_check_returns_result(self) -> None:
        check = FullCheck()
        result = await check.check("example.com")
        assert isinstance(result, CheckResult)
        assert result.status == Status.COMPLETED
        assert result.data is not None
        assert result.data.value == "example.com"

    async def test_check_with_issues(self) -> None:
        check = FullCheck()
        result = await check.check("bad.example.com")
        assert len(result.issues) == 1
        assert result.issues[0].id == "stub.bad"

    async def test_check_with_throttler(self) -> None:
        check = FullCheck()
        throttler = ThrottleManager(max_rps=1000.0, burst=10)
        result = await check.check("example.com", throttler=throttler)
        assert result.status == Status.COMPLETED

    async def test_check_raises_capability_error(self) -> None:
        """A check without CHECK capability raises CapabilityError."""

        class NoCheckCapability(BaseCheck[StubData, StubParams]):
            name: ClassVar[str] = "nocap"
            capabilities: ClassVar[frozenset[Capability]] = frozenset(
                {Capability.GENERATE}
            )

            async def _get(self, domain: str, *, config: Any | None = None) -> StubData:
                return StubData()

            async def _check(
                self, domain: str, *, config: Any | None = None
            ) -> CheckResult[StubData]:
                return CheckResult(status=Status.COMPLETED, data=StubData())

        check = NoCheckCapability()
        with pytest.raises(CapabilityError, match="check"):
            await check.check("example.com")


# -- BaseCheck.generate tests ------------------------------------------------


class TestGenerate:
    def test_generate_returns_record(self) -> None:
        check = FullCheck()
        record = check.generate(params=StubParams())
        assert isinstance(record, GeneratedRecord)
        assert record.record_type == "TXT"
        assert record.host == "_stub"

    def test_generate_passes_params(self) -> None:
        check = FullCheck()
        record = check.generate(params=StubParams())
        assert record.value == "v=STUB1"

    def test_generate_raises_capability_error(self) -> None:
        check = CheckOnlyCheck()
        with pytest.raises(CapabilityError, match="generate"):
            check.generate(params=StubParams())

    def test_generate_not_implemented_fallback(self) -> None:
        """Subclass declares GENERATE but does not override _generate."""

        class NoGenerateImpl(BaseCheck[StubData, StubParams]):
            name: ClassVar[str] = "nogen"
            capabilities: ClassVar[frozenset[Capability]] = frozenset(
                {Capability.CHECK, Capability.GENERATE}
            )

            async def _get(self, domain: str, *, config: Any | None = None) -> StubData:
                return StubData()

            async def _check(
                self, domain: str, *, config: Any | None = None
            ) -> CheckResult[StubData]:
                return CheckResult(status=Status.COMPLETED, data=StubData())

        check = NoGenerateImpl()
        with pytest.raises(NotImplementedError, match="did not override"):
            check.generate(params=StubParams())
