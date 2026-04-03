"""CLI serialiser dispatch and emit helpers (:mod:`dnsight.cli.output`)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from dnsight.cli.output import emit_audit_results, emit_check_result, get_serialiser
from dnsight.cli.state import GlobalState
from dnsight.core.models import CheckResult, DomainResult, ZoneResult
from dnsight.core.types import OutputFormat, Status
from dnsight.serialisers import (
    JsonSerialiser,
    MarkdownSerialiser,
    RichSerialiser,
    SarifSerialiser,
)


def _state(
    *, fmt: OutputFormat = OutputFormat.JSON, out: Path | None = None
) -> GlobalState:
    return GlobalState(
        config_path=None, output_format=fmt, output_path=out, quiet=True, verbose=False
    )


def test_get_serialiser_dispatches_all_formats() -> None:
    assert isinstance(get_serialiser(OutputFormat.JSON), JsonSerialiser)
    assert isinstance(get_serialiser(OutputFormat.MARKDOWN), MarkdownSerialiser)
    assert isinstance(get_serialiser(OutputFormat.SARIF), SarifSerialiser)
    assert isinstance(get_serialiser(OutputFormat.RICH), RichSerialiser)


def test_emit_audit_results_empty_batch_returns_zero() -> None:
    code = emit_audit_results(_state(), [])
    assert code == 0


def test_emit_check_result_writes_json_to_output_path(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    st = _state(fmt=OutputFormat.JSON, out=out)
    cr = CheckResult(status=Status.COMPLETED, data=None, issues=[])
    code = emit_check_result(st, cr, domain="example.com", check_name="dmarc")
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "example.com" in text
    assert "dmarc" in text


def test_emit_audit_results_multi_domain_json_to_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    z = ZoneResult(zone="a.com", results={})
    dr_a = DomainResult(
        domain="a.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z],
        partial=False,
    )
    z2 = ZoneResult(zone="b.com", results={})
    dr_b = DomainResult(
        domain="b.com",
        timestamp=datetime.now(UTC),
        config_version=1,
        zones=[z2],
        partial=False,
    )
    code = emit_audit_results(_state(fmt=OutputFormat.JSON), [dr_a, dr_b])
    assert code == 0
    captured = capsys.readouterr()
    assert "a.com" in captured.out
    assert "b.com" in captured.out
