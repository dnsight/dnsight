"""Tests for :mod:`dnsight.serialisers.base` helpers and :func:`~dnsight.serialisers.writer.write_serialiser`."""

from __future__ import annotations

import pytest

from dnsight.core.models import CheckResult
from dnsight.core.types import Status
from dnsight.serialisers import write_serialiser
from dnsight.serialisers.base import domain_result_from_check
from dnsight.serialisers.json import JsonSerialiser


def test_domain_result_from_check_wraps_single_zone() -> None:
    cr = CheckResult[object](status=Status.COMPLETED, data=None, issues=[])
    dr = domain_result_from_check(
        domain="example.com", check_name="dmarc", result=cr, config_version=7
    )
    assert dr.domain == "example.com"
    assert dr.config_version == 7
    assert set(dr.root.results.keys()) == {"dmarc"}
    assert dr.root.results["dmarc"] == cr
    assert dr.partial is False


def test_serialise_check_result_requires_domain_and_check_name() -> None:
    cr = CheckResult[object](status=Status.COMPLETED, data=None, issues=[])
    with pytest.raises(TypeError, match="domain="):
        JsonSerialiser().serialise(cr)
    with pytest.raises(TypeError, match="check_name="):
        JsonSerialiser().serialise(cr, domain="x.com")


def test_serialise_rejects_empty_domain_sequence() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        JsonSerialiser().serialise([])


def test_serialise_rejects_non_domain_sequence_members() -> None:
    with pytest.raises(TypeError, match="DomainResult"):
        JsonSerialiser().serialise([object()])


def test_serialise_rejects_str_payload() -> None:
    with pytest.raises(TypeError, match="unexpected str"):
        JsonSerialiser().serialise("not-a-result")


def test_write_serialiser_atomic_json(domain_result_nested, tmp_path) -> None:
    path = tmp_path / "out.json"
    write_serialiser(JsonSerialiser(), domain_result_nested, path)
    assert path.is_file()
    assert not (tmp_path / "out.json.tmp").exists()
    expected = JsonSerialiser().serialise(domain_result_nested)
    assert path.read_text(encoding="utf-8") == expected
