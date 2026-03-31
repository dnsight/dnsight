"""Tests for :func:`~dnsight.serialisers.write_serialiser`."""

from __future__ import annotations

from dnsight.serialisers.base import write_serialiser
from dnsight.serialisers.json import JsonSerialiser


def test_write_serialiser_atomic_json(domain_result_nested, tmp_path) -> None:
    path = tmp_path / "out.json"
    write_serialiser(JsonSerialiser(), domain_result_nested, path)
    assert path.is_file()
    assert not (tmp_path / "out.json.tmp").exists()
    expected = JsonSerialiser().serialise(domain_result_nested)
    assert path.read_text(encoding="utf-8") == expected
