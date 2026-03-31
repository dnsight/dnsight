"""Tests for :mod:`dnsight.serialisers._data_summary`."""

from __future__ import annotations

from types import SimpleNamespace

from dnsight.serialisers._data_summary import data_summary_lines


def test_empty_when_none() -> None:
    assert data_summary_lines(None) == []


def test_record_only() -> None:
    d = SimpleNamespace(raw_record="v=spf1 -all")
    lines = data_summary_lines(d)
    assert len(lines) == 1
    assert lines[0].startswith("Record: v=spf1 -all")


def test_flattened_only() -> None:
    flat = SimpleNamespace(
        effective_lookup_count=5,
        ip4_ranges=["10.0.0.0/8", "172.16.0.0/12"],
        ip6_ranges=["::1/128"],
    )
    lines = data_summary_lines(SimpleNamespace(flattened=flat))
    assert lines == ["Flattened: 5 lookups, 3 IP ranges"]


def test_suggested_only() -> None:
    lines = data_summary_lines(
        SimpleNamespace(suggested_record="v=spf1 ip4:1.2.3.4 -all")
    )
    assert len(lines) == 1
    assert lines[0].startswith("Suggested:")


def test_all_three_ordered_record_flattened_suggested() -> None:
    flat = SimpleNamespace(effective_lookup_count=1, ip4_ranges=[], ip6_ranges=[])
    d = SimpleNamespace(
        raw_record="v=spf1 ~all", flattened=flat, suggested_record="v=spf1 -all"
    )
    lines = data_summary_lines(d)
    assert [ln.split(":")[0] for ln in lines] == ["Record", "Flattened", "Suggested"]


def test_blank_raw_record_skipped() -> None:
    assert data_summary_lines(SimpleNamespace(raw_record="   ")) == []


def test_mapping_dict_supported() -> None:
    lines = data_summary_lines(
        {
            "raw_record": "v=spf1 -all",
            "flattened": {
                "effective_lookup_count": 2,
                "ip4_ranges": [],
                "ip6_ranges": [],
            },
        }
    )
    assert any(ln.startswith("Record:") for ln in lines)
    assert any(ln.startswith("Flattened:") for ln in lines)
