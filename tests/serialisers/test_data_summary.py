"""Tests for :mod:`dnsight.serialisers._data_summary`."""

from __future__ import annotations

from dnsight.serialisers._data_summary import data_summary_lines


def test_data_summary_flatten_compact_only_by_default() -> None:
    data = {
        "raw_record": "v=spf1 include:_spf.example.com ~all",
        "flattened": {
            "effective_lookup_count": 3,
            "resolved_mechanisms": ["include:_spf.example.com", "~all"],
            "ip4_ranges": ["192.0.2.0/24"],
            "ip6_ranges": [],
        },
    }
    lines = data_summary_lines(data, flatten_detail=False)
    assert any("Flattened: 3 lookups, 1 IP ranges" in ln for ln in lines)
    assert not any("Resolved mechanisms" in ln for ln in lines)
    assert not any("  ip4:" in ln for ln in lines)


def test_data_summary_flatten_detail_expands() -> None:
    data = {
        "raw_record": "v=spf1 ip4:192.0.2.1 -all",
        "flattened": {
            "effective_lookup_count": 1,
            "resolved_mechanisms": ["ip4:192.0.2.1", "-all"],
            "ip4_ranges": ["192.0.2.1", "192.0.2.2"],
            "ip6_ranges": ["2001:db8::/32"],
        },
    }
    lines = data_summary_lines(data, flatten_detail=True)
    assert any("Flattened: 1 lookups, 3 IP ranges" in ln for ln in lines)
    assert any("Resolved mechanisms:" in ln for ln in lines)
    assert any("ip4:192.0.2.1" in ln for ln in lines)
    assert sum(1 for ln in lines if ln.strip().startswith("ip4:")) >= 2
    assert any("ip6:" in ln for ln in lines)


def test_data_summary_flatten_detail_truncates_ip_lists() -> None:
    many = [f"10.0.0.{i}" for i in range(30)]
    data = {
        "flattened": {
            "effective_lookup_count": 0,
            "resolved_mechanisms": [],
            "ip4_ranges": many,
            "ip6_ranges": [],
        }
    }
    lines = data_summary_lines(data, flatten_detail=True)
    assert any("+10 more" in ln for ln in lines)
