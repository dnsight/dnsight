"""Tests for :class:`~dnsight.serialisers.json.JsonSerialiser`."""

from __future__ import annotations

import json

from dnsight.serialisers.json import JsonSerialiser


def test_json_partial_and_zone_order(domain_result_nested) -> None:
    s = JsonSerialiser().serialise(domain_result_nested)
    doc = json.loads(s)
    assert "domains" in doc
    d0 = doc["domains"][0]
    assert d0["partial"] is True
    assert d0["domain"] == "example.com"
    assert d0["target"] == "example.com"
    zones = d0["zones"]
    assert [z["zone"] for z in zones] == ["example.com", "sub.example.com"]


def test_json_per_check_status_and_data(domain_result_nested) -> None:
    doc = json.loads(JsonSerialiser().serialise(domain_result_nested))
    zones = doc["domains"][0]["zones"]
    root_zone = next(z for z in zones if z["zone"] == "example.com")
    assert root_zone["results"]["dmarc"]["status"] == "completed"
    assert root_zone["results"]["spf"]["data"]["raw_record"].startswith("v=spf1")
    child_zone = next(z for z in zones if z["zone"] == "sub.example.com")
    assert child_zone["results"]["spf"]["status"] == "failed"
    assert "DNS timeout" in (child_zone["results"]["spf"].get("error") or "")
