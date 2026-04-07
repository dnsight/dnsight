"""Tests for :class:`~dnsight.serialisers.sarif.SarifSerialiser`."""

from __future__ import annotations

import json

from dnsight.serialisers.sarif import SarifSerialiser


def test_sarif_schema_and_invocation(domain_result_nested) -> None:
    raw = SarifSerialiser().serialise(domain_result_nested)
    doc = json.loads(raw)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is (
        not domain_result_nested.partial
    )
    assert domain_result_nested.partial is True
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["properties"]["target"] == domain_result_nested.target


def test_sarif_issue_rule_ids(domain_result_nested) -> None:
    doc = json.loads(SarifSerialiser().serialise(domain_result_nested))
    results = doc["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert "test.issue" in rule_ids
    assert "dnsight.check.failed" in rule_ids


def test_sarif_driver_metadata(domain_result_nested) -> None:
    doc = json.loads(SarifSerialiser().serialise(domain_result_nested))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "dnsight"
    assert "version" in driver
