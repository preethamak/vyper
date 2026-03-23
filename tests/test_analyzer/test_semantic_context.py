"""Tests for semantic context wiring into findings/reporting."""

from __future__ import annotations

import json

from guardian.analyzer.static import StaticAnalyzer
from guardian.reporting.json_exporter import export_json

SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]
owner: address

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""


def test_findings_get_semantic_context() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    assert report.findings

    with_context = [f for f in report.findings if f.semantic_context]
    assert with_context, "Expected at least one finding with semantic_context"

    ctx = with_context[0].semantic_context
    assert "function" in ctx
    assert "external_calls" in ctx
    assert "external_calls_in_loop" in ctx
    assert "state_writes" in ctx


def test_json_export_includes_semantic_context() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    payload = json.loads(export_json(report))

    findings = payload.get("findings", [])
    assert findings
    assert any("semantic_context" in f for f in findings)
