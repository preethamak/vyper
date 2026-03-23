"""Tests for explainability payload on findings."""

from __future__ import annotations

import json

from guardian.analyzer.static import StaticAnalyzer
from guardian.reporting.json_exporter import export_json

SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""


def test_findings_include_explainability_fields() -> None:
    analyzer = StaticAnalyzer()
    report = analyzer.analyze_source(SOURCE, "sample.vy")

    assert report.findings, "Expected at least one finding"
    first = report.findings[0]
    assert first.why_flagged
    assert isinstance(first.evidence, list)


def test_json_export_includes_explainability_when_available() -> None:
    analyzer = StaticAnalyzer()
    report = analyzer.analyze_source(SOURCE, "sample.vy")

    payload = json.loads(export_json(report))
    assert payload["findings"], "Expected non-empty findings in JSON"

    explainable = [f for f in payload["findings"] if f.get("why_flagged")]
    assert explainable, "Expected at least one finding with why_flagged"
    assert any("evidence" in f and isinstance(f["evidence"], list) for f in explainable)
