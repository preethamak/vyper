from __future__ import annotations

import json
from datetime import datetime, timezone

from guardian.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    SecurityGrade,
    Severity,
    VulnerabilityType,
)
from guardian.reporting.sarif_exporter import export_sarif


def _sample_report() -> AnalysisReport:
    return AnalysisReport(
        file_path="contracts/sample.vy",
        timestamp=datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc),
        vyper_version="^0.4.0",
        findings=[
            DetectorResult(
                detector_name="unsafe_raw_call",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                vulnerability_type=VulnerabilityType.EXTERNAL_CALL,
                title="Unchecked raw_call in withdraw()",
                description="raw_call return value is not checked.",
                line_number=12,
                source_snippet='raw_call(msg.sender, b"", value=amount)',
                fix_suggestion="Wrap raw_call in assert.",
            ),
            DetectorResult(
                detector_name="timestamp_dependence",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                vulnerability_type=VulnerabilityType.TIMESTAMP_DEPENDENCE,
                title="Timestamp dependence in settle()",
                description="block.timestamp used in condition.",
                line_number=30,
                source_snippet="if block.timestamp > self.deadline:",
                fix_suggestion="Use oracle/time-window checks.",
            ),
        ],
        detectors_run=["unsafe_raw_call", "timestamp_dependence"],
        security_score=77,
        grade=SecurityGrade.A,
    )


def test_export_sarif_has_valid_top_level_contract() -> None:
    payload = json.loads(export_sarif(_sample_report()))

    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"]) == 1


def test_export_sarif_maps_findings_and_levels() -> None:
    payload = json.loads(export_sarif(_sample_report()))
    run = payload["runs"][0]
    results = run["results"]

    assert len(results) == 2
    assert results[0]["ruleId"] == "unsafe_raw_call"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12

    assert results[1]["ruleId"] == "timestamp_dependence"
    assert results[1]["level"] == "note"


def test_export_sarif_includes_rules_and_summary() -> None:
    payload = json.loads(export_sarif(_sample_report()))
    run = payload["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}

    assert {"unsafe_raw_call", "timestamp_dependence"}.issubset(rule_ids)
    assert run["properties"]["summary"]["total"] == 2
    assert run["properties"]["summary"]["high"] == 1
    assert run["properties"]["summary"]["low"] == 1
