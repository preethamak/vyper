"""Golden-output tests for report exporters and terminal formatter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from guardian import __version__
from guardian.analyzer.ai_triage import apply_ai_triage
from guardian.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    SecurityGrade,
    Severity,
    VulnerabilityType,
)
from guardian.reporting.formatter import print_report
from guardian.reporting.json_exporter import export_json
from guardian.reporting.markdown_exporter import export_markdown

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden"


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


def test_json_export_matches_golden_contract() -> None:
    payload = json.loads(export_json(_sample_report()))
    payload["tool"]["version"] = "<VERSION>"
    payload["environment"]["python"] = "<PYTHON>"
    payload["environment"]["platform"] = "<PLATFORM>"

    for finding in payload["findings"]:
        finding["fingerprint"] = "<FINGERPRINT>"

    actual = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    expected = (GOLDEN / "report.json").read_text(encoding="utf-8")

    assert actual == expected


def test_markdown_export_matches_golden_contract() -> None:
    actual = export_markdown(_sample_report())
    actual = actual.replace(f"vyper-guard v{__version__}", "vyper-guard v<VERSION>")
    actual = actual.replace(f" v{__version__} • ", " v<VERSION> • ")

    expected = (GOLDEN / "report.md").read_text(encoding="utf-8")

    assert actual == expected


def test_terminal_formatter_matches_golden_contract() -> None:
    console = Console(record=True, width=100, force_terminal=False, color_system=None)
    print_report(_sample_report(), console=console)

    actual = console.export_text().replace(f"v{__version__}", "v<VERSION>")
    expected = (GOLDEN / "report.cli.txt").read_text(encoding="utf-8")

    assert actual == expected


def _extract_ai_triage_section(markdown_text: str) -> str:
    start = markdown_text.find("## 🤖 AI-Assisted Triage")
    if start == -1:
        return ""
    end = markdown_text.find("\n---", start)
    if end == -1:
        end = len(markdown_text)
    return markdown_text[start:end].rstrip() + "\n"


def test_json_ai_triage_export_matches_golden_contract() -> None:
    report = _sample_report()
    apply_ai_triage(report)
    payload = json.loads(export_json(report))

    actual = json.dumps(payload.get("ai_triage", []), indent=2, ensure_ascii=False) + "\n"
    expected = (GOLDEN / "report.ai_triage.json").read_text(encoding="utf-8")

    assert actual == expected
    assert payload["ai_triage_policy"]["policy_version"] == "1.0.0"
    assert payload["ai_triage_policy"]["deterministic"] is True
    assert payload["ai_triage_policy"]["can_override_verdict"] is False


def test_markdown_ai_triage_section_matches_golden_contract() -> None:
    report = _sample_report()
    apply_ai_triage(report)
    actual = export_markdown(report)

    triage_section = _extract_ai_triage_section(actual)
    expected = (GOLDEN / "report.ai_triage.section.md").read_text(encoding="utf-8")

    assert triage_section == expected


def test_json_ai_triage_policy_deprecated_matches_golden_contract() -> None:
    report = _sample_report()
    apply_ai_triage(
        report,
        policy_status="deprecated",
        deprecation_announced=True,
        deprecation_sunset_after="2026-12-31",
    )
    payload = json.loads(export_json(report))

    actual = json.dumps(payload.get("ai_triage_policy", {}), indent=2, ensure_ascii=False) + "\n"
    expected = (GOLDEN / "report.ai_triage.policy.deprecated.json").read_text(encoding="utf-8")

    assert actual == expected


def test_markdown_ai_triage_deprecated_section_matches_golden_contract() -> None:
    report = _sample_report()
    apply_ai_triage(
        report,
        policy_status="deprecated",
        deprecation_announced=True,
        deprecation_sunset_after="2026-12-31",
    )
    actual = export_markdown(report)

    triage_section = _extract_ai_triage_section(actual)
    expected = (GOLDEN / "report.ai_triage.section.deprecated.md").read_text(encoding="utf-8")

    assert triage_section == expected
