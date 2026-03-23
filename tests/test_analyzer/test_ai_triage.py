"""Tests for optional AI-assisted triage post-processor (Phase 4 kickoff)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.analyzer.ai_triage import TRIAGE_POLICY_VERSION, apply_ai_triage
from guardian.analyzer.static import StaticAnalyzer
from guardian.cli import app
from guardian.models import Severity
from guardian.reporting.markdown_exporter import export_markdown

runner = CliRunner()

SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""

MIXED_SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount

@external
@view
def clock() -> bool:
    assert block.timestamp > 100
    return True
"""


def test_ai_triage_does_not_mutate_findings() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    before = [
        (f.detector_name, f.title, f.severity.value, f.line_number)
        for f in report.findings
    ]

    apply_ai_triage(report)

    after = [
        (f.detector_name, f.title, f.severity.value, f.line_number)
        for f in report.findings
    ]
    assert after == before
    assert len(report.ai_triage) == len(report.findings)
    assert all(item["provenance"]["can_override_verdict"] is False for item in report.ai_triage)
    assert all("scoring_rationale" in item for item in report.ai_triage)
    assert report.ai_triage_policy["policy_version"] == TRIAGE_POLICY_VERSION
    assert report.ai_triage_policy["deterministic"] is True


def test_ai_triage_scoring_rationale_matches_confidence() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    apply_ai_triage(report)

    item = report.ai_triage[0]
    rationale = item["scoring_rationale"]
    assert rationale["version"] == "triage_scoring_v1"
    assert rationale["final_confidence"] == item["confidence"]
    assert item["provenance"]["policy_version"] == TRIAGE_POLICY_VERSION


def test_ai_triage_policy_transition_warnings_are_emitted() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    apply_ai_triage(
        report,
        policy_status="deprecated",
        deprecation_announced=True,
        deprecation_sunset_after="2026-12-31",
    )

    warnings = report.ai_triage_policy.get("warnings", [])
    assert warnings
    assert any("deprecated" in w for w in warnings)
    assert any("2026-12-31" in w for w in warnings)


def test_cli_json_includes_ai_triage_when_enabled() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai-triage",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "findings" in payload
        assert "ai_triage" in payload
        assert "ai_triage_policy" in payload
        assert len(payload["ai_triage"]) == len(payload["findings"])


def test_markdown_export_includes_ai_triage_section_when_present() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    apply_ai_triage(report)

    text = export_markdown(report)
    assert "## 🤖 AI-Assisted Triage" in text
    assert "Policy: `v1.0.0` (`stable`)" in text
    assert "Guardrail: triage is advisory only" in text
    assert "triage_scoring_v1" in text


def test_markdown_export_surfaces_policy_warnings() -> None:
    report = StaticAnalyzer().analyze_source(SOURCE, "sample.vy")
    apply_ai_triage(
        report,
        policy_status="deprecated",
        deprecation_announced=True,
        deprecation_sunset_after="2026-12-31",
    )

    text = export_markdown(report)
    assert "Policy warnings:" in text
    assert "2026-12-31" in text


def test_cli_output_renders_ai_triage_section() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "cli",
                "--ai-triage",
            ],
            color=False,
        )

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "AI-Assisted Triage" in combined
        assert "triage_scoring_v1" in combined


def test_ai_triage_policy_applies_min_severity_and_max_items() -> None:
        report = StaticAnalyzer().analyze_source(MIXED_SOURCE, "sample.vy")
        apply_ai_triage(report, min_severity=Severity.HIGH, max_items=1)

        assert len(report.ai_triage) == 1
        assert report.ai_triage[0]["severity"] in {"CRITICAL", "HIGH"}


def test_config_can_enable_ai_triage_without_cli_flag() -> None:
        with runner.isolated_filesystem():
                contract = Path("contract.vy")
                contract.write_text(SOURCE, encoding="utf-8")

                Path(".guardianrc").write_text(
                        """\
analysis:
    enabled_detectors:
        - all
    disabled_detectors: []
    severity_threshold: LOW

reporting:
    default_format: json
    show_source_snippets: true
    show_fix_suggestions: true

ai_triage:
    enabled: true
    min_severity: LOW
    max_items: 5
""",
                        encoding="utf-8",
                )

                result = runner.invoke(app, ["analyze", str(contract)])

                assert result.exit_code == 0
                payload = json.loads(result.stdout)
                assert "ai_triage" in payload
                assert payload["ai_triage"]


def test_cli_output_surfaces_policy_warnings_from_config() -> None:
        with runner.isolated_filesystem():
                contract = Path("contract.vy")
                contract.write_text(SOURCE, encoding="utf-8")

                Path(".guardianrc").write_text(
                        """\
analysis:
    enabled_detectors:
        - all
    disabled_detectors: []
    severity_threshold: LOW

reporting:
    default_format: cli
    show_source_snippets: true
    show_fix_suggestions: true

ai_triage:
    enabled: true
    min_severity: LOW
    max_items: 5
    policy_status: deprecated
    deprecation_announced: true
    deprecation_sunset_after: 2026-12-31
""",
                        encoding="utf-8",
                )

                result = runner.invoke(app, ["analyze", str(contract)], color=False)
                assert result.exit_code == 0
                combined = result.stdout + result.stderr
                assert "Policy warning:" in combined
