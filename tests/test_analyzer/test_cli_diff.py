"""Regression tests for CLI diff behavior."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app
from guardian.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    SecurityGrade,
    Severity,
    VulnerabilityType,
)

runner = CliRunner()


def _finding(line: int) -> DetectorResult:
    return DetectorResult(
        detector_name="unsafe_raw_call",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        vulnerability_type=VulnerabilityType.EXTERNAL_CALL,
        title="Unchecked raw_call in withdraw()",
        description="raw_call return value is not checked.",
        line_number=line,
        source_snippet='raw_call(msg.sender, b"", value=amount)',
        fix_suggestion="Wrap raw_call in assert.",
    )


def test_diff_ignores_line_only_movement(monkeypatch) -> None:
    with runner.isolated_filesystem():
        file_a = Path("a.vy")
        file_b = Path("b.vy")
        base_source = "# pragma version ^0.4.0\n\n@external\ndef ping() -> bool:\n    return True\n"
        file_a.write_text(base_source, encoding="utf-8")
        file_b.write_text(base_source, encoding="utf-8")

        report_a = AnalysisReport(
            file_path=str(file_a),
            findings=[_finding(10)],
            detectors_run=["unsafe_raw_call"],
            security_score=80,
            grade=SecurityGrade.A,
        )
        report_b = AnalysisReport(
            file_path=str(file_b),
            findings=[_finding(12)],
            detectors_run=["unsafe_raw_call"],
            security_score=80,
            grade=SecurityGrade.A,
        )

        def _fake_analyze_file(self, path):
            return report_a if str(path).endswith("a.vy") else report_b

        monkeypatch.setattr(
            "guardian.analyzer.static.StaticAnalyzer.analyze_file", _fake_analyze_file
        )

        result = runner.invoke(app, ["diff", str(file_a), str(file_b)])

        assert result.exit_code == 0
        assert "No changes in findings between the two contracts" in result.output
