"""Tests for detector confidence calibration policy."""

from __future__ import annotations

from guardian.analyzer.confidence import calibrate_confidence
from guardian.analyzer.static import StaticAnalyzer
from guardian.models import Confidence, DetectorResult, Severity, VulnerabilityType

RAW_CALL_SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""


def test_policy_sets_minimum_confidence_for_high_signal_detector() -> None:
    report = StaticAnalyzer().analyze_source(RAW_CALL_SOURCE, "sample.vy")
    raw_call_findings = [f for f in report.findings if f.detector_name == "unsafe_raw_call"]
    assert raw_call_findings, "Expected unsafe_raw_call finding"

    for finding in raw_call_findings:
        assert finding.confidence in {Confidence.MEDIUM, Confidence.HIGH}


def test_compiler_info_confidence_is_calibrated_low() -> None:
    finding = DetectorResult(
        detector_name="compiler_version_check",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        vulnerability_type=VulnerabilityType.COMPILER_BUG,
        title="Missing pragma",
        description="No pragma",
        line_number=1,
        source_snippet="# missing pragma",
        why_flagged="missing pragma",
        evidence=["pragma:missing", "line:1"],
    )

    calibrated = calibrate_confidence([finding])[0]
    assert calibrated.confidence == Confidence.LOW
