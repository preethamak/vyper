from guardian.analyzer.triage import build_triage_summary
from guardian.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    Severity,
    VulnerabilityType,
)


def test_triage_groups_repeated_detector_findings() -> None:
    findings = [
        DetectorResult(
            detector_name="timestamp_dependence",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            vulnerability_type=VulnerabilityType.TIMESTAMP_DEPENDENCE,
            title=f"Timestamp {index}",
            description="test",
        )
        for index in range(5)
    ]
    summary = build_triage_summary(AnalysisReport(file_path="sample.vy", findings=findings))
    assert summary["raw_findings"] == 5
    assert summary["candidates_shown"] == 1
    assert summary["omitted_repetitions"] == 4
