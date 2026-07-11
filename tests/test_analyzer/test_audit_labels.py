import json

from guardian.analyzer.audit_labels import classify_report, load_audit_labels
from guardian.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    Severity,
    VulnerabilityType,
)


def test_known_audit_issue_is_distinguished_from_new_candidate(tmp_path) -> None:
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-labels/v2",
                "labels": [
                    {
                        "file": "VotingEscrow.vy",
                        "detector": "missing_zero_address_check",
                        "verdict": "true_positive",
                        "reviewer": "Trail of Bits",
                        "reviewed_at": "2020-06-01T00:00:00Z",
                        "evidence": "https://example.org/audit.pdf",
                        "finding_id": "TOB-CURVE-DAO-011",
                        "function": "commit_transfer_ownership",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = AnalysisReport(
        file_path="/repo/VotingEscrow.vy",
        findings=[
            DetectorResult(
                detector_name="missing_zero_address_check",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                vulnerability_type=VulnerabilityType.INPUT_VALIDATION,
                title="Missing zero check in commit_transfer_ownership()",
                description="test",
            ),
            DetectorResult(
                detector_name="cei_violation",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                vulnerability_type=VulnerabilityType.REENTRANCY,
                title="New candidate",
                description="test",
            ),
        ],
    )
    counts = classify_report(report, load_audit_labels(labels_path))
    assert counts == {
        "known_issue_rediscovered": 1,
        "known_false_positive": 0,
        "new_candidate": 1,
    }
