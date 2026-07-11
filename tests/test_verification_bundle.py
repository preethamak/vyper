import json

from guardian.analyzer.exploit_verifier import apply_execution_evidence
from guardian.models import Confidence, DetectorResult, Severity, VulnerabilityType
from guardian.verification_bundle import generate_verification_bundle


def test_bundle_contains_only_reachable_verification_candidates(tmp_path) -> None:
    report = tmp_path / "report.json"
    verification = {
        "status": "reachable",
        "finding_fingerprint_inputs": {"detector": "cei_violation", "line": 4, "title": "CEI"},
    }
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "detector": "cei_violation",
                        "title": "CEI",
                        "line_number": 4,
                        "exploit_verification": verification,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    manifest = generate_verification_bundle(report, tmp_path / "bundle")
    assert len(manifest["candidates"]) == 1
    assert (tmp_path / "bundle" / "test_verification.py").is_file()


def test_execution_evidence_advances_to_reproduced() -> None:
    fingerprint = {"detector": "cei_violation", "line": 4, "title": "CEI"}
    finding = DetectorResult(
        detector_name="cei_violation",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        vulnerability_type=VulnerabilityType.REENTRANCY,
        title="CEI",
        description="test",
        exploit_verification={
            "status": "reachable",
            "evidence_levels": {"pattern_match": True, "reachable": True},
            "finding_fingerprint_inputs": fingerprint,
        },
    )
    apply_execution_evidence(
        finding,
        {
            "finding_fingerprint_inputs": fingerprint,
            "outcome": "reproduced",
            "framework": "titanoboa",
            "command": "pytest -q",
            "exit_code": 0,
        },
    )
    assert finding.exploit_verification["status"] == "reproduced"
