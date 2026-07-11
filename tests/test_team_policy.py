import json

from guardian.team_policy import evaluate_team_policy, render_pr_markdown


def test_team_policy_blocks_new_high_confidence_finding(tmp_path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "detector": "cei_violation",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "title": "Call before state update",
                        "fingerprint": "finding-1",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yml"
    policy.write_text(
        """gate:
  min_severity: HIGH
  min_confidence: HIGH
owners:
  default: security
  cei_violation: protocol
""",
        encoding="utf-8",
    )
    result = evaluate_team_policy(report, policy)
    assert result["passed"] is False
    assert result["blocking"][0]["owner"] == "protocol"
    assert "Vyper Guard: FAIL" in render_pr_markdown(result)


def test_active_acceptance_prevents_blocking(tmp_path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "detector": "cei_violation",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "title": "Reviewed",
                        "fingerprint": "accepted",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yml"
    policy.write_text(
        """acceptances:
  - fingerprint: accepted
    owner: security
    reason: reviewed
    expires_at: 2999-01-01T00:00:00Z
""",
        encoding="utf-8",
    )
    result = evaluate_team_policy(report, policy)
    assert result["passed"] is True
    assert result["summary"]["accepted"] == 1
