import json

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()


def _labels(path) -> None:
    path.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-labels/v2",
                "labels": [
                    {
                        "file": "sample.vy",
                        "detector": "missing_zero_address_check",
                        "verdict": "true_positive",
                        "reviewer": "auditor-a",
                        "reviewed_at": "2026-01-01T00:00:00Z",
                        "evidence": "https://example.org/audit",
                        "function": "set_owner",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_analyze_applies_reviewed_audit_labels(tmp_path) -> None:
    contract = tmp_path / "sample.vy"
    contract.write_text(
        """# pragma version ^0.4.0
owner: address
@external
def set_owner(new_owner: address):
    self.owner = new_owner
""",
        encoding="utf-8",
    )
    labels = tmp_path / "labels.json"
    _labels(labels)
    result = runner.invoke(
        app,
        ["analyze", str(contract), "--audit-labels", str(labels), "--format", "json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    finding = next(
        item for item in payload["findings"] if item["detector"] == "missing_zero_address_check"
    )
    assert finding["audit_classification"]["classification"] == "known_issue_rediscovered"


def test_label_quality_command_is_machine_readable(tmp_path) -> None:
    labels = tmp_path / "labels.json"
    _labels(labels)
    result = runner.invoke(
        app,
        [
            "label-quality",
            str(labels),
            "--min-positive",
            "1",
            "--min-negative",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["schema"] == "vyper-guard-label-quality/v1"
