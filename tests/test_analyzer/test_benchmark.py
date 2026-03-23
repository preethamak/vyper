"""Tests for benchmark command and benchmark runner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()

SAFE_CONTRACT = """\
# pragma version ^0.4.0

@external
@view
def ping() -> bool:
    return True
"""

VULN_CONTRACT = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""


def test_benchmark_json_output_shape() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        corpus = root / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)

        (corpus / "safe_contract.vy").write_text(SAFE_CONTRACT, encoding="utf-8")
        (corpus / "vuln_raw_call.vy").write_text(VULN_CONTRACT, encoding="utf-8")

        result = runner.invoke(app, ["benchmark", str(corpus), "--format", "json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)

        assert payload["files_total"] == 2
        assert "metrics" in payload
        assert {"precision", "recall", "f1"}.issubset(payload["metrics"])
        assert "by_detector" in payload
        assert "unsafe_raw_call" in payload["by_detector"]

        detector_metrics = payload["by_detector"]["unsafe_raw_call"]
        assert {"tp", "fp", "fn", "support", "precision", "recall", "f1"}.issubset(detector_metrics)


def test_benchmark_uses_external_labels_file_when_provided() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        corpus = root / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)

        (corpus / "safe_contract.vy").write_text(SAFE_CONTRACT, encoding="utf-8")
        # Filename heuristics would normally mark this vulnerable.
        (corpus / "custom_case.vy").write_text(VULN_CONTRACT, encoding="utf-8")

        labels = root / "labels.json"
        labels.write_text(
            json.dumps(
                {
                    "files": {
                        "safe_contract.vy": {"vulnerable": False, "detectors": []},
                        "custom_case.vy": {
                            "vulnerable": False,
                            "detectors": [],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            app,
            [
                "benchmark",
                str(corpus),
                "--format",
                "json",
                "--labels-file",
                str(labels),
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["labels_file"] is not None
        assert payload["expected"]["vulnerable"] == 0


def test_benchmark_invalid_quality_gate_value_returns_exit_2() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        corpus = root / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)

        (corpus / "safe_contract.vy").write_text(SAFE_CONTRACT, encoding="utf-8")
        (corpus / "vuln_raw_call.vy").write_text(VULN_CONTRACT, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "benchmark",
                str(corpus),
                "--format",
                "json",
                "--min-f1",
                "1.1",
            ],
        )

        assert result.exit_code == 2


def test_benchmark_quality_gate_failure_exits_1_with_labels_override() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        corpus = root / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)

        (corpus / "safe_contract.vy").write_text(SAFE_CONTRACT, encoding="utf-8")
        (corpus / "vuln_raw_call.vy").write_text(VULN_CONTRACT, encoding="utf-8")

        labels = root / "labels.json"
        labels.write_text(
            json.dumps(
                {
                    "files": {
                        "safe_contract.vy": {"vulnerable": False, "detectors": []},
                        "vuln_raw_call.vy": {"vulnerable": False, "detectors": []},
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            app,
            [
                "benchmark",
                str(corpus),
                "--format",
                "json",
                "--labels-file",
                str(labels),
                "--min-f1",
                "0.1",
            ],
        )

        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert payload["quality_gates"]["configured"] is True
        assert payload["quality_gates"]["passed"] is False
        assert payload["quality_gates"]["failures"]


def test_benchmark_quality_gate_passes_and_reports_status() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        corpus = root / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)

        (corpus / "safe_contract.vy").write_text(SAFE_CONTRACT, encoding="utf-8")
        (corpus / "vuln_raw_call.vy").write_text(VULN_CONTRACT, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "benchmark",
                str(corpus),
                "--format",
                "json",
                "--min-f1",
                "0.5",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["quality_gates"]["configured"] is True
        assert payload["quality_gates"]["passed"] is True
        assert payload["quality_gates"]["failures"] == []


def test_benchmark_per_detector_gate_failure_exits_1() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        corpus = root / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)

        (corpus / "safe_contract.vy").write_text(SAFE_CONTRACT, encoding="utf-8")
        (corpus / "vuln_raw_call.vy").write_text(VULN_CONTRACT, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "benchmark",
                str(corpus),
                "--format",
                "json",
                "--min-detector-f1",
                "1.0",
                "--min-detector-support",
                "1",
            ],
        )

        payload = json.loads(result.stdout)
        assert payload["quality_gates"]["configured"] is True
