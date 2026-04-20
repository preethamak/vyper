"""CLI contract tests for edge-case behavior and startup guarantees."""

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

LOW_FINDING_CONTRACT = """\
# pragma version ^0.4.0

@external
@view
def check_time() -> bool:
    assert block.timestamp > 100
    return True
"""


def _write_contract(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    return path


def test_invalid_severity_threshold_returns_exit_2() -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), SAFE_CONTRACT)

        result = runner.invoke(
            app,
            ["analyze", str(contract), "--severity-threshold", "SEVERE", "--format", "json"],
        )

        assert result.exit_code == 2


def test_invalid_format_returns_exit_2() -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), SAFE_CONTRACT)

        result = runner.invoke(app, ["analyze", str(contract), "--format", "xml"])

        assert result.exit_code == 2


def test_help_subcommand_displays_html_format_guidance() -> None:
    result = runner.invoke(app, ["help"])

    assert result.exit_code == 0
    assert "analyze --format cli|json|markdown|sarif|html" in result.output
    assert "analyze contract.vy -f html -o report.html" in result.output


def test_ci_mode_exits_1_when_threshold_finding_present() -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), LOW_FINDING_CONTRACT)

        result = runner.invoke(
            app,
            ["analyze", str(contract), "--format", "json", "--severity-threshold", "LOW", "--ci"],
        )

        assert result.exit_code == 1


def test_analyze_unexpected_runtime_error_returns_structured_fallback_json(
    monkeypatch,
) -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), SAFE_CONTRACT)

        def _boom(self, file_path):
            raise RuntimeError("boom")

        monkeypatch.setattr("guardian.analyzer.static.StaticAnalyzer.analyze_file", _boom)

        result = runner.invoke(app, ["analyze", str(contract), "--format", "json"])

        assert result.exit_code == 0
        assert "analyzer_runtime_error" in result.output
        assert '"security_score": 0' in result.output


def test_analyze_supports_sarif_output() -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), SAFE_CONTRACT)

        result = runner.invoke(app, ["analyze", str(contract), "--format", "sarif"])

        assert result.exit_code == 0
        assert '"version": "2.1.0"' in result.output
        assert '"runs": [' in result.output

    def test_analyze_supports_html_output() -> None:
        with runner.isolated_filesystem():
            contract = _write_contract(Path("contract.vy"), SAFE_CONTRACT)

            result = runner.invoke(app, ["analyze", str(contract), "--format", "html"])

            assert result.exit_code == 0
            assert "<!doctype html>" in result.output
            assert "Vyper Guard Security Report" in result.output


def test_analyze_directory_supports_json_output() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "safe.vy", SAFE_CONTRACT)
        _write_contract(contracts / "risky.vy", LOW_FINDING_CONTRACT)

        result = runner.invoke(app, ["analyze", str(contracts), "--format", "json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["$schema"] == "vyper-guard-project-report/v1"
        assert payload["contracts_analyzed"] == 2
        assert payload["summary"]["total"] >= 1
        assert len(payload["reports"]) == 2


def test_analyze_directory_ci_exits_1_when_findings_present() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "risky.vy", LOW_FINDING_CONTRACT)

        result = runner.invoke(app, ["analyze", str(contracts), "--format", "json", "--ci"])

        assert result.exit_code == 1


def test_analyze_directory_supports_sarif_output() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "safe.vy", SAFE_CONTRACT)

        result = runner.invoke(app, ["analyze", str(contracts), "--format", "sarif"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["version"] == "2.1.0"
        assert len(payload["runs"]) == 1
        assert payload["runs"][0]["properties"]["contracts_analyzed"] == 1


def test_analyze_directory_supports_html_output() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "safe.vy", SAFE_CONTRACT)

        result = runner.invoke(app, ["analyze", str(contracts), "--format", "html"])

        assert result.exit_code == 0
        assert "<!doctype html>" in result.output
        assert "Project Security Report" in result.output


def test_analyze_ci_respects_baseline_suppression() -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), LOW_FINDING_CONTRACT)

        first = runner.invoke(app, ["analyze", str(contract), "--format", "json"])
        assert first.exit_code == 0
        first_payload = json.loads(first.output)
        fps = [finding["fingerprint"] for finding in first_payload["findings"]]
        assert fps

        baseline = Path("baseline.json")
        baseline.write_text(json.dumps({"fingerprints": fps}), encoding="utf-8")

        second = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--baseline-file",
                str(baseline),
                "--ci",
            ],
        )
        assert second.exit_code == 0
        second_payload = json.loads(second.output)
        assert second_payload["summary"]["total"] == 0
        baseline_meta = second_payload["analysis_context"]["baseline"]
        assert baseline_meta["entries"] == len(fps)
        assert baseline_meta["findings_suppressed"] >= 1
        assert baseline_meta["findings_active"] == 0


def test_analyze_directory_update_baseline_writes_file() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "risky.vy", LOW_FINDING_CONTRACT)

        baseline = Path("dir-baseline.json")
        result = runner.invoke(
            app,
            [
                "analyze",
                str(contracts),
                "--format",
                "json",
                "--baseline-file",
                str(baseline),
                "--update-baseline",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(baseline.read_text(encoding="utf-8"))
        assert payload["$schema"] == "vyper-guard-finding-baseline/v1"
        assert payload["target"] == str(contracts)
        assert isinstance(payload["fingerprints"], list)


def test_analyze_directory_json_includes_baseline_review_metadata() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "risky.vy", LOW_FINDING_CONTRACT)

        first = runner.invoke(app, ["analyze", str(contracts), "--format", "json"])
        assert first.exit_code == 0
        first_payload = json.loads(first.output)
        fps: list[str] = []
        for report in first_payload["reports"]:
            fps.extend([finding["fingerprint"] for finding in report["findings"]])
        assert fps

        baseline = Path("dir-baseline.json")
        baseline.write_text(json.dumps({"fingerprints": fps}), encoding="utf-8")

        second = runner.invoke(
            app,
            [
                "analyze",
                str(contracts),
                "--format",
                "json",
                "--baseline-file",
                str(baseline),
            ],
        )
        assert second.exit_code == 0
        second_payload = json.loads(second.output)
        baseline_meta = second_payload["baseline"]
        assert baseline_meta["entries"] == len(fps)
        assert baseline_meta["findings_suppressed"] >= 1
        assert baseline_meta["findings_active"] == 0


def test_analyze_baseline_diff_requires_baseline_file() -> None:
    with runner.isolated_filesystem():
        contract = _write_contract(Path("contract.vy"), SAFE_CONTRACT)

        result = runner.invoke(
            app, ["analyze", str(contract), "--format", "json", "--baseline-diff"]
        )

        assert result.exit_code == 2


def test_analyze_single_file_includes_baseline_diff_metadata() -> None:
    with runner.isolated_filesystem():
        risky = _write_contract(Path("risky.vy"), LOW_FINDING_CONTRACT)

        first = runner.invoke(app, ["analyze", str(risky), "--format", "json"])
        assert first.exit_code == 0
        first_payload = json.loads(first.output)
        fps = [finding["fingerprint"] for finding in first_payload["findings"]]
        assert fps

        baseline = Path("baseline.json")
        baseline.write_text(json.dumps({"fingerprints": fps}), encoding="utf-8")

        second = runner.invoke(
            app,
            [
                "analyze",
                str(risky),
                "--format",
                "json",
                "--baseline-file",
                str(baseline),
                "--baseline-diff",
            ],
        )

        assert second.exit_code == 0
        second_payload = json.loads(second.output)
        diff = second_payload["analysis_context"]["baseline_diff"]
        assert diff["baseline_entries"] == len(fps)
        assert diff["new_count"] == 0
        assert diff["resolved_count"] == 0
        assert diff["unchanged_count"] >= 1


def test_analyze_directory_json_includes_baseline_diff_metadata() -> None:
    with runner.isolated_filesystem():
        contracts = Path("contracts")
        contracts.mkdir(parents=True, exist_ok=True)
        _write_contract(contracts / "risky.vy", LOW_FINDING_CONTRACT)

        first = runner.invoke(app, ["analyze", str(contracts), "--format", "json"])
        assert first.exit_code == 0
        first_payload = json.loads(first.output)
        fps: list[str] = []
        for report in first_payload["reports"]:
            fps.extend([finding["fingerprint"] for finding in report["findings"]])
        assert fps

        baseline = Path("dir-baseline.json")
        baseline.write_text(json.dumps({"fingerprints": fps}), encoding="utf-8")

        second = runner.invoke(
            app,
            [
                "analyze",
                str(contracts),
                "--format",
                "json",
                "--baseline-file",
                str(baseline),
                "--baseline-diff",
            ],
        )

        assert second.exit_code == 0
        second_payload = json.loads(second.output)
        diff = second_payload["baseline_diff"]
        assert diff["baseline_entries"] == len(fps)
        assert diff["new_count"] == 0
        assert diff["resolved_count"] == 0
        assert diff["unchanged_count"] >= 1
