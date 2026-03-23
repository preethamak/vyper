"""CLI contract tests for edge-case behavior and startup guarantees."""

from __future__ import annotations

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
