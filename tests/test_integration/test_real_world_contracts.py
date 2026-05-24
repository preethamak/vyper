from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
REAL_WORLD_DIR = ROOT / "test_contracts" / "real_world"


def _real_world_contracts() -> list[Path]:
    if not REAL_WORLD_DIR.exists():
        return []
    return sorted(REAL_WORLD_DIR.glob("*.vy"))


def test_real_world_contracts_present() -> None:
    contracts = _real_world_contracts()
    assert len(contracts) >= 20


@pytest.mark.parametrize("contract", _real_world_contracts())
def test_real_world_analyze_json(contract: Path) -> None:
    result = runner.invoke(app, ["analyze", str(contract), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["$schema"] == "vyper-guard-report/v1"
    assert payload["file_path"].endswith(contract.name)
    assert "summary" in payload
    assert isinstance(payload.get("findings"), list)


def test_verify_reports_include_verification_metadata() -> None:
    contracts = _real_world_contracts()
    assert contracts
    unit_cmd = f"{sys.executable} -c \"print('ok')\""
    fuzz_cmd = f"{sys.executable} -c \"print('ok')\""
    result = runner.invoke(
        app,
        [
            "verify",
            str(REAL_WORLD_DIR),
            "--format",
            "json",
            "--unit-cmd",
            unit_cmd,
            "--fuzz-cmd",
            fuzz_cmd,
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    verification = payload.get("verification") or payload.get("analysis_context", {}).get("verification")
    assert isinstance(verification, dict)
    summary = verification.get("summary")
    assert summary and summary.get("passed", 0) >= 2


def test_verify_supports_markdown_and_html_outputs() -> None:
    unit_cmd = f"{sys.executable} -c \"print('ok')\""
    fuzz_cmd = f"{sys.executable} -c \"print('ok')\""

    md = runner.invoke(
        app,
        [
            "verify",
            str(REAL_WORLD_DIR),
            "--format",
            "markdown",
            "--unit-cmd",
            unit_cmd,
            "--fuzz-cmd",
            fuzz_cmd,
        ],
    )
    assert md.exit_code == 0
    assert "Verification" in md.output

    html = runner.invoke(
        app,
        [
            "verify",
            str(REAL_WORLD_DIR),
            "--format",
            "html",
            "--unit-cmd",
            unit_cmd,
            "--fuzz-cmd",
            fuzz_cmd,
        ],
    )
    assert html.exit_code == 0
    assert "<!doctype html>" in html.output
    assert "Verification" in html.output


def test_test_and_fuzz_commands_emit_verification_reports() -> None:
    unit_cmd = f"{sys.executable} -c \"print('ok')\""
    fuzz_cmd = f"{sys.executable} -c \"print('ok')\""

    test_run = runner.invoke(
        app,
        ["test", str(REAL_WORLD_DIR), "--format", "json", "--unit-cmd", unit_cmd],
    )
    assert test_run.exit_code == 0
    test_payload = json.loads(test_run.stdout)
    assert "verification" in test_payload

    fuzz_run = runner.invoke(
        app,
        ["fuzz", str(REAL_WORLD_DIR), "--format", "json", "--fuzz-cmd", fuzz_cmd],
    )
    assert fuzz_run.exit_code == 0
    fuzz_payload = json.loads(fuzz_run.stdout)
    assert "verification" in fuzz_payload
