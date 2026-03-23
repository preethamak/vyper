"""CLI unification tests: --ai alias, ast/flow commands, and fix command wrapper."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()

SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def deposit(amount: uint256):
    self.balances[msg.sender] += amount

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""


def test_analyze_ai_flag_enables_ai_payload() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            ["analyze", str(contract), "--format", "json", "--ai"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "ai_triage" in payload


def test_ast_json_command_outputs_structure() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(app, ["ast", str(contract), "--format", "json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["file_path"].endswith("contract.vy")
        assert len(payload["functions"]) >= 2


def test_flow_mermaid_command_outputs_graph() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(app, ["flow", str(contract), "--format", "mermaid"])

        assert result.exit_code == 0
        assert "graph TD" in result.stdout
        assert "withdraw" in result.stdout


def test_fix_command_wrapper_runs_dry_run() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "fix",
                str(contract),
                "--fix-dry-run",
                "--max-auto-fix-tier",
                "B",
            ],
        )

        assert result.exit_code == 0
        output = result.output.lower()
        assert "dry-run mode" in output
        assert not contract.with_suffix(".fixed.vy").exists()
