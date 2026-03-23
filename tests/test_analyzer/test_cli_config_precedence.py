"""CLI contract tests: config defaults and CLI override precedence."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()


LOW_ONLY_CONTRACT = """\
# pragma version ^0.4.0

@external
@view
def check_time() -> bool:
    assert block.timestamp > 100
    return True
"""


def _write_project_files(
    root: Path, *, severity: str = "HIGH", default_format: str = "json"
) -> Path:
    contract = root / "contract.vy"
    contract.write_text(LOW_ONLY_CONTRACT, encoding="utf-8")

    cfg = root / ".guardianrc"
    cfg.write_text(
        f"""\
analysis:
  enabled_detectors:
    - all
  disabled_detectors: []
  severity_threshold: {severity}

reporting:
  default_format: {default_format}
  show_source_snippets: true
  show_fix_suggestions: true
""",
        encoding="utf-8",
    )
    return contract


def test_config_default_format_is_used_when_no_flag() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        contract = _write_project_files(root, default_format="json")

        result = runner.invoke(app, ["analyze", str(contract)])

        assert result.exit_code == 0
        assert '"$schema": "vyper-guard-report/v1"' in result.stdout


def test_config_severity_threshold_filters_findings() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        contract = _write_project_files(root, severity="HIGH")

        result = runner.invoke(app, ["analyze", str(contract), "--format", "json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["summary"]["total"] == 0


def test_cli_severity_threshold_overrides_config() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        contract = _write_project_files(root, severity="HIGH")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--severity-threshold",
                "LOW",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["summary"]["total"] >= 1
