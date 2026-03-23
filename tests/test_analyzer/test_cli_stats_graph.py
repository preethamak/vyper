from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()


SAMPLE_CONTRACT = """\
# pragma version ^0.4.0

owner: public(address)

event Ping:
    ok: bool

@external
@view
def ping() -> bool:
    return True
"""


def test_stats_graph_writes_default_json_and_html_artifacts() -> None:
    with runner.isolated_filesystem():
        contract = Path("sample.vy")
        contract.write_text(SAMPLE_CONTRACT, encoding="utf-8")

        result = runner.invoke(app, ["stats", str(contract), "--graph"])

        assert result.exit_code == 0

        json_path = Path("sample.stats.json")
        html_path = Path("sample.stats.html")
        assert json_path.exists()
        assert html_path.exists()

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        assert payload["metrics"]["functions"] == 1
        assert payload["metrics"]["state_variables"] == 1
        assert payload["metrics"]["events"] == 1

        html = html_path.read_text(encoding="utf-8")
        assert "Vyper Guard Stats Graph" in html
        assert "line_breakdown" in html


def test_stats_graph_respects_custom_output_paths() -> None:
    with runner.isolated_filesystem():
        contract = Path("sample.vy")
        contract.write_text(SAMPLE_CONTRACT, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "stats",
                str(contract),
                "--graph-json",
                "artifacts/overview.json",
                "--graph-html",
                "artifacts/overview.html",
            ],
        )

        assert result.exit_code == 0
        assert Path("artifacts/overview.json").exists()
        assert Path("artifacts/overview.html").exists()
