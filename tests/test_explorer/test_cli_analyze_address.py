from __future__ import annotations

import json

from typer.testing import CliRunner

from guardian.cli import app
from guardian.explorer.client import ExplorerResponse

runner = CliRunner()


def test_analyze_address_json_output(monkeypatch) -> None:
    def _fake_fetch(self, address: str):
        return ExplorerResponse(
            address=address,
            network="ethereum",
            source_code="# pragma version ^0.4.0\n@external\ndef ping() -> bool:\n    return True\n",
            abi=[{"type": "function", "name": "ping"}],
            contract_name="Ping",
            compiler_version="^0.4.0",
            optimization_used=True,
            runs=200,
            is_proxy=False,
            implementation=None,
            function_names=["ping"],
            raw={},
        )

    monkeypatch.setattr("guardian.explorer.client.ExplorerClient.fetch_contract", _fake_fetch)

    result = runner.invoke(app, ["analyze-address", "0x123", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["file_path"] == "explorer://ethereum/0x123"
    assert "summary" in payload


def test_analyze_address_requires_verified_source(monkeypatch) -> None:
    def _fake_fetch(self, address: str):
        return ExplorerResponse(
            address=address,
            network="ethereum",
            source_code=None,
            abi=[],
            contract_name="Unknown",
            compiler_version=None,
            optimization_used=None,
            runs=None,
            is_proxy=None,
            implementation=None,
            function_names=[],
            raw={},
        )

    monkeypatch.setattr("guardian.explorer.client.ExplorerClient.fetch_contract", _fake_fetch)

    result = runner.invoke(app, ["analyze-address", "0x123", "--format", "json"])

    assert result.exit_code == 2
