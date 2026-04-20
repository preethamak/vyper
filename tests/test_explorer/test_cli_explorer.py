from __future__ import annotations

import json

from typer.testing import CliRunner

from guardian.cli import app
from guardian.explorer.client import ExplorerResponse

runner = CliRunner()


def test_explorer_json_output_contains_contract_metadata(monkeypatch) -> None:
    def _fake_fetch(self, address: str):
        return ExplorerResponse(
            address=address,
            network="ethereum",
            source_code="# pragma version ^0.4.0",
            abi=[{"type": "function", "name": "ping"}],
            contract_name="Ping",
            compiler_version="v0.4.0",
            optimization_used=True,
            runs=200,
            is_proxy=False,
            implementation=None,
            function_names=["ping"],
            raw={},
            provider="blockscout",
        )

    monkeypatch.setattr("guardian.explorer.client.ExplorerClient.fetch_contract", _fake_fetch)

    result = runner.invoke(app, ["explorer", "0x123", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["contract_name"] == "Ping"
    assert payload["function_names"] == ["ping"]
    assert payload["provider"] == "blockscout"
    assert payload["explorer"]["source_language"] == "vyper"
    assert payload["explorer"]["stats"]["function_count"] == 1


def test_explorer_rejects_invalid_private_key() -> None:
    result = runner.invoke(
        app,
        ["explorer", "0x123", "--private-key", "bad-key"],
    )
    assert result.exit_code == 2
