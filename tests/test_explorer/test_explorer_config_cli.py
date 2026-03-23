"""Tests for `vyper-guard explorer config` command group."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()


def test_explorer_config_set_and_show_roundtrip(monkeypatch) -> None:
    with runner.isolated_filesystem():
        home = Path.cwd()
        monkeypatch.setenv("HOME", str(home))

        set_provider = runner.invoke(app, ["explorer", "config", "set", "provider", "auto"])
        set_network = runner.invoke(app, ["explorer", "config", "set", "network", "sepolia"])
        set_key = runner.invoke(app, ["explorer", "config", "set", "api-key", "exp-test-key-123456"])

        assert set_provider.exit_code == 0
        assert set_network.exit_code == 0
        assert set_key.exit_code == 0

        shown = runner.invoke(app, ["explorer", "config", "show"])
        assert shown.exit_code == 0
        payload = json.loads(shown.stdout)
        assert payload["provider"] == "auto"
        assert payload["network"] == "sepolia"
        assert payload["api_key_set"] is True


def test_explorer_config_set_rejects_unknown_key() -> None:
    result = runner.invoke(app, ["explorer", "config", "set", "unknown", "x"])
    assert result.exit_code == 2
