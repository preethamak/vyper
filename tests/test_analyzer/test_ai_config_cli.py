"""Tests for `vyper-guard ai config` command group."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()


def test_ai_config_set_and_show_roundtrip(monkeypatch) -> None:
    with runner.isolated_filesystem():
        home = Path.cwd()
        monkeypatch.setenv("HOME", str(home))

        set_provider = runner.invoke(app, ["ai", "config", "set", "provider", "openai"])
        set_model = runner.invoke(app, ["ai", "config", "set", "model", "gpt-5.3-codex"])
        set_key = runner.invoke(app, ["ai", "config", "set", "api-key", "sk-test-key-123456"])

        assert set_provider.exit_code == 0
        assert set_model.exit_code == 0
        assert set_key.exit_code == 0

        cfg_file = home / ".guardianrc"
        assert cfg_file.exists()

        shown = runner.invoke(app, ["ai", "config", "show"])
        assert shown.exit_code == 0
        payload = json.loads(shown.stdout)
        assert payload["provider"] == "openai"
        assert payload["model"] == "gpt-5.3-codex"
        assert payload["api_key_set"] is True
        assert payload["api_key"].startswith("sk-")


def test_ai_config_set_api_key_interactive_prompt(monkeypatch) -> None:
    with runner.isolated_filesystem():
        home = Path.cwd()
        monkeypatch.setenv("HOME", str(home))

        result = runner.invoke(
            app,
            ["ai", "config", "set", "api-key"],
            input="sk-interactive-abc\nsk-interactive-abc\n",
        )

        assert result.exit_code == 0
        shown = runner.invoke(app, ["ai", "config", "show"])
        assert shown.exit_code == 0
        payload = json.loads(shown.stdout)
        assert payload["api_key_set"] is True


def test_ai_config_set_rejects_unknown_key() -> None:
    result = runner.invoke(app, ["ai", "config", "set", "unknown", "x"])
    assert result.exit_code == 2
