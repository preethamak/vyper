"""Tests for `vyper-guard ai config` command group."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app
from guardian.utils.config import load_config

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


def test_ai_config_set_provider_gemini_sets_compatible_defaults(monkeypatch) -> None:
    with runner.isolated_filesystem():
        home = Path.cwd()
        monkeypatch.setenv("HOME", str(home))

        result = runner.invoke(app, ["ai", "config", "set", "provider", "gemini"])
        assert result.exit_code == 0

        shown = runner.invoke(app, ["ai", "config", "show"])
        assert shown.exit_code == 0
        payload = json.loads(shown.stdout)
        assert payload["provider"] == "gemini"
        assert payload["base_url"] == "https://generativelanguage.googleapis.com/v1beta/openai"
        assert payload["model"].startswith("gemini-")


def test_load_config_merges_user_and_project_config(monkeypatch) -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        home = root / "fake_home"
        home.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("GUARDIAN_LLM_API_KEY", raising=False)
        monkeypatch.delenv("GUARDIAN_LLM_MODEL", raising=False)
        monkeypatch.delenv("GUARDIAN_LLM_ENABLED", raising=False)

        (home / ".guardianrc").write_text(
            """\
llm:
    provider: openai_compatible
    model: gpt-5.4-mini
    api_key: sk-merge-test-key
    enabled: true
""",
            encoding="utf-8",
        )

        (root / ".guardianrc").write_text(
            """\
reporting:
    default_format: json
analysis:
    severity_threshold: HIGH
""",
            encoding="utf-8",
        )

        cfg = load_config()

        assert cfg.reporting.default_format == "json"
        assert cfg.analysis.severity_threshold == "HIGH"
        assert cfg.llm.model == "gpt-5.4-mini"
        assert cfg.llm.enabled is True
        assert cfg.llm.api_key == "sk-merge-test-key"


def test_load_config_reads_llm_memory_max_entries_from_env(monkeypatch) -> None:
    monkeypatch.setenv("GUARDIAN_LLM_MEMORY_MAX_ENTRIES", "123")

    cfg = load_config()

    assert cfg.llm.memory_max_entries == 123


def test_load_config_does_not_trust_parent_by_default(monkeypatch) -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        parent_cfg = root / ".guardianrc"
        parent_cfg.write_text(
            """\
analysis:
  severity_threshold: CRITICAL
""",
            encoding="utf-8",
        )

        child = root / "child"
        child.mkdir()
        monkeypatch.delenv("GUARDIAN_TRUST_PARENT_CONFIG", raising=False)

        cfg = load_config(start_dir=child)
        assert cfg.analysis.severity_threshold == "LOW"


def test_load_config_can_trust_parent_when_explicitly_enabled(monkeypatch) -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        parent_cfg = root / ".guardianrc"
        parent_cfg.write_text(
            """\
analysis:
  severity_threshold: CRITICAL
""",
            encoding="utf-8",
        )

        child = root / "child"
        child.mkdir()
        monkeypatch.setenv("GUARDIAN_TRUST_PARENT_CONFIG", "1")

        cfg = load_config(start_dir=child)
        assert cfg.analysis.severity_threshold == "CRITICAL"


def test_invalid_env_overrides_are_ignored(monkeypatch) -> None:
    monkeypatch.setenv("GUARDIAN_DEFAULT_FORMAT", "xml")
    monkeypatch.setenv("GUARDIAN_SEVERITY_THRESHOLD", "SEVERE")
    monkeypatch.setenv("GUARDIAN_MAX_AUTO_FIX_TIER", "Z")

    cfg = load_config()

    assert cfg.reporting.default_format == "cli"
    assert cfg.analysis.severity_threshold == "LOW"
    assert cfg.remediation.max_auto_fix_tier == "C"
