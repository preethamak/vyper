from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from typer.testing import CliRunner

from guardian.cli import app
from guardian.utils.config import load_config

runner = CliRunner()

SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""


def test_ai_llm_mode_fails_by_default_when_unavailable() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai-triage",
                "--ai-triage-mode",
                "llm",
            ],
            env={"HOME": str(Path.cwd())},
        )

        assert result.exit_code == 2
        combined = result.stdout + result.stderr
        assert "LLM triage failed" in combined


def test_ai_llm_mode_falls_back_when_explicitly_allowed() -> None:
    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai-triage",
                "--ai-triage-mode",
                "llm",
                "--allow-ai-fallback",
            ],
            env={"HOME": str(Path.cwd())},
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "ai_triage" in payload
        assert payload["ai_triage_policy"]["deterministic"] is True
        assert payload["ai_triage_policy"]["fallback_from"] == "llm"
        assert "fallback_reason" in payload["ai_triage_policy"]


def test_ai_llm_mode_calls_api_and_sets_nondeterministic_policy(monkeypatch) -> None:
    class _Resp:
        status_code: ClassVar[int] = 200
        reason: ClassVar[str] = "OK"
        headers: ClassVar[dict[str, str]] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self):
            content = json.dumps(
                {
                    "items": [
                        {
                            "finding_index": 0,
                            "priority_rank": 1,
                            "triage_bucket": "review_now",
                            "confidence": 0.91,
                            "suggested_next_step": "Patch raw_call handling first.",
                            "reasoning": "Unchecked external call with state mutation impact.",
                        }
                    ]
                }
            )
            return {"choices": [{"message": {"content": content}}]}

    def _fake_post(*args, **kwargs):
        return _Resp()

    monkeypatch.setattr("guardian.agents.llm_triage.requests.post", _fake_post)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai-triage",
                "--ai-triage-mode",
                "llm",
            ],
            env={
                "GUARDIAN_LLM_API_KEY": "test-key",
                "GUARDIAN_LLM_PROVIDER": "openai_compatible",
                "GUARDIAN_LLM_BASE_URL": "https://api.openai.com/v1",
                "GUARDIAN_LLM_MODEL": "gpt-5",
            },
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["ai_triage_policy"]["deterministic"] is False
        assert payload["ai_triage_policy"]["provider"] == "openai_compatible"
        assert payload["ai_triage"][0]["provenance"]["mode"] == "llm_triage_v1"


def test_ai_flag_prefers_llm_when_api_key_available(monkeypatch) -> None:
    class _Resp:
        status_code: ClassVar[int] = 200
        reason: ClassVar[str] = "OK"
        headers: ClassVar[dict[str, str]] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self):
            content = json.dumps(
                {
                    "items": [
                        {
                            "finding_index": 0,
                            "priority_rank": 1,
                            "triage_bucket": "review_now",
                            "confidence": 0.93,
                            "suggested_next_step": "Apply nonreentrant and CEI fixes.",
                            "reasoning": "High exploitability from external call ordering.",
                        }
                    ]
                }
            )
            return {"choices": [{"message": {"content": content}}]}

    def _fake_post(*args, **kwargs):
        return _Resp()

    monkeypatch.setattr("guardian.agents.llm_triage.requests.post", _fake_post)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai",
            ],
            env={
                "GUARDIAN_LLM_API_KEY": "test-key",
                "GUARDIAN_LLM_PROVIDER": "openai_compatible",
                "GUARDIAN_LLM_BASE_URL": "https://api.openai.com/v1",
                "GUARDIAN_LLM_MODEL": "gpt-5",
            },
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["ai_triage_policy"]["deterministic"] is False
        assert payload["ai_triage"][0]["provenance"]["mode"] == "llm_triage_v1"


def test_load_config_reads_llm_and_explorer_api_keys_from_env(monkeypatch) -> None:
    monkeypatch.setenv("GUARDIAN_LLM_API_KEY", "llm-key")
    monkeypatch.setenv("GUARDIAN_EXPLORER_API_KEY", "exp-key")
    monkeypatch.setenv("GUARDIAN_LLM_ENABLED", "true")
    monkeypatch.setenv("GUARDIAN_LLM_MODEL", "gpt-5")

    cfg = load_config()

    assert cfg.llm.enabled is True
    assert cfg.llm.api_key == "llm-key"
    assert cfg.llm.model == "gpt-5"
    assert cfg.explorer.api_key == "exp-key"


def test_ai_llm_mode_uses_gemini_header_when_provider_is_gemini(monkeypatch) -> None:
    class _Resp:
        status_code: ClassVar[int] = 200
        reason: ClassVar[str] = "OK"
        headers: ClassVar[dict[str, str]] = {}

        def json(self):
            content = json.dumps(
                {
                    "items": [
                        {
                            "finding_index": 0,
                            "priority_rank": 1,
                            "triage_bucket": "review_now",
                            "confidence": 0.9,
                            "suggested_next_step": "Patch first.",
                            "reasoning": "High risk.",
                        }
                    ]
                }
            )
            return {"candidates": [{"content": {"parts": [{"text": content}]}}]}

    def _fake_post(url, headers=None, **kwargs):
        assert isinstance(headers, dict)
        assert headers.get("Content-Type") == "application/json"
        assert kwargs.get("params", {}).get("key") == "gemini-test-key"
        assert url.endswith("/models/gemini-2.0-flash:generateContent")
        return _Resp()

    monkeypatch.setattr("guardian.agents.llm_triage.requests.post", _fake_post)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai-triage",
                "--ai-triage-mode",
                "llm",
            ],
            env={
                "GUARDIAN_LLM_PROVIDER": "gemini",
                "GUARDIAN_LLM_MODEL": "gemini-2.0-flash",
                "GUARDIAN_LLM_API_KEY": "gemini-test-key",
                "GUARDIAN_LLM_BASE_URL": "https://generativelanguage.googleapis.com/v1beta",
            },
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["ai_triage_policy"]["deterministic"] is False
        assert payload["ai_triage_policy"]["provider"] == "gemini"


def test_ai_llm_mode_uses_openai_compat_for_gemini_openai_base(monkeypatch) -> None:
    class _Resp:
        status_code: ClassVar[int] = 200
        reason: ClassVar[str] = "OK"
        headers: ClassVar[dict[str, str]] = {}

        def json(self):
            content = json.dumps(
                {
                    "items": [
                        {
                            "finding_index": 0,
                            "priority_rank": 1,
                            "triage_bucket": "review_now",
                            "confidence": 0.9,
                            "suggested_next_step": "Patch first.",
                            "reasoning": "High risk.",
                        }
                    ]
                }
            )
            return {"choices": [{"message": {"content": content}}]}

    def _fake_post(url, headers=None, json=None, **kwargs):
        assert url.endswith("/chat/completions")
        assert isinstance(headers, dict)
        assert str(headers.get("Authorization", "")).startswith("Bearer ")
        assert isinstance(json, dict)
        assert "response_format" not in json
        return _Resp()

    monkeypatch.setattr("guardian.agents.llm_triage.requests.post", _fake_post)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "analyze",
                str(contract),
                "--format",
                "json",
                "--ai-triage",
                "--ai-triage-mode",
                "llm",
            ],
            env={
                "GUARDIAN_LLM_PROVIDER": "gemini",
                "GUARDIAN_LLM_MODEL": "gemini-2.0-flash",
                "GUARDIAN_LLM_API_KEY": "gemini-test-key",
                "GUARDIAN_LLM_BASE_URL": "https://generativelanguage.googleapis.com/v1beta/openai",
            },
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["ai_triage_policy"]["deterministic"] is False
        assert payload["ai_triage_policy"]["provider"] == "gemini"
