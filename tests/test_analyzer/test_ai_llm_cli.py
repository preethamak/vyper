from __future__ import annotations

import json
from pathlib import Path

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


def test_ai_llm_mode_falls_back_to_deterministic_when_unavailable() -> None:
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
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "ai_triage" in payload
        assert payload["ai_triage_policy"]["deterministic"] is True


def test_ai_llm_mode_calls_api_and_sets_nondeterministic_policy(monkeypatch) -> None:
    class _Resp:
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
            env={"GUARDIAN_LLM_API_KEY": "test-key"},
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["ai_triage_policy"]["deterministic"] is False
        assert payload["ai_triage_policy"]["provider"] == "openai_compatible"
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
