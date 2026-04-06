from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app
from guardian.explorer.client import ExplorerResponse

runner = CliRunner()

SAFE_SOURCE = """\
# pragma version ^0.4.0

@external
@view
def ping() -> bool:
    return True
"""


def test_agent_can_save_context_and_output(monkeypatch) -> None:
    def _fake_ask(self, prompt: str, *, context=None):
        assert isinstance(context, dict)
        return "agent-answer"

    monkeypatch.setattr("guardian.agents.adk.SecurityAgent.ask", _fake_ask)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SAFE_SOURCE, encoding="utf-8")

        ctx_file = Path("context.json")
        out_file = Path("answer.md")

        result = runner.invoke(
            app,
            [
                "agent",
                "Summarize risks",
                "--file",
                str(contract),
                "--save-context",
                str(ctx_file),
                "--save-output",
                str(out_file),
            ],
        )

        assert result.exit_code == 0
        assert ctx_file.exists()
        assert out_file.exists()
        payload = json.loads(ctx_file.read_text(encoding="utf-8"))
        assert "available_tools" in payload
        assert "local_analysis" in payload


def test_agent_uses_explorer_context_with_overrides(monkeypatch) -> None:
    def _fake_fetch(self, address: str):
        return ExplorerResponse(
            address=address,
            network="sepolia",
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
        )

    def _fake_ask(self, prompt: str, *, context=None):
        assert "explorer" in (context or {})
        return "ok"

    monkeypatch.setattr("guardian.explorer.client.ExplorerClient.fetch_contract", _fake_fetch)
    monkeypatch.setattr("guardian.agents.adk.SecurityAgent.ask", _fake_ask)

    result = runner.invoke(
        app,
        [
            "agent",
            "Analyze contract surface",
            "--address",
            "0x123",
            "--explorer-provider",
            "etherscan",
            "--explorer-network",
            "sepolia",
            "--explorer-api-key",
            "abc",
        ],
    )

    assert result.exit_code == 0


def test_agent_memory_tail_stats_clear_cycle() -> None:
    with runner.isolated_filesystem():
        memory = Path("mem.jsonl")
        memory.write_text(
            '{"prompt":"a","answer":"b"}\n{"prompt":"c","answer":"d"}\n',
            encoding="utf-8",
        )

        stats = runner.invoke(app, ["agent-memory", "stats", "--memory-file", str(memory)])
        assert stats.exit_code == 0
        stats_payload = json.loads(stats.stdout)
        assert stats_payload["entries"] == 2

        tail = runner.invoke(
            app, ["agent-memory", "tail", "--memory-file", str(memory), "--limit", "1"]
        )
        assert tail.exit_code == 0
        tail_payload = json.loads(tail.stdout)
        assert len(tail_payload) == 1

        cleared = runner.invoke(app, ["agent-memory", "clear", "--memory-file", str(memory)])
        assert cleared.exit_code == 0
        assert not memory.exists()


def test_agent_fails_by_default_when_llm_unavailable(monkeypatch) -> None:
    from guardian.agents.adk import AgentError

    def _fail_ask(self, prompt: str, *, context=None):
        raise AgentError("429 Too Many Requests")

    monkeypatch.setattr("guardian.agents.adk.SecurityAgent.ask", _fail_ask)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SAFE_SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "agent",
                "Analyze this contract",
                "--file",
                str(contract),
            ],
        )

        assert result.exit_code == 2
        combined = result.stdout + result.stderr
        assert "Agent LLM request failed" in combined


def test_agent_returns_fallback_output_when_explicitly_allowed(monkeypatch) -> None:
    from guardian.agents.adk import AgentError

    def _fail_ask(self, prompt: str, *, context=None):
        raise AgentError("429 Too Many Requests")

    monkeypatch.setattr("guardian.agents.adk.SecurityAgent.ask", _fail_ask)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SAFE_SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "agent",
                "Analyze this contract",
                "--file",
                str(contract),
                "--allow-fallback",
            ],
        )

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "Agent Fallback Response" in combined
        assert "prioritized_actions" in combined


def test_agent_provider_override_is_forwarded(monkeypatch) -> None:
    def _fake_ask(self, prompt: str, *, context=None):
        assert self.provider == "gemini"
        return "ok"

    monkeypatch.setattr("guardian.agents.adk.SecurityAgent.ask", _fake_ask)

    with runner.isolated_filesystem():
        contract = Path("contract.vy")
        contract.write_text(SAFE_SOURCE, encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "agent",
                "Analyze this contract",
                "--file",
                str(contract),
                "--provider",
                "gemini",
            ],
        )

        assert result.exit_code == 0


def test_agent_memory_retention_is_bounded() -> None:
    from guardian.agents.adk import AgentMemory

    with runner.isolated_filesystem():
        memory = AgentMemory(Path("mem.jsonl"), max_entries=2)
        memory.append({"prompt": "a", "answer": "1"})
        memory.append({"prompt": "b", "answer": "2"})
        memory.append({"prompt": "c", "answer": "3"})

        tail = memory.tail(10)
        assert len(tail) == 2
        assert tail[0]["prompt"] == "b"
        assert tail[1]["prompt"] == "c"
