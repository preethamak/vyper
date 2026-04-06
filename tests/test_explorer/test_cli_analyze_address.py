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


def test_analyze_address_ai_alias_uses_llm_when_configured(monkeypatch) -> None:
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

    def _fake_llm_triage(report, source_code, **kwargs):
        report.ai_triage = [
            {
                "finding_index": 0,
                "priority_rank": 1,
                "detector": "mock_detector",
                "title": "mock",
                "severity": "INFO",
                "triage_bucket": "review_later",
                "confidence": 0.5,
                "scoring_rationale": {"version": "llm_triage_v1"},
                "suggested_next_step": "none",
                "reasoning": "mock",
                "evidence_refs": [],
                "provenance": {"mode": "llm_triage_v1", "deterministic": False},
            }
        ]
        report.ai_triage_policy = {
            "policy_version": "1.0.0",
            "status": "stable",
            "deterministic": False,
            "can_override_verdict": False,
            "provider": "openai_compatible",
            "model": "gpt-5",
            "warnings": [],
        }
        return report

    monkeypatch.setattr("guardian.explorer.client.ExplorerClient.fetch_contract", _fake_fetch)
    monkeypatch.setattr("guardian.agents.llm_triage.apply_llm_triage", _fake_llm_triage)

    result = runner.invoke(
        app,
        ["analyze-address", "0x123", "--format", "json", "--ai"],
        env={"GUARDIAN_LLM_API_KEY": "test-key"},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ai_triage_policy"]["deterministic"] is False
