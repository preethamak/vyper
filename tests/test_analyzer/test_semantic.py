"""Tests for semantic summary extraction."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.semantic import _SEMANTIC_CACHE, build_semantic_summary
from guardian.analyzer.static import StaticAnalyzer

SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]
owner: address

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
    log Withdraw(msg.sender, amount)

@external
def exec_delegate(target: address, data: Bytes[256]):
    assert raw_call(target, data, is_delegate_call=True)
"""


def test_semantic_summary_extracts_reads_writes_and_calls() -> None:
    contract = parse_vyper_source(SOURCE, "sample.vy")
    summary = build_semantic_summary(contract)

    withdraw = summary.functions["withdraw"]
    assert "balances" in withdraw.state_writes
    assert withdraw.external_calls >= 1
    assert withdraw.external_calls_in_loop is False
    assert withdraw.emits_event is True


def test_semantic_summary_detects_delegatecall_usage() -> None:
    contract = parse_vyper_source(SOURCE, "sample.vy")
    summary = build_semantic_summary(contract)

    delegate = summary.functions["exec_delegate"]
    assert delegate.uses_delegatecall is True


def test_semantic_summary_detects_multiline_dynarray_mapping() -> None:
    source = """\
# pragma version ^0.3.7

user_tokens: HashMap[
    address,
    DynArray[uint256, 100]
]
"""
    contract = parse_vyper_source(source, "sample.vy")
    summary = build_semantic_summary(contract)

    assert summary.uses_dynarray_in_mapping is True


def test_semantic_summary_detects_external_call_inside_loop() -> None:
    source = """\
# pragma version ^0.4.0

users: DynArray[address, 100]

@external
def payout():
    for u: address in self.users:
        send(u, 1)
"""
    contract = parse_vyper_source(source, "sample.vy")
    summary = build_semantic_summary(contract)

    payout = summary.functions["payout"]
    assert payout.external_calls_in_loop is True


def test_forced_compiler_mode_reports_source_when_compiler_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("guardian.analyzer.static.check_vyper_available", lambda: None)
    monkeypatch.setattr("guardian.analyzer.static.discover_compilers", lambda: ())
    report = StaticAnalyzer(semantic_mode="compiler").analyze_source(SOURCE, "sample.vy")
    assert report.analysis_context["semantic_mode"] == "source"


def test_compiler_cli_backend_extracts_semantics(monkeypatch, tmp_path) -> None:
    ast_payload = {
        "ast": {
            "ast_type": "Module",
            "body": [
                {
                    "ast_type": "FunctionDef",
                    "name": "run",
                    "body": [
                        {
                            "ast_type": "Assign",
                            "target": {
                                "ast_type": "Attribute",
                                "value": {"ast_type": "Name", "id": "self"},
                                "attr": "balance",
                            },
                            "value": {"ast_type": "Int", "value": 1},
                        },
                        {
                            "ast_type": "Call",
                            "func": {"ast_type": "Name", "id": "raw_call"},
                            "args": [],
                            "keywords": [],
                        },
                        {"ast_type": "Log", "value": {"ast_type": "Call", "args": []}},
                    ],
                }
            ],
        }
    }
    monkeypatch.setattr("guardian.analyzer.semantic._parse_vyper_ast", lambda _: None)
    monkeypatch.setattr("guardian.analyzer.semantic.check_vyper_available", lambda: "0.4.3")
    monkeypatch.setattr(
        "guardian.analyzer.semantic.resolve_compiler",
        lambda _: SimpleNamespace(
            candidate=SimpleNamespace(executable="/usr/bin/vyper", version_text="0.4.3"),
            reason=None,
        ),
    )
    monkeypatch.setattr(
        "guardian.analyzer.semantic.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, json.dumps(ast_payload), ""
        ),
    )
    _SEMANTIC_CACHE.clear()
    contract = parse_vyper_source(
        "# pragma version ^0.4.0\n\nbalance: uint256\n\n@external\ndef run():\n    pass\n",
        str(tmp_path / "sample.vy"),
    ).model_copy(update={"semantic_mode": "compiler"})

    summary = build_semantic_summary(contract)

    assert summary.engine == "compiler-cli"
    assert summary.compiler_version == "0.4.3"
    assert summary.functions["run"].state_writes == {"balance"}
    assert summary.functions["run"].external_calls == 1
    assert summary.functions["run"].emits_event is True
