"""Tests for semantic summary extraction."""

from __future__ import annotations

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.semantic import build_semantic_summary

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
