"""Tests for the individual Vyper vulnerability detectors."""

from __future__ import annotations

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.compiler_check import check_compiler_version
from guardian.analyzer.static import StaticAnalyzer
from guardian.analyzer.vyper_detector import (
    CEIViolationDetector,
    DangerousDelegatecallDetector,
    IntegerOverflowDetector,
    MissingEventEmissionDetector,
    MissingNonreentrantDetector,
    SendInLoopDetector,
    TimestampDependenceDetector,
    UncheckedSendDetector,
    UncheckedSubtractionDetector,
    UnprotectedSelfdestructDetector,
    UnprotectedStateChangeDetector,
    UnsafeRawCallDetector,
)
from guardian.models import Severity

# -------------------------------------------------------------------------
# Helper
# -------------------------------------------------------------------------


def _run_detector(detector_cls, source: str):
    contract = parse_vyper_source(source, "<test>")
    detector = detector_cls()
    return detector.detect(contract)


# -------------------------------------------------------------------------
# MissingNonreentrantDetector
# -------------------------------------------------------------------------


class TestMissingNonreentrant:
    def test_flags_external_send_without_nonreentrant(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    send(msg.sender, 100)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "nonreentrant" in results[0].title.lower()

    def test_ignores_external_with_nonreentrant(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
@nonreentrant
def withdraw():
    send(msg.sender, 100)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 0

    def test_ignores_view_functions(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
@view
def get_value() -> uint256:
    return 42
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 0

    def test_flags_raw_call_without_nonreentrant(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def execute(target: address, data: Bytes[1024]):
    raw_call(target, data)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 1

    def test_negated_sender_assert_does_not_count_as_access_control(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
def withdraw(amount: uint256):
    assert msg.sender != self.owner
    raw_call(msg.sender, b"", value=amount)
    self.owner = msg.sender
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL

    def test_interface_call_without_nonreentrant_is_detected(self) -> None:
        source = """\
# pragma version ^0.4.0

interface IERC20:
    def transfer(to: address, amount: uint256) -> bool: nonpayable

token: public(address)

@external
def payout(to: address, amount: uint256):
    IERC20(self.token).transfer(to, amount)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 1

    def test_state_only_setter_without_external_call_surface_is_not_flagged(self) -> None:
        source = """\
# pragma version ^0.4.0

count: uint256

@external
def set_count(v: uint256):
    self.count = v
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# UnsafeRawCallDetector
# -------------------------------------------------------------------------


class TestUnsafeRawCall:
    def test_flags_unchecked_raw_call(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def execute(target: address, data: Bytes[1024]):
    raw_call(target, data)
"""
        results = _run_detector(UnsafeRawCallDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH

    def test_ignores_asserted_raw_call(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def execute(target: address, data: Bytes[1024]):
    assert raw_call(target, data)
"""
        results = _run_detector(UnsafeRawCallDetector, source)
        assert len(results) == 0

    def test_ignores_raw_call_with_revert_on_failure_true(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def execute(target: address, data: Bytes[1024]):
    raw_call(target, data, revert_on_failure=True)
"""
        results = _run_detector(UnsafeRawCallDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# MissingEventEmissionDetector
# -------------------------------------------------------------------------


class TestMissingEventEmission:
    def test_flags_state_change_without_event(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
def set_value():
    self.owner = msg.sender
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.LOW

    def test_ignores_function_with_event(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

event OwnerChanged:
    new_owner: address

@external
def set_value():
    self.owner = msg.sender
    log OwnerChanged(msg.sender)
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# UncheckedSendDetector
# -------------------------------------------------------------------------


class TestUncheckedSend:
    def test_flags_unchecked_send(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    send(msg.sender, 100)
"""
        results = _run_detector(UncheckedSendDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH

    def test_ignores_asserted_send(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    assert send(msg.sender, 100)
"""
        results = _run_detector(UncheckedSendDetector, source)
        assert len(results) == 0

    def test_ignores_checked_assignment(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    ok: bool = send(msg.sender, 100)
    assert ok
"""
        results = _run_detector(UncheckedSendDetector, source)
        assert len(results) == 0

    def test_ignores_if_not_send(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    if not send(msg.sender, 100):
        assert False
"""
        results = _run_detector(UncheckedSendDetector, source)
        assert len(results) == 0

    def test_comparison_is_not_treated_as_state_write(self) -> None:
        source = """\
# pragma version ^0.4.0

paused: bool

@external
def check_only() -> bool:
    if self.paused == True:
        return True
    return False
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# TimestampDependenceDetector
# -------------------------------------------------------------------------


class TestTimestampDependence:
    def test_flags_timestamp_in_assert(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def check():
    assert block.timestamp > 1000, "Too early"
"""
        results = _run_detector(TimestampDependenceDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.LOW

    def test_ignores_timestamp_assignment(self) -> None:
        source = """\
# pragma version ^0.4.0

last_update: uint256

@external
def update():
    self.last_update = block.timestamp
"""
        results = _run_detector(TimestampDependenceDetector, source)
        assert len(results) == 0

    def test_large_unrelated_number_does_not_suppress_timestamp_finding(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def check(v: uint256):
    assert block.timestamp > v and 999999 > 1
"""
        results = _run_detector(TimestampDependenceDetector, source)
        assert len(results) == 1


# -------------------------------------------------------------------------
# IntegerOverflowDetector
# -------------------------------------------------------------------------


class TestIntegerOverflow:
    def test_flags_unsafe_math_operations(self) -> None:
        """IntegerOverflowDetector should flag unsafe_add/unsafe_sub/etc."""
        source = """\
# pragma version ^0.4.0

@external
def fast_add(a: uint256, b: uint256) -> uint256:
    return unsafe_add(a, b)
"""
        results = _run_detector(IntegerOverflowDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "unsafe_add" in results[0].title

    def test_no_flag_for_safe_arithmetic(self) -> None:
        """Normal arithmetic should NOT be flagged — Vyper has built-in overflow
        protection since v0.1.x."""
        source = """\
# pragma version ^0.3.9

@external
def add(a: uint256, b: uint256) -> uint256:
    return a + b
"""
        results = _run_detector(IntegerOverflowDetector, source)
        assert len(results) == 0

    def test_no_flag_for_old_version_without_unsafe_ops(self) -> None:
        """Older Vyper versions have overflow protection by default.
        The detector should NOT flag them just for being old."""
        source = """\
# pragma version ^0.3.9
"""
        results = _run_detector(IntegerOverflowDetector, source)
        assert len(results) == 0

    def test_flags_multiple_unsafe_ops(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def risky(a: uint256, b: uint256) -> uint256:
    x: uint256 = unsafe_add(a, b)
    y: uint256 = unsafe_mul(x, 2)
    return y
"""
        results = _run_detector(IntegerOverflowDetector, source)
        assert len(results) == 2


# -------------------------------------------------------------------------
# UnprotectedSelfdestructDetector
# -------------------------------------------------------------------------


class TestUnprotectedSelfdestruct:
    def test_flags_unprotected(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: address

@external
def destroy():
    selfdestruct(self.owner)
"""
        results = _run_detector(UnprotectedSelfdestructDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL

    def test_ignores_protected(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: address

@external
def destroy():
    assert msg.sender == self.owner, "Not owner"
    selfdestruct(self.owner)
"""
        results = _run_detector(UnprotectedSelfdestructDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# DangerousDelegatecallDetector
# -------------------------------------------------------------------------


class TestDangerousDelegatecall:
    def test_flags_delegatecall(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def upgrade(target: address, data: Bytes[1024]):
    raw_call(target, data, is_delegate_call=True)
"""
        results = _run_detector(DangerousDelegatecallDetector, source)
        assert len(results) == 1

    def test_flags_with_access_control_at_lower_severity(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: address

@external
def upgrade(target: address, data: Bytes[1024]):
    assert msg.sender == self.owner, "Not owner"
    raw_call(target, data, is_delegate_call=True)
"""
        results = _run_detector(DangerousDelegatecallDetector, source)
        assert len(results) == 1
        # Should still flag it, but at HIGH not CRITICAL
        assert results[0].severity == Severity.HIGH

    def test_flags_delegatecall_when_boolean_is_lowercase_true(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def upgrade(target: address, data: Bytes[1024]):
    raw_call(target, data, is_delegate_call=true)
"""
        results = _run_detector(DangerousDelegatecallDetector, source)
        assert len(results) == 1


# -------------------------------------------------------------------------
# UnprotectedStateChangeDetector
# -------------------------------------------------------------------------


class TestUnprotectedStateChange:
    def test_flags_unprotected_owner_write(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
def set_owner(new_owner: address):
    self.owner = new_owner
"""
        results = _run_detector(UnprotectedStateChangeDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH

    def test_ignores_protected_write(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
def set_owner(new_owner: address):
    assert msg.sender == self.owner, "Not owner"
    self.owner = new_owner
"""
        results = _run_detector(UnprotectedStateChangeDetector, source)
        assert len(results) == 0

    def test_flags_payable_sensitive_write_without_access_control(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
@payable
def set_owner(new_owner: address):
    self.owner = new_owner
"""
        results = _run_detector(UnprotectedStateChangeDetector, source)
        assert len(results) == 1


# -------------------------------------------------------------------------
# End-to-end: StaticAnalyzer on fixture contracts
# -------------------------------------------------------------------------


class TestStaticAnalyzerEndToEnd:
    """Integration tests running the full pipeline on fixture contracts."""

    def test_vulnerable_vault_has_many_findings(self, vulnerable_vault_source: str) -> None:
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_source(vulnerable_vault_source, "vulnerable_vault.vy")
        # Expect at least 4 findings (nonreentrant, raw_call, event, selfdestruct, owner)
        assert len(report.findings) >= 4
        assert report.security_score < 60

    def test_safe_token_has_no_critical(self, safe_token_source: str) -> None:
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_source(safe_token_source, "safe_token.vy")
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0
        assert report.security_score >= 75

    def test_complex_defi_mixed_findings(self, complex_defi_source: str) -> None:
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_source(complex_defi_source, "complex_defi.vy")
        # Should find timestamp dependence, delegatecall, unprotected state changes
        detector_names = [f.detector_name for f in report.findings]
        assert (
            "timestamp_dependence" in detector_names or "dangerous_delegatecall" in detector_names
        )
        assert report.security_score < 100

    def test_custom_detector_selection(self, vulnerable_vault_source: str) -> None:
        analyzer = StaticAnalyzer(enabled_detectors=["missing_nonreentrant"])
        report = analyzer.analyze_source(vulnerable_vault_source, "vault.vy")
        detector_names = {f.detector_name for f in report.findings}
        # Only compiler_version_check (always runs) and missing_nonreentrant
        assert detector_names <= {"compiler_version_check", "missing_nonreentrant"}

    def test_severity_threshold_filters_low(self, vulnerable_vault_source: str) -> None:
        analyzer = StaticAnalyzer(severity_threshold=Severity.HIGH)
        report = analyzer.analyze_source(vulnerable_vault_source, "vault.vy")
        for f in report.findings:
            assert f.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_detector_crash_is_reported_explicitly(self) -> None:
        class _BrokenDetector:
            NAME = "broken_detector"

            def detect(self, contract):
                raise RuntimeError("boom")

        analyzer = StaticAnalyzer(enabled_detectors=[])
        analyzer._detectors = [_BrokenDetector]  # type: ignore[assignment]

        source = "# pragma version ^0.4.0\nowner: public(address)\n"
        report = analyzer.analyze_source(source, "broken.vy")

        assert "broken_detector" in report.failed_detectors
        assert "broken_detector" in report.detector_errors
        crash_findings = [
            f for f in report.findings if f.detector_name == "detector_runtime_failure"
        ]
        assert len(crash_findings) == 1
        assert crash_findings[0].severity == Severity.CRITICAL
        # Detector failures should additionally degrade score trust.
        assert report.security_score <= 50


# -------------------------------------------------------------------------
# Constructor / __init__ / @deploy exclusion tests
# -------------------------------------------------------------------------


class TestConstructorExclusion:
    """Ensure __init__ and @deploy functions are not flagged by most detectors."""

    def test_init_not_flagged_for_missing_event(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
def __init__():
    self.owner = msg.sender
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 0

    def test_deploy_init_not_flagged_for_missing_event(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@deploy
def __init__():
    self.owner = msg.sender
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 0

    def test_init_not_flagged_for_nonreentrant(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def __init__():
    send(msg.sender, 100)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 0

    def test_init_not_flagged_for_unprotected_state(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: public(address)

@external
def __init__():
    self.owner = msg.sender
"""
        results = _run_detector(UnprotectedStateChangeDetector, source)
        assert len(results) == 0

    def test_default_not_flagged_for_missing_event(self) -> None:
        source = """\
# pragma version ^0.4.0

counter: uint256

@external
@payable
def __default__():
    self.counter += 1
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# No duplicate overflow findings
# -------------------------------------------------------------------------


class TestNoDuplicateOverflow:
    """compiler_check and IntegerOverflowDetector have separate concerns."""

    def test_compiler_check_does_not_report_overflow(self) -> None:
        """compiler_check handles CVEs; overflow detection is separate."""
        source = """\
# pragma version ^0.3.10
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        # ^0.3.10 is NOT <0.3.10 and NOT <0.3.8, so zero findings
        assert len(results) == 0

    def test_integer_overflow_only_flags_unsafe_ops(self) -> None:
        """IntegerOverflowDetector should ONLY flag unsafe_* operations,
        not old Vyper versions (since Vyper has always had overflow protection)."""
        source = """\
# pragma version ^0.3.10
"""
        results = _run_detector(IntegerOverflowDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# Real source snippets (not fabricated)
# -------------------------------------------------------------------------


class TestRealSourceSnippets:
    """Ensure detectors use actual source lines, not fabricated text."""

    def test_unsafe_math_snippet_shows_actual_line(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def fast(a: uint256) -> uint256:
    return unsafe_add(a, 1)
"""
        results = _run_detector(IntegerOverflowDetector, source)
        assert len(results) == 1
        assert "unsafe_add" in results[0].source_snippet

    def test_compiler_check_snippet_uses_real_pragma(self) -> None:
        source = """\
# @version ^0.3.9
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        assert len(results) >= 1
        assert "# @version ^0.3.9" in results[0].source_snippet

    def test_compiler_check_flags_historical_lock_regression_versions(self) -> None:
        source = """\
# @version 0.2.15
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        assert any("historical lock regression" in r.title.lower() for r in results)

    def test_compiler_check_uses_real_pragma_not_unrelated_comment(self) -> None:
        source = """\
# random note mentioning 0.3.9 but not a pragma
# @version ^0.3.9
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        assert len(results) >= 1
        assert results[0].source_snippet == "# @version ^0.3.9"


# -------------------------------------------------------------------------
# Multi-line function definition parsing
# -------------------------------------------------------------------------


class TestMultiLineFunctionDef:
    """Parser should handle function args that span multiple lines."""

    def test_multiline_def_parsed(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def transfer(
    recipient: address,
    amount: uint256,
    memo: String[100]
) -> bool:
    self.owner = recipient
    return True
"""
        contract = parse_vyper_source(source, "<test>")
        assert len(contract.functions) == 1
        func = contract.functions[0]
        assert func.name == "transfer"
        assert "recipient" in func.args
        assert "amount" in func.args
        assert "memo" in func.args

    def test_multiline_def_body_parsed(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def set_config(
    new_fee: uint256,
    new_admin: address
):
    self.admin = new_admin
"""
        contract = parse_vyper_source(source, "<test>")
        assert len(contract.functions) == 1
        assert "self.admin = new_admin" in contract.functions[0].body_text


# -------------------------------------------------------------------------
# Docstring handling
# -------------------------------------------------------------------------


class TestDocstringHandling:
    """Top-level docstrings should not produce false state variables."""

    def test_toplevel_docstring_skipped(self) -> None:
        source = '''\
# pragma version ^0.4.0

"""
Simple Token Contract
Allows: minting and burning
"""

owner: public(address)
'''
        contract = parse_vyper_source(source, "<test>")
        # "Allows" or "Simple" should NOT appear as state variables
        var_names = [v.name for v in contract.state_variables]
        assert "Simple" not in var_names
        assert "Allows" not in var_names
        assert "owner" in var_names

    def test_singleline_docstring_skipped(self) -> None:
        source = '''\
# pragma version ^0.4.0

"""Simple contract"""

owner: public(address)
'''
        contract = parse_vyper_source(source, "<test>")
        var_names = [v.name for v in contract.state_variables]
        assert "owner" in var_names
        assert len(contract.state_variables) == 1


# -------------------------------------------------------------------------
# Interface / struct / flag block handling
# -------------------------------------------------------------------------


class TestBlockSkipping:
    """Interface, struct, and flag blocks should not pollute parsed functions."""

    def test_interface_block_skipped(self) -> None:
        source = """\
# pragma version ^0.4.0

interface AggregatorV3Interface:
    def decimals() -> uint8: view
    def latestAnswer() -> int256: view

owner: public(address)

@external
def get_price() -> int256:
    return 42
"""
        contract = parse_vyper_source(source, "<test>")
        # Only get_price should be a function, not the interface stubs
        assert len(contract.functions) == 1
        assert contract.functions[0].name == "get_price"
        assert "owner" in [v.name for v in contract.state_variables]

    def test_struct_block_skipped(self) -> None:
        source = """\
# pragma version ^0.4.0

struct Person:
    age: uint256
    name: String[100]

people: HashMap[address, Person]
"""
        contract = parse_vyper_source(source, "<test>")
        # age and name should NOT be state variables
        var_names = [v.name for v in contract.state_variables]
        assert "age" not in var_names
        assert "name" not in var_names
        assert "people" in var_names

    def test_flag_block_skipped(self) -> None:
        source = """\
# pragma version ^0.4.0

flag Color:
    RED
    GREEN
    BLUE

status: Color
"""
        contract = parse_vyper_source(source, "<test>")
        var_names = [v.name for v in contract.state_variables]
        assert "RED" not in var_names
        assert "status" in var_names


# -------------------------------------------------------------------------
# Modern Vyper directives
# -------------------------------------------------------------------------


class TestModernVyperDirectives:
    """Vyper 0.4.x directives should not break parsing."""

    def test_implements_directive(self) -> None:
        source = """\
# pragma version ^0.4.0

from ethereum.ercs import IERC20
implements: IERC20

owner: public(address)
"""
        contract = parse_vyper_source(source, "<test>")
        var_names = [v.name for v in contract.state_variables]
        assert "implements" not in var_names
        assert "owner" in var_names

    def test_exports_directive(self) -> None:
        source = """\
# pragma version ^0.4.0

exports: some_module.__interface__

owner: public(address)
"""
        contract = parse_vyper_source(source, "<test>")
        var_names = [v.name for v in contract.state_variables]
        assert "exports" not in var_names
        assert "owner" in var_names


# -------------------------------------------------------------------------
# SendInLoopDetector
# -------------------------------------------------------------------------


class TestSendInLoop:
    def test_flags_send_in_for_loop(self) -> None:
        source = """\
# pragma version ^0.4.0

users: DynArray[address, 100]
balances: HashMap[address, uint256]

@external
def refund_all():
    for user: address in self.users:
        amount: uint256 = self.balances[user]
        if amount > 0:
            send(user, amount)
            self.balances[user] = 0
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "loop" in results[0].title.lower()

    def test_ignores_send_outside_loop(self) -> None:
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    send(msg.sender, 100)
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 0

    def test_flags_raw_call_in_loop(self) -> None:
        source = """\
# pragma version ^0.4.0

addrs: DynArray[address, 50]

@external
def distribute():
    for a: address in self.addrs:
        raw_call(a, b"", value=100)
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 1

    def test_flags_interface_call_in_loop(self) -> None:
        source = """\
# pragma version ^0.4.0

interface IERC20:
    def transfer(to: address, amount: uint256) -> bool: nonpayable

users: DynArray[address, 50]
token: public(address)

@external
def distribute(amount: uint256):
    for user: address in self.users:
        IERC20(self.token).transfer(user, amount)
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 1


# -------------------------------------------------------------------------
# UncheckedSubtractionDetector
# -------------------------------------------------------------------------


class TestUncheckedSubtraction:
    def test_flags_subtraction_without_check(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def transfer(_to: address, _amount: uint256):
    self.balances[msg.sender] -= _amount
    self.balances[_to] += _amount
"""
        results = _run_detector(UncheckedSubtractionDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "subtraction" in results[0].title.lower()

    def test_ignores_subtraction_with_assert(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def transfer(_to: address, _amount: uint256):
    assert self.balances[msg.sender] >= _amount
    self.balances[msg.sender] -= _amount
    self.balances[_to] += _amount
"""
        results = _run_detector(UncheckedSubtractionDetector, source)
        assert len(results) == 0

    def test_flags_only_unchecked_one(self) -> None:
        source = """\
# pragma version ^0.4.0

counter: uint256
balances: HashMap[address, uint256]

@external
def complex(_amount: uint256):
    assert self.balances[msg.sender] >= _amount
    self.balances[msg.sender] -= _amount
    self.counter -= _amount
"""
        results = _run_detector(UncheckedSubtractionDetector, source)
        # Only self.counter -= _amount is unchecked
        assert len(results) == 1
        assert "counter" in results[0].title

    def test_related_mapping_guard_does_not_hide_total_balance_subtraction(self) -> None:
        source = """\
# pragma version ^0.4.0

total_balance: uint256
user_balance: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    assert self.user_balance[msg.sender] >= amount
    self.total_balance -= amount
"""
        results = _run_detector(UncheckedSubtractionDetector, source)
        assert len(results) == 1
        assert "total_balance" in results[0].title


# -------------------------------------------------------------------------
# CEIViolationDetector
# -------------------------------------------------------------------------


class TestCEIViolation:
    def test_flags_call_before_state_update(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "CEI" in results[0].title

    def test_nonreentrant_cei_violation_is_downgraded(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
@nonreentrant
def withdraw(amount: uint256):
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.LOW

    def test_no_flag_when_effects_before_interaction(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 0

    def test_skips_init(self) -> None:
        source = """\
# pragma version ^0.4.0

owner: address

@deploy
def __init__():
    send(msg.sender, 0)
    self.owner = msg.sender
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 0

    def test_flags_when_later_external_call_precedes_state_write(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def mixed(amount: uint256):
    # Early interaction that is not followed by any write yet.
    raw_call(msg.sender, b"", value=0)
    self.balances[msg.sender] -= amount
    # Later interaction followed by a write should still be flagged.
    send(msg.sender, amount)
    self.balances[msg.sender] = 0
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 2
        assert results[0].severity == Severity.HIGH

    def test_flags_interface_call_before_state_update(self) -> None:
        source = """\
# pragma version ^0.4.0

interface IERC20:
    def transfer(to: address, amount: uint256) -> bool: nonpayable

token: public(address)
balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    IERC20(self.token).transfer(msg.sender, amount)
    self.balances[msg.sender] -= amount
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 1

    def test_flags_call_before_dynarray_append_state_mutation(self) -> None:
        source = """\
# pragma version ^0.4.0

items: DynArray[uint256, 100]

@external
def collect(v: uint256):
    send(msg.sender, 0)
    self.items.append(v)
"""
        results = _run_detector(CEIViolationDetector, source)
        assert len(results) == 1


# -------------------------------------------------------------------------
# HashMap event emission (updated regex)
# -------------------------------------------------------------------------


class TestHashMapEventEmission:
    """Ensure MissingEventEmission catches HashMap writes like self.balances[x] = y."""

    def test_flags_hashmap_write_without_event(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def deposit():
    self.balances[msg.sender] += msg.value
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 1

    def test_ignores_hashmap_write_with_event(self) -> None:
        source = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

event Deposited:
    user: address
    amount: uint256

@external
def deposit():
    self.balances[msg.sender] += msg.value
    log Deposited(msg.sender, msg.value)
"""
        results = _run_detector(MissingEventEmissionDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# UnprotectedStateChange with total_supply
# -------------------------------------------------------------------------


class TestUnprotectedMint:
    """Ensure total_supply is treated as a sensitive variable."""

    def test_flags_unprotected_total_supply_write(self) -> None:
        source = """\
# pragma version ^0.4.0

total_supply: public(uint256)

@external
def mint(amount: uint256):
    self.total_supply += amount
"""
        results = _run_detector(UnprotectedStateChangeDetector, source)
        assert len(results) == 1
        assert "total_supply" in results[0].title

    def test_ignores_protected_mint(self) -> None:
        source = """\
# pragma version ^0.4.0

total_supply: public(uint256)
owner: address

@external
def mint(amount: uint256):
    assert msg.sender == self.owner
    self.total_supply += amount
"""
        results = _run_detector(UnprotectedStateChangeDetector, source)
        assert len(results) == 0


# -------------------------------------------------------------------------
# False-positive suppression tests
# -------------------------------------------------------------------------


class TestFalsePositiveSuppression:
    """Tests verifying that detectors do NOT produce false positives
    on real-world patterns found in audited contracts."""

    # --- UnsafeRawCall: safeTransfer pattern ---

    def test_safe_transfer_pattern_not_flagged(self) -> None:
        """The standard safeTransfer pattern captures raw_call response
        and checks it. This should NOT be flagged."""
        source = """\
# @version ^0.2.8

coins: address[2]

@internal
def _safe_transfer(_coin: address, _to: address, _value: uint256):
    _response: Bytes[32] = raw_call(
        _coin,
        concat(
            method_id("transfer(address,uint256)"),
            convert(_to, bytes32),
            convert(_value, bytes32),
        ),
        max_outsize=32,
    )
    if len(_response) > 0:
        assert convert(_response, bool)
"""
        results = _run_detector(UnsafeRawCallDetector, source)
        assert len(results) == 0

    def test_safe_transfer_from_pattern_not_flagged(self) -> None:
        source = """\
# @version ^0.2.8

@internal
def _safe_transfer_from(_coin: address, _from: address, _to: address, _value: uint256):
    _response: Bytes[32] = raw_call(
        _coin,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(_from, bytes32),
            convert(_to, bytes32),
            convert(_value, bytes32),
        ),
        max_outsize=32,
    )
    if len(_response) > 0:
        assert convert(_response, bool)
"""
        results = _run_detector(UnsafeRawCallDetector, source)
        assert len(results) == 0

    def test_unchecked_raw_call_still_flagged(self) -> None:
        """A raw_call with no return value capture should still be flagged."""
        source = """\
# pragma version ^0.4.0

@external
def execute(target: address, data: Bytes[1024]):
    raw_call(target, data)
"""
        results = _run_detector(UnsafeRawCallDetector, source)
        assert len(results) == 1

    # --- Timestamp: timelock patterns ---

    def test_timelock_deadline_not_flagged(self) -> None:
        """Timelocks with deadline variables should NOT be flagged."""
        source = """\
# @version ^0.2.8

admin_actions_deadline: uint256
ADMIN_ACTIONS_DELAY: constant(uint256) = 259200

@external
def apply_new_fee():
    assert block.timestamp >= self.admin_actions_deadline
    pass
"""
        results = _run_detector(TimestampDependenceDetector, source)
        assert len(results) == 0

    def test_large_constant_timelock_not_flagged(self) -> None:
        """Timestamp comparison with large constants (>= 1 hour) is NOT
        a miner manipulation concern."""
        source = """\
# @version ^0.2.8

kill_deadline: uint256

@external
def kill_me():
    assert block.timestamp < self.kill_deadline
    pass
"""
        results = _run_detector(TimestampDependenceDetector, source)
        assert len(results) == 0

    def test_short_timestamp_still_flagged(self) -> None:
        """Timestamp in a small-window comparison should still be flagged."""
        source = """\
# pragma version ^0.4.0

@external
def check():
    assert block.timestamp > 1000, "Too early"
"""
        results = _run_detector(TimestampDependenceDetector, source)
        assert len(results) == 1

    # --- SendInLoop: small constant loops ---

    def test_small_range_loop_not_flagged(self) -> None:
        """Loop over range(N_COINS) where N_COINS is a known small constant
        is NOT a DoS vector."""
        source = """\
# @version ^0.2.8

N_COINS: constant(int128) = 2
coins: address[2]

@external
def withdraw_admin_fees():
    for i in range(N_COINS):
        raw_call(self.coins[i], b"")
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 0

    def test_numeric_range_small_not_flagged(self) -> None:
        """for i in range(3): raw_call(...) should NOT be flagged."""
        source = """\
# pragma version ^0.4.0

addrs: address[3]

@external
def send_all():
    for i in range(3):
        raw_call(self.addrs[i], b"")
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 0

    def test_dynamic_array_loop_still_flagged(self) -> None:
        """Loop over a DynArray (potentially unbounded) should be flagged."""
        source = """\
# pragma version ^0.4.0

users: DynArray[address, 100]
balances: HashMap[address, uint256]

@external
def refund_all():
    for user: address in self.users:
        amount: uint256 = self.balances[user]
        if amount > 0:
            send(user, amount)
            self.balances[user] = 0
"""
        results = _run_detector(SendInLoopDetector, source)
        assert len(results) == 1

    # --- MissingNonreentrant: access control downgrade ---

    def test_nonreentrant_owner_only_downgraded(self) -> None:
        """Owner-only functions missing @nonreentrant should be MEDIUM, not CRITICAL."""
        source = """\
# @version ^0.2.8

owner: address

@external
def withdraw_admin_fees():
    assert msg.sender == self.owner
    send(msg.sender, 100)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.MEDIUM

    def test_nonreentrant_no_access_control_critical(self) -> None:
        """Public function without access control should remain CRITICAL."""
        source = """\
# pragma version ^0.4.0

@external
def withdraw():
    send(msg.sender, 100)
"""
        results = _run_detector(MissingNonreentrantDetector, source)
        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL

    # --- Compiler check: GHSA-vxmm pattern check ---

    def test_ghsa_vxmm_suppressed_without_dynarray_in_map(self) -> None:
        """GHSA-vxmm should NOT be flagged if contract doesn't use
        DynArray as HashMap values."""
        source = """\
# @version ^0.2.8

balances: HashMap[address, uint256]
coins: address[2]
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        # Should still flag GHSA-5824 (reentrancy guard) but NOT GHSA-vxmm
        advisory_ids = [r.title for r in results]
        assert any("GHSA-5824" in t for t in advisory_ids)
        assert not any("GHSA-vxmm" in t for t in advisory_ids)

    def test_ghsa_vxmm_flagged_with_dynarray_in_map(self) -> None:
        """GHSA-vxmm SHOULD be flagged if contract uses DynArray in HashMap."""
        source = """\
# @version ^0.3.7

user_tokens: HashMap[address, DynArray[uint256, 100]]
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        advisory_ids = [r.title for r in results]
        assert any("GHSA-vxmm" in t for t in advisory_ids)

    def test_ghsa_vxmm_flagged_with_multiline_dynarray_in_map(self) -> None:
        """GHSA-vxmm SHOULD be flagged for multiline HashMap[..., DynArray[...]] too."""
        source = """\
# @version ^0.3.7

user_tokens: HashMap[
    address,
    DynArray[uint256, 100]
]
"""
        contract = parse_vyper_source(source, "<test>")
        results = check_compiler_version(contract)
        advisory_ids = [r.title for r in results]
        assert any("GHSA-vxmm" in t for t in advisory_ids)
