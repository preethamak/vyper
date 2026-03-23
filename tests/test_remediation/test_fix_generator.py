"""Tests for the FixGenerator — one test per detector handler."""

from __future__ import annotations

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.static import StaticAnalyzer
from guardian.models import (
    Confidence,
    DetectorResult,
    Severity,
    VulnerabilityType,
)
from guardian.remediation.fix_generator import (
    ALLOWED_RISK_TIERS,
    FixGenerator,
    FixResult,
    remediation_planning_contract,
    remediation_policy_contract,
    remediation_tier_rules,
    validate_fix_results_by_tier,
    validate_remediation_policy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _analyze_and_fix(source: str) -> tuple[list[DetectorResult], list[FixResult], str]:
    """Run full analysis + fix pipeline.  Returns (findings, fix_results, patched_source)."""
    analyzer = StaticAnalyzer()
    report = analyzer.analyze_source(source, file_path="test.vy")
    contract = parse_vyper_source(source, "test.vy")
    gen = FixGenerator(source.splitlines(), contract)
    results = gen.generate_all(report.findings)
    patched = gen.patched_source()
    return report.findings, results, patched


def _has_fix_for(results: list[FixResult], detector_name: str) -> FixResult | None:
    """Return the first applied FixResult for a given detector."""
    for r in results:
        if r.finding.detector_name == detector_name and r.applied:
            return r
    return None


# ---------------------------------------------------------------------------
# Test contracts
# ---------------------------------------------------------------------------

REENTRANCY_CONTRACT = """\
# pragma version ^0.3.10

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""

ACCESS_CONTROL_CONTRACT = """\
# pragma version ^0.4.0

owner: public(address)
total_supply: public(uint256)

@external
def mint(amount: uint256):
    self.total_supply += amount
"""

UNCHECKED_SUB_CONTRACT = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)
"""

SEND_IN_LOOP_CONTRACT = """\
# pragma version ^0.4.0

recipients: DynArray[address, 100]
amounts: HashMap[address, uint256]

@external
def distribute():
    for addr: address in self.recipients:
        send(addr, self.amounts[addr])
"""

EVENT_MISSING_CONTRACT = """\
# pragma version ^0.4.0

owner: public(address)
paused: bool

@external
def pause():
    assert msg.sender == self.owner
    self.paused = True
"""

TIMESTAMP_CONTRACT = """\
# pragma version ^0.4.0

last_price: public(uint256)

@external
def check():
    if block.timestamp > 100:
        self.last_price = 42
"""

RAW_CALL_CONTRACT = """\
# pragma version ^0.4.0

@external
def forward(target: address, data: Bytes[1024]):
    raw_call(target, data)
"""

SELFDESTRUCT_CONTRACT = """\
# pragma version ^0.3.10

@external
def destroy():
    selfdestruct(msg.sender)
"""

DELEGATECALL_CONTRACT = """\
# pragma version ^0.4.0

@external
def upgrade(impl: address):
    raw_call(impl, b"", is_delegate_call=True)
"""

OLD_PRAGMA_CONTRACT = """\
# @version ^0.2.15

owner: public(address)

@external
def foo():
    pass
"""

CEI_VIOLATION_CONTRACT = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
"""


# ---------------------------------------------------------------------------
# Tests: Fix for missing @nonreentrant
# ---------------------------------------------------------------------------


class TestFixMissingNonreentrant:
    def test_nonreentrant_added(self) -> None:
        _, results, patched = _analyze_and_fix(REENTRANCY_CONTRACT)
        fix = _has_fix_for(results, "missing_nonreentrant")
        assert fix is not None, (
            f"Expected nonreentrant fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "@nonreentrant" in patched

    def test_diff_present(self) -> None:
        _, results, _ = _analyze_and_fix(REENTRANCY_CONTRACT)
        fix = _has_fix_for(results, "missing_nonreentrant")
        assert fix is not None
        assert fix.diff != ""
        assert "@nonreentrant" in fix.diff


# ---------------------------------------------------------------------------
# Tests: Fix for unsafe raw_call
# ---------------------------------------------------------------------------


class TestFixUnsafeRawCall:
    def test_raw_call_wrapped_in_assert(self) -> None:
        _, results, patched = _analyze_and_fix(RAW_CALL_CONTRACT)
        fix = _has_fix_for(results, "unsafe_raw_call")
        assert fix is not None, (
            f"Expected raw_call fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "assert" in patched.lower() or "assert raw_call" in patched

    def test_diff_shows_assert(self) -> None:
        _, results, _ = _analyze_and_fix(RAW_CALL_CONTRACT)
        fix = _has_fix_for(results, "unsafe_raw_call")
        if fix:
            assert "assert" in fix.diff

    def test_raw_call_fix_is_tier_a(self) -> None:
        _, results, _ = _analyze_and_fix(RAW_CALL_CONTRACT)
        fix = _has_fix_for(results, "unsafe_raw_call")
        assert fix is not None
        assert fix.risk_tier == "A"


# ---------------------------------------------------------------------------
# Tests: Fix for unprotected state change
# ---------------------------------------------------------------------------


class TestFixUnprotectedStateChange:
    def test_access_control_added(self) -> None:
        _, results, patched = _analyze_and_fix(ACCESS_CONTROL_CONTRACT)
        fix = _has_fix_for(results, "unprotected_state_change")
        assert fix is not None, (
            f"Expected access control fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "msg.sender" in patched
        assert "self.owner" in patched

    def test_description_mentions_owner(self) -> None:
        _, results, _ = _analyze_and_fix(ACCESS_CONTROL_CONTRACT)
        fix = _has_fix_for(results, "unprotected_state_change")
        assert fix is not None
        assert "owner" in fix.description.lower() or "access" in fix.description.lower()


# ---------------------------------------------------------------------------
# Tests: Fix for unchecked subtraction
# ---------------------------------------------------------------------------


class TestFixUncheckedSubtraction:
    def test_balance_check_added(self) -> None:
        _, results, patched = _analyze_and_fix(UNCHECKED_SUB_CONTRACT)
        fix = _has_fix_for(results, "unchecked_subtraction")
        assert fix is not None, (
            f"Expected subtraction fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "assert" in patched
        assert ">=" in patched

    def test_diff_shows_guard(self) -> None:
        _, results, _ = _analyze_and_fix(UNCHECKED_SUB_CONTRACT)
        fix = _has_fix_for(results, "unchecked_subtraction")
        assert fix is not None
        assert ">=" in fix.diff


# ---------------------------------------------------------------------------
# Tests: Fix for send in loop
# ---------------------------------------------------------------------------


class TestFixSendInLoop:
    def test_fixme_comment_added(self) -> None:
        _, results, patched = _analyze_and_fix(SEND_IN_LOOP_CONTRACT)
        fix = _has_fix_for(results, "send_in_loop")
        assert fix is not None, (
            f"Expected send_in_loop fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "FIXME" in patched or "pull" in patched.lower()

    def test_description_mentions_pull(self) -> None:
        _, results, _ = _analyze_and_fix(SEND_IN_LOOP_CONTRACT)
        fix = _has_fix_for(results, "send_in_loop")
        assert fix is not None
        assert "pull" in fix.description.lower()


# ---------------------------------------------------------------------------
# Tests: Fix for missing event emission
# ---------------------------------------------------------------------------


class TestFixMissingEvent:
    def test_event_added(self) -> None:
        _, results, patched = _analyze_and_fix(EVENT_MISSING_CONTRACT)
        fix = _has_fix_for(results, "missing_event_emission")
        assert fix is not None, (
            f"Expected event fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "event" in patched.lower() or "log" in patched.lower()


# ---------------------------------------------------------------------------
# Tests: Fix for CEI violation
# ---------------------------------------------------------------------------


class TestFixCEIViolation:
    def test_fixme_added(self) -> None:
        _, results, patched = _analyze_and_fix(CEI_VIOLATION_CONTRACT)
        fix = _has_fix_for(results, "cei_violation")
        assert fix is not None, (
            f"Expected CEI fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "FIXME" in patched or "CEI" in patched

    def test_description_mentions_manual_review(self) -> None:
        _, results, _ = _analyze_and_fix(CEI_VIOLATION_CONTRACT)
        fix = _has_fix_for(results, "cei_violation")
        assert fix is not None
        assert "manual" in fix.description.lower() or "review" in fix.description.lower()

    def test_cei_fix_is_tier_c(self) -> None:
        _, results, _ = _analyze_and_fix(CEI_VIOLATION_CONTRACT)
        fix = _has_fix_for(results, "cei_violation")
        assert fix is not None
        assert fix.risk_tier == "C"


# ---------------------------------------------------------------------------
# Tests: Fix for timestamp dependence
# ---------------------------------------------------------------------------


class TestFixTimestampDependence:
    def test_note_added(self) -> None:
        _, results, patched = _analyze_and_fix(TIMESTAMP_CONTRACT)
        fix = _has_fix_for(results, "timestamp_dependence")
        assert fix is not None, (
            f"Expected timestamp fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "NOTE" in patched or "timestamp" in patched.lower()


class TestRemediationPolicyContract:
    def test_policy_contract_is_well_formed(self) -> None:
        policy = remediation_policy_contract()
        assert policy["policy_version"] == "1.0.0"
        assert set(policy["risk_tiers"]) == set(ALLOWED_RISK_TIERS)
        assert isinstance(policy["detector_tiers"], dict)
        assert isinstance(policy["tier_rules"], dict)
        assert policy["planning_contract"]["eligibility_rule"] == "tier_rank <= max_auto_fix_tier"

    def test_tier_rules_have_expected_shape(self) -> None:
        rules = remediation_tier_rules()
        assert set(rules) == set(ALLOWED_RISK_TIERS)
        assert rules["A"]["requires_manual_review"] is False
        assert rules["C"]["expected_change_kind"] == "advisory_annotation"

    def test_planning_contract_counts_eligible_and_skipped(self) -> None:
        findings, _, _ = _analyze_and_fix(REENTRANCY_CONTRACT)
        contract = remediation_planning_contract(findings, max_auto_fix_tier="B")
        assert contract["max_auto_fix_tier"] == "B"
        assert contract["eligibility_rule"] == "tier_rank <= max_auto_fix_tier"
        assert contract["eligible_total"] + contract["skipped_total"] == len(findings)

    def test_policy_validation_has_no_errors(self) -> None:
        errors = validate_remediation_policy()
        assert errors == []

    def test_fix_results_validation_accepts_real_pipeline_output(self) -> None:
        _, results, _ = _analyze_and_fix(REENTRANCY_CONTRACT)
        errors = validate_fix_results_by_tier(results)
        assert errors == []


# ---------------------------------------------------------------------------
# Tests: Fix for integer overflow / old pragma
# ---------------------------------------------------------------------------


class TestFixCompilerVersion:
    def test_pragma_upgraded(self) -> None:
        _, results, patched = _analyze_and_fix(OLD_PRAGMA_CONTRACT)
        # Could be integer_overflow or compiler_version_check
        has_fix = _has_fix_for(results, "integer_overflow") or _has_fix_for(
            results, "compiler_version_check"
        )
        assert has_fix is not None, (
            f"Expected pragma fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "0.4.0" in patched


# ---------------------------------------------------------------------------
# Tests: Fix for unprotected selfdestruct
# ---------------------------------------------------------------------------


class TestFixSelfdestruct:
    def test_access_control_added(self) -> None:
        _, results, patched = _analyze_and_fix(SELFDESTRUCT_CONTRACT)
        fix = _has_fix_for(results, "unprotected_selfdestruct")
        assert fix is not None, (
            f"Expected selfdestruct fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "msg.sender" in patched or "owner" in patched


# ---------------------------------------------------------------------------
# Tests: Fix for dangerous delegatecall
# ---------------------------------------------------------------------------


class TestFixDelegatecall:
    def test_access_control_added(self) -> None:
        _, results, patched = _analyze_and_fix(DELEGATECALL_CONTRACT)
        fix = _has_fix_for(results, "dangerous_delegatecall")
        assert fix is not None, (
            f"Expected delegatecall fix. Fixes: {[r.finding.detector_name for r in results]}"
        )
        assert "msg.sender" in patched or "owner" in patched


# ---------------------------------------------------------------------------
# Tests: FixGenerator general behaviour
# ---------------------------------------------------------------------------


class TestFixGeneratorGeneral:
    def test_no_findings_returns_empty(self) -> None:
        source = "# pragma version ^0.4.0\n"
        contract = parse_vyper_source(source, "test.vy")
        gen = FixGenerator(source.splitlines(), contract)
        results = gen.generate_all([])
        assert results == []

    def test_unknown_detector_not_applied(self) -> None:
        source = "# pragma version ^0.4.0\n"
        contract = parse_vyper_source(source, "test.vy")
        gen = FixGenerator(source.splitlines(), contract)
        fake = DetectorResult(
            detector_name="nonexistent_detector",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            vulnerability_type=VulnerabilityType.CODE_QUALITY,
            title="Fake",
            description="Fake finding",
        )
        results = gen.generate_all([fake])
        assert len(results) == 1
        assert results[0].applied is False

    def test_patched_source_is_string(self) -> None:
        _, _, patched = _analyze_and_fix(REENTRANCY_CONTRACT)
        assert isinstance(patched, str)
        assert len(patched) > 0

    def test_multiple_findings_all_get_results(self) -> None:
        """Contract with multiple issues should produce a result per finding."""
        source = """\
# @version ^0.2.15

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""
        _, results, _ = _analyze_and_fix(source)
        # Should have at least findings for: old pragma, missing nonreentrant,
        # unsafe raw_call, unchecked subtraction, etc.
        assert len(results) >= 3

    def test_fix_result_has_diff(self) -> None:
        _, results, _ = _analyze_and_fix(REENTRANCY_CONTRACT)
        applied = [r for r in results if r.applied]
        for r in applied:
            assert r.diff != "", f"Fix for {r.finding.detector_name} has empty diff"

    def test_fix_result_has_description(self) -> None:
        _, results, _ = _analyze_and_fix(REENTRANCY_CONTRACT)
        for r in results:
            assert r.description != ""
