"""Automated fix generation engine.

Maps detected vulnerabilities to concrete source-level patches and
produces ``FixResult`` objects containing the before/after source,
a unified diff, and the description of the change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardian.models import (
    ContractInfo,
    DetectorResult,
    FunctionInfo,
)
from guardian.remediation.ast_manipulator import CodePatcher, Patch, generate_diff
from guardian.remediation.validator import FixValidator

REMEDIATION_POLICY_VERSION = "1.0.0"
ALLOWED_RISK_TIERS: tuple[str, ...] = ("A", "B", "C")
_RISK_TIER_ORDER: dict[str, int] = {"A": 1, "B": 2, "C": 3}

# Tier guardrails are intentionally explicit and versioned through
# remediation_policy_contract() so downstream tooling can validate behavior.
_TIER_RULES: dict[str, dict[str, object]] = {
    "A": {
        "description": "Low-risk mechanical edits (safe to auto-apply)",
        "auto_apply_allowed": True,
        "requires_manual_review": False,
        "expected_change_kind": "behavioral_patch",
    },
    "B": {
        "description": "Moderate-risk edits (review recommended)",
        "auto_apply_allowed": True,
        "requires_manual_review": True,
        "expected_change_kind": "behavioral_patch",
    },
    "C": {
        "description": "Advisory/manual-refactor prompts",
        "auto_apply_allowed": True,
        "requires_manual_review": True,
        "expected_change_kind": "advisory_annotation",
    },
}

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class FixResult:
    """Outcome of generating a fix for one finding."""

    finding: DetectorResult
    description: str
    applied: bool = False
    diff: str = ""
    patched_lines: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    risk_tier: str = "B"


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------


class FixGenerator:
    """Generate code fixes for every finding in an ``AnalysisReport``.

    Usage::

        gen = FixGenerator(source_lines, contract_info)
        results = gen.generate_all(report.findings)
        # results is a list[FixResult]
        # gen.patched_source() returns the final fixed source code
    """

    def __init__(self, source_lines: list[str], contract: ContractInfo) -> None:
        self._original = list(source_lines)
        self._contract = contract
        self._patcher = CodePatcher(source_lines)
        self._validator = FixValidator()
        self._results: list[FixResult] = []
        # Track which fixes were applied to build cumulative patched source
        self._current_lines = list(source_lines)

    # -- Public API ----------------------------------------------------------

    def generate_all(self, findings: list[DetectorResult]) -> list[FixResult]:
        """Generate fixes for all findings.  Returns list of ``FixResult``."""
        results: list[FixResult] = []
        for finding in findings:
            result = self._generate_one(finding)
            if result is not None:
                results.append(result)
        self._results = results
        return results

    def patched_source(self) -> str:
        """Return the final source after applying all successful fixes."""
        lines = self._patcher.apply()

        # Validate
        warnings = self._validator.validate(lines)
        if warnings:
            for r in self._results:
                r.warnings.extend(warnings)

        return "\n".join(lines)

    # -- Internal dispatch ---------------------------------------------------

    def _generate_one(self, finding: DetectorResult) -> FixResult | None:
        """Dispatch a single finding to its handler."""
        handler = _HANDLERS.get(finding.detector_name)
        if handler is None:
            return FixResult(
                finding=finding,
                description=f"No auto-fix available for {finding.detector_name}.",
                applied=False,
                risk_tier="C",
            )
        result = handler(self, finding)
        result.risk_tier = _RISK_TIER_BY_DETECTOR.get(finding.detector_name, "B")
        return result

    # -- Handler helpers -----------------------------------------------------

    def _find_function(self, line_number: int | None) -> FunctionInfo | None:
        """Find the function that contains *line_number*."""
        if line_number is None:
            return None
        for func in self._contract.functions:
            if func.start_line <= line_number <= func.end_line:
                return func
        return None

    def _find_first_body_line(self, func: FunctionInfo) -> int:
        """Return 1-based line number of the first body line of *func*.

        Computed from the end of the function so multi-line signatures
        don't cause off-by-one errors.
        """
        if func.body_lines:
            return func.end_line - len(func.body_lines) + 1
        # Fallback: no body lines means empty function
        return func.end_line

    def _make_diff(self, patched: list[str], filename: str = "contract.vy") -> str:
        return generate_diff(self._original, patched, filename)


# ---------------------------------------------------------------------------
# Fix handlers — one per detector
# ---------------------------------------------------------------------------


def _fix_missing_nonreentrant(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add @nonreentrant decorator above the function."""
    func = gen._find_function(finding.line_number)
    if func is None:
        return FixResult(finding=finding, description="Cannot locate function.", applied=False)

    # Prefer placing @nonreentrant immediately after @external to follow
    # common Vyper ordering conventions.
    top_line = func.start_line  # 1-based
    def_line = top_line
    for ln in range(top_line, min(func.end_line, len(gen._original)) + 1):
        if gen._original[ln - 1].strip().startswith("def "):
            def_line = ln
            break

    insert_after = top_line - 1
    for ln in range(top_line, def_line):
        if gen._original[ln - 1].strip().startswith("@external"):
            insert_after = ln
            break

    insert_line = insert_after + 1
    idx = insert_line - 1
    indent = _get_indent(gen._original[max(top_line - 1, 0)])
    new_line = f"{indent}@nonreentrant"

    if insert_after >= top_line:
        patched_lines = [gen._original[insert_line - 1], new_line]
        preview_insert_idx = idx + 1
    else:
        patched_lines = [new_line, gen._original[insert_line - 1]]
        preview_insert_idx = idx

    gen._patcher.add_patch(
        Patch(
            start_line=insert_line,
            end_line=insert_line,
            new_lines=patched_lines,
            description=f"Add @nonreentrant to {func.name}()",
        )
    )

    preview = list(gen._original)
    preview.insert(preview_insert_idx, new_line)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=f"Added ``@nonreentrant`` decorator to ``{func.name}()``.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_unsafe_raw_call(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Rewrite unchecked raw_call into a Vyper-safe response-check pattern."""
    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    if idx >= len(gen._original):
        return FixResult(finding=finding, description="Line out of range.", applied=False)

    original_line = gen._original[idx]
    stripped = original_line.strip()

    # Only patch standalone raw_call lines; multi-line calls are too
    # complex to auto-patch reliably.
    if "raw_call(" not in stripped:
        return FixResult(
            finding=finding,
            description="Multi-line or indirect raw_call — manual fix needed.",
            applied=False,
        )

    # Only patch standalone raw_call statements; assignment/multi-line cases
    # require manual review to avoid changing contract semantics.
    if not stripped.startswith("raw_call("):
        return FixResult(
            finding=finding,
            description="Non-standalone raw_call — manual fix needed.",
            applied=False,
        )

    indent = _get_indent(original_line)
    raw_expr = _ensure_raw_call_max_outsize(stripped, 32)
    response_var = _next_response_var_name(gen._original, base="_response")
    new_lines = [
        f"{indent}{response_var}: Bytes[32] = {raw_expr}",
        f"{indent}if len({response_var}) > 0:",
        f"{indent}    assert convert({response_var}, bool)",
    ]
    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=new_lines,
            description="Rewrite raw_call with response check",
        )
    )

    preview = list(gen._original)
    preview[idx : idx + 1] = new_lines
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=(
            "Rewrote ``raw_call()`` to capture response bytes and assert "
            "``convert(response, bool)`` when data is returned."
        ),
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_missing_event(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add event definition and log statement."""
    func = gen._find_function(finding.line_number)
    if func is None:
        return FixResult(finding=finding, description="Cannot locate function.", applied=False)

    # Determine event name from function name
    event_name = _camel_case(func.name) + "Executed"

    # Check if event already exists
    existing_events = {e.name for e in gen._contract.events}
    if event_name in existing_events:
        event_name = event_name + "_"

    # Add event definition at top of file (after pragma + state vars)
    # Find line after last event or after pragma
    insert_after = 1
    for e in gen._contract.events:
        if e.line_number > insert_after:
            insert_after = e.line_number + len(e.fields) + 1
    if not gen._contract.events:
        # After last state variable or pragma
        for sv in gen._contract.state_variables:
            if sv.line_number > insert_after:
                insert_after = sv.line_number
        if gen._contract.pragma_version:
            for i, line in enumerate(gen._original):
                if gen._contract.pragma_version in line:
                    insert_after = max(insert_after, i + 2)
                    break

    # Add log at end of function body
    body_end = func.end_line  # 1-based
    body_indent = "    "
    if func.body_lines:
        body_indent = _get_indent(func.body_lines[0])
        if not body_indent:
            body_indent = "    "
    log_line = f"{body_indent}log {event_name}(msg.sender)"

    # Register BOTH patches with the patcher so patched_source() includes them.
    # 1. Insert event definition block after insert_after
    event_insert_lines = [f"event {event_name}:", "    caller: indexed(address)", ""]
    # We keep the original line at insert_after and append event lines after it.
    gen._patcher.add_patch(
        Patch(
            start_line=insert_after,
            end_line=insert_after,
            new_lines=[gen._original[insert_after - 1], "", *event_insert_lines],
            description=f"Add event {event_name} definition",
        )
    )
    # 2. Insert log at end of function body
    gen._patcher.add_patch(
        Patch(
            start_line=body_end,
            end_line=body_end,
            new_lines=[gen._original[body_end - 1], log_line],
            description=f"Add log {event_name} at end of {func.name}()",
        )
    )

    preview = list(gen._original)
    # Insert event def
    event_lines = ["", *event_insert_lines]
    for j, el in enumerate(event_lines):
        preview.insert(insert_after + j, el)
    # Insert log (after event insertion shifted lines)
    shift = len(event_lines)
    preview.insert(body_end + shift, log_line)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=f"Added ``event {event_name}`` definition and ``log {event_name}(msg.sender)`` at end of ``{func.name}()``.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_unprotected_state_change(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add access-control assertion at the top of the function body."""
    func = gen._find_function(finding.line_number)
    if func is None:
        return FixResult(finding=finding, description="Cannot locate function.", applied=False)

    first_body = gen._find_first_body_line(func)
    idx = first_body - 1
    indent = _get_indent(gen._original[idx]) if idx < len(gen._original) else "    "
    if not indent:
        indent = "    "

    # Try to find the actual access-control variable name from state vars
    owner_var = None
    for sv in gen._contract.state_variables:
        if sv.name in ("owner", "admin", "governance", "controller", "operator"):
            owner_var = sv.name
            break
    if owner_var is None:
        owner_var = "owner"
    guard = f'{indent}assert msg.sender == self.{owner_var}, "Not {owner_var}"'

    gen._patcher.add_patch(
        Patch(
            start_line=first_body,
            end_line=first_body,
            new_lines=[guard, gen._original[idx]],
            description=f"Add access control to {func.name}()",
        )
    )

    preview = list(gen._original)
    preview.insert(idx, guard)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=f"Added ``assert msg.sender == self.owner`` at top of ``{func.name}()``.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_unprotected_selfdestruct(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add access-control assertion before selfdestruct."""
    return _fix_unprotected_state_change(gen, finding)


def _fix_cei_violation(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Flag the CEI violation with a TODO comment (reordering is too risky to auto-apply)."""
    func = gen._find_function(finding.line_number)
    if func is None:
        return FixResult(finding=finding, description="Cannot locate function.", applied=False)

    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    indent = _get_indent(gen._original[idx])
    comment = f"{indent}# FIXME: CEI violation — move state updates ABOVE this external call"
    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[comment, gen._original[idx]],
            description="Add FIXME comment for CEI violation",
        )
    )

    preview = list(gen._original)
    preview.insert(idx, comment)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=(
            "Added ``FIXME`` comment above the external call. "
            "**Manual review required** — move all ``self.x = …`` state updates "
            "above the ``send()`` / ``raw_call()`` to follow the CEI pattern."
        ),
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_send_in_loop(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add a warning comment above the send-in-loop."""
    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    indent = _get_indent(gen._original[idx])
    comment = f"{indent}# FIXME: DoS risk — replace push loop with pull-based withdrawal"
    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[comment, gen._original[idx]],
            description="Add FIXME comment for send-in-loop",
        )
    )

    preview = list(gen._original)
    preview.insert(idx, comment)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=(
            "Added ``FIXME`` comment. **Manual refactor required** — use a "
            "pull pattern: store amounts owed and let users call ``withdraw()`` individually."
        ),
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_unchecked_subtraction(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add assert self.x >= y before the subtraction line."""
    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    line = gen._original[idx]
    indent = _get_indent(line)

    # Parse the subtraction: self.balances[msg.sender] -= amount
    m = re.search(r"(self\.\w+(?:\[.*?\])*)\s*-=\s*(\w+)", line)
    if not m:
        return FixResult(finding=finding, description="Cannot parse subtraction.", applied=False)

    lhs = m.group(1)
    rhs = m.group(2)
    guard = f'{indent}assert {lhs} >= {rhs}, "Insufficient balance"'

    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[guard, line],
            description="Add balance check before subtraction",
        )
    )

    preview = list(gen._original)
    preview.insert(idx, guard)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=f"Added ``assert {lhs} >= {rhs}`` before the subtraction.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_integer_overflow(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Replace unsafe_* arithmetic helpers with safe infix operators."""
    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    if idx >= len(gen._original):
        return FixResult(finding=finding, description="Line out of range.", applied=False)

    original_line = gen._original[idx]
    replaced_line = _rewrite_unsafe_math_calls(original_line)
    if replaced_line == original_line:
        return FixResult(
            finding=finding,
            description="Could not safely rewrite unsafe arithmetic call.",
            applied=False,
        )

    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[replaced_line],
            description="Replace unsafe_* arithmetic with safe operators",
        )
    )

    preview = list(gen._original)
    preview[idx] = replaced_line
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description="Replaced ``unsafe_*`` arithmetic with safe infix arithmetic.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_compiler_version(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Upgrade/add pragma to a safe compiler pin."""
    pragma_line = 1
    for i, line in enumerate(gen._original, start=1):
        lowered = line.strip().lower()
        if lowered.startswith("# pragma version") or lowered.startswith("#pragma version"):
            pragma_line = i
            break
        if lowered.startswith("# @pragma") or lowered.startswith("# @version"):
            pragma_line = i
            break

    new_pragma = "# pragma version ^0.4.0"
    if 1 <= pragma_line <= len(gen._original):
        gen._patcher.add_patch(
            Patch(
                start_line=pragma_line,
                end_line=pragma_line,
                new_lines=[new_pragma],
                description="Upgrade pragma version",
            )
        )
        preview = list(gen._original)
        preview[pragma_line - 1] = new_pragma
    else:
        gen._patcher.add_patch(
            Patch(
                start_line=1,
                end_line=1,
                new_lines=[new_pragma, gen._original[0]] if gen._original else [new_pragma],
                description="Insert pragma version",
            )
        )
        preview = [new_pragma, *gen._original]

    diff = gen._make_diff(preview, gen._contract.file_path)
    return FixResult(
        finding=finding,
        description=f"Upgraded pragma to ``{new_pragma}``.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_timestamp_dependence(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add a TODO comment — timestamp dependence is often intentional."""
    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    indent = _get_indent(gen._original[idx])
    comment = f"{indent}# NOTE: block.timestamp can be manipulated by ~15s by miners"
    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[comment, gen._original[idx]],
            description="Add NOTE about timestamp manipulation",
        )
    )

    preview = list(gen._original)
    preview.insert(idx, comment)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description="Added ``NOTE`` comment about miner timestamp manipulation.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_dangerous_delegatecall(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Add access-control if missing."""
    func = gen._find_function(finding.line_number)
    if func is None:
        return FixResult(finding=finding, description="Cannot locate function.", applied=False)

    # Check if access control already exists
    body = func.body_text
    if re.search(r"\bassert\s+.*\bmsg\.sender\b", body):
        return FixResult(
            finding=finding,
            description="Access control already present — no auto-fix needed.",
            applied=False,
        )

    return _fix_unprotected_state_change(gen, finding)


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, object] = {
    "missing_nonreentrant": _fix_missing_nonreentrant,
    "unsafe_raw_call": _fix_unsafe_raw_call,
    "missing_event_emission": _fix_missing_event,
    "unprotected_state_change": _fix_unprotected_state_change,
    "unprotected_selfdestruct": _fix_unprotected_selfdestruct,
    "cei_violation": _fix_cei_violation,
    "send_in_loop": _fix_send_in_loop,
    "unchecked_subtraction": _fix_unchecked_subtraction,
    "integer_overflow": _fix_integer_overflow,
    "compiler_version_check": _fix_compiler_version,
    "timestamp_dependence": _fix_timestamp_dependence,
    "dangerous_delegatecall": _fix_dangerous_delegatecall,
}


# Phase 5 prep: remediation risk tiers
# - Tier A: low-risk mechanical edits (safe to auto-apply)
# - Tier B: moderate-risk edits (review recommended)
# - Tier C: advisory/manual refactor prompts
_RISK_TIER_BY_DETECTOR: dict[str, str] = {
    "missing_nonreentrant": "A",
    "unsafe_raw_call": "A",
    "missing_event_emission": "B",
    "unprotected_state_change": "B",
    "unprotected_selfdestruct": "B",
    "unchecked_subtraction": "B",
    "dangerous_delegatecall": "B",
    "integer_overflow": "A",
    "compiler_version_check": "A",
    "cei_violation": "C",
    "send_in_loop": "C",
    "timestamp_dependence": "C",
}


def risk_tier_for_detector(detector_name: str) -> str:
    """Return remediation risk tier for a detector name."""
    return _RISK_TIER_BY_DETECTOR.get(detector_name, "B")


def remediation_tier_rules() -> dict[str, dict[str, object]]:
    """Return tier guardrail metadata keyed by risk tier."""
    return {tier: dict(rule) for tier, rule in _TIER_RULES.items()}


def remediation_planning_contract(
    findings: list[DetectorResult], max_auto_fix_tier: str
) -> dict[str, object]:
    """Return a deterministic planning contract for fix eligibility by tier.

    The contract is intentionally simple so CLI/CI/reporting surfaces can
    reason about expected remediation scope before applying patches.
    """
    cap = max_auto_fix_tier.upper()
    if cap not in _RISK_TIER_ORDER:
        cap = "C"
    max_rank = _RISK_TIER_ORDER[cap]

    eligible_by_tier = {tier: 0 for tier in ALLOWED_RISK_TIERS}
    skipped_by_tier = {tier: 0 for tier in ALLOWED_RISK_TIERS}

    for finding in findings:
        tier = risk_tier_for_detector(finding.detector_name)
        rank = _RISK_TIER_ORDER.get(tier, 99)
        if rank <= max_rank:
            eligible_by_tier[tier] = eligible_by_tier.get(tier, 0) + 1
        else:
            skipped_by_tier[tier] = skipped_by_tier.get(tier, 0) + 1

    return {
        "policy_version": REMEDIATION_POLICY_VERSION,
        "max_auto_fix_tier": cap,
        "eligibility_rule": "tier_rank <= max_auto_fix_tier",
        "eligible_by_tier": eligible_by_tier,
        "skipped_by_tier": skipped_by_tier,
        "eligible_total": sum(eligible_by_tier.values()),
        "skipped_total": sum(skipped_by_tier.values()),
    }


def validate_fix_results_by_tier(results: list[FixResult]) -> list[str]:
    """Return validation errors for generated fixes under tier guardrails."""
    errors: list[str] = []
    for r in results:
        tier = (r.risk_tier or "").upper()
        if tier not in ALLOWED_RISK_TIERS:
            errors.append(f"{r.finding.detector_name}: invalid risk tier {r.risk_tier}")
            continue

        if not r.applied:
            continue

        if tier == "C":
            payload = f"{r.description}\n{r.diff}".lower()
            if not any(
                token in payload for token in ("fixme", "manual", "review", "note", "refactor")
            ):
                errors.append(
                    f"{r.finding.detector_name}: tier C applied fix must remain advisory/manual"
                )

        if tier == "A" and "fixme" in r.diff.lower():
            errors.append(
                f"{r.finding.detector_name}: tier A fix should not add advisory FIXME comments"
            )

    return errors


def remediation_policy_contract() -> dict[str, object]:
    """Return remediation policy contract metadata.

    Exposes versioned risk-tier assignment so tooling/CI can validate
    auto-remediation behavior.
    """
    return {
        "policy_version": REMEDIATION_POLICY_VERSION,
        "risk_tiers": list(ALLOWED_RISK_TIERS),
        "tier_rules": remediation_tier_rules(),
        "detector_tiers": dict(sorted(_RISK_TIER_BY_DETECTOR.items())),
        "planning_contract": {
            "eligibility_rule": "tier_rank <= max_auto_fix_tier",
            "default_max_auto_fix_tier": "C",
        },
    }


def validate_remediation_policy() -> list[str]:
    """Return policy errors (empty list means valid)."""
    errors: list[str] = []
    for detector, tier in _RISK_TIER_BY_DETECTOR.items():
        if tier not in ALLOWED_RISK_TIERS:
            errors.append(f"{detector}: invalid risk tier {tier}")

    for tier in ALLOWED_RISK_TIERS:
        if tier not in _TIER_RULES:
            errors.append(f"{tier}: missing tier rule")

    extra_tier_rules = set(_TIER_RULES) - set(ALLOWED_RISK_TIERS)
    for tier in sorted(extra_tier_rules):
        errors.append(f"{tier}: tier rule defined but not allowed")

    for tier, rule in _TIER_RULES.items():
        if not isinstance(rule.get("auto_apply_allowed"), bool):
            errors.append(f"{tier}: auto_apply_allowed must be bool")
        if not isinstance(rule.get("requires_manual_review"), bool):
            errors.append(f"{tier}: requires_manual_review must be bool")
        expected_kind = rule.get("expected_change_kind")
        if expected_kind not in {"behavioral_patch", "advisory_annotation"}:
            errors.append(f"{tier}: invalid expected_change_kind {expected_kind}")

    missing = set(_HANDLERS) - set(_RISK_TIER_BY_DETECTOR)
    for detector in sorted(missing):
        errors.append(f"{detector}: missing risk tier mapping")

    extra = set(_RISK_TIER_BY_DETECTOR) - set(_HANDLERS)
    for detector in sorted(extra):
        errors.append(f"{detector}: risk tier mapped but no handler")

    return errors


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _get_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _next_response_var_name(lines: list[str], base: str = "_response") -> str:
    """Return a response variable name that does not collide with source text."""
    joined = "\n".join(lines)
    if base not in joined:
        return base
    i = 2
    while f"{base}_{i}" in joined:
        i += 1
    return f"{base}_{i}"


def _ensure_raw_call_max_outsize(raw_expr: str, outsize: int) -> str:
    """Ensure raw_call expression includes ``max_outsize``."""
    if "max_outsize" in raw_expr:
        return raw_expr
    close = raw_expr.rfind(")")
    if close == -1:
        return raw_expr
    before = raw_expr[:close].rstrip()
    suffix = ", " if not before.endswith("(") else ""
    return f"{before}{suffix}max_outsize={outsize}{raw_expr[close:]}"


def _find_matching_paren(text: str, open_idx: int) -> int:
    """Return index of matching ')' for '(' at *open_idx*, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_top_level_args(args: str) -> list[str]:
    """Split argument list by top-level commas (ignoring nested parentheses)."""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in args:
        if ch == "(":
            depth += 1
            cur.append(ch)
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
            continue
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _rewrite_unsafe_math_calls(line: str) -> str:
    """Rewrite unsafe_add/sub/mul/div calls on a line to safe infix operators."""
    op_map = {"add": "+", "sub": "-", "mul": "*", "div": "/"}
    cursor = 0
    result = line

    while True:
        m = re.search(r"\bunsafe_(add|sub|mul|div)\s*\(", result[cursor:])
        if not m:
            break
        start = cursor + m.start()
        open_idx = cursor + m.end() - 1
        close_idx = _find_matching_paren(result, open_idx)
        if close_idx == -1:
            break

        kind = m.group(1)
        args = result[open_idx + 1 : close_idx]
        parts = _split_top_level_args(args)
        if len(parts) != 2:
            cursor = close_idx + 1
            continue

        replacement = f"({parts[0]} {op_map[kind]} {parts[1]})"
        result = f"{result[:start]}{replacement}{result[close_idx + 1 :]}"
        cursor = start + len(replacement)

    return result


def _camel_case(snake: str) -> str:
    """Convert snake_case to CamelCase."""
    return "".join(word.capitalize() for word in snake.split("_"))
