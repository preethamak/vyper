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
            )
        return handler(self, finding)

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

    # Find the first decorator line of this function
    top_line = func.start_line  # 1-based, points to first decorator or def
    idx = top_line - 1  # 0-based
    indent = _get_indent(gen._original[idx])
    new_line = f"{indent}@nonreentrant"

    gen._patcher.add_patch(
        Patch(
            start_line=top_line,
            end_line=top_line,
            new_lines=[new_line, gen._original[idx]],
            description=f"Add @nonreentrant before {func.name}()",
        )
    )

    preview = list(gen._original)
    preview.insert(idx, new_line)
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=f"Added ``@nonreentrant`` decorator to ``{func.name}()``.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_unsafe_raw_call(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Wrap raw_call(...) in assert raw_call(...)."""
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

    indent = _get_indent(original_line)
    new_text = f"{indent}assert {stripped}"
    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[new_text],
            description="Wrap raw_call in assert",
        )
    )

    preview = list(gen._original)
    preview[idx] = _get_indent(original_line) + "assert " + stripped
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description="Wrapped ``raw_call()`` in ``assert`` to check return value.",
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
    preview.insert(body_end - 1 + shift + 1, log_line)
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
    """Upgrade pragma to ^0.4.0."""
    if finding.line_number is None:
        return FixResult(finding=finding, description="No line number.", applied=False)

    idx = finding.line_number - 1
    new_pragma = "# pragma version ^0.4.0"
    gen._patcher.add_patch(
        Patch(
            start_line=finding.line_number,
            end_line=finding.line_number,
            new_lines=[new_pragma],
            description="Upgrade pragma version",
        )
    )

    preview = list(gen._original)
    preview[idx] = new_pragma
    diff = gen._make_diff(preview, gen._contract.file_path)

    return FixResult(
        finding=finding,
        description=f"Upgraded pragma to ``{new_pragma}``.",
        applied=True,
        diff=diff,
        patched_lines=preview,
    )


def _fix_compiler_version(gen: FixGenerator, finding: DetectorResult) -> FixResult:
    """Same as integer overflow — upgrade pragma."""
    return _fix_integer_overflow(gen, finding)


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
    if re.search(r"\b(assert|require)\s+.*\bmsg\.sender\b", body):
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


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _get_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _camel_case(snake: str) -> str:
    """Convert snake_case to CamelCase."""
    return "".join(word.capitalize() for word in snake.split("_"))
