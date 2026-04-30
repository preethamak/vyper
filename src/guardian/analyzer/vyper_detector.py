"""Vyper-specific vulnerability detectors.

This module defines the ``BaseDetector`` abstract class and ships eleven
concrete detectors that operate on parsed ``ContractInfo`` objects.  Every
detector works purely on the **source-level parse** produced by
``ast_parser``; the Vyper compiler is never required.

Detector catalogue
------------------
 1. MissingNonreentrantDetector
 2. UnsafeRawCallDetector
 3. UncheckedSendDetector
 4. MissingEventEmissionDetector
 5. TimestampDependenceDetector
 6. IntegerOverflowDetector          (version-based)
 7. UnprotectedSelfdestructDetector
 8. DangerousDelegatecallDetector
 9. UnprotectedStateChangeDetector
10. SendInLoopDetector               (DoS via revert)
11. UncheckedSubtractionDetector     (missing balance check)
12. CEIViolationDetector             (call before state update)
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar

from guardian.analyzer.semantic import build_semantic_summary
from guardian.models import (
    Confidence,
    ContractInfo,
    DetectorResult,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)

# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseDetector(ABC):
    """Base class for all vulnerability detectors.

    Subclasses must set the four class-level constants and implement
    ``detect()``.
    """

    NAME: ClassVar[str]
    DESCRIPTION: ClassVar[str]
    SEVERITY: ClassVar[Severity]
    VULNERABILITY_TYPE: ClassVar[VulnerabilityType]

    @abstractmethod
    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        """Run the detector against a parsed contract.

        Args:
            contract: A ``ContractInfo`` produced by ``ast_parser.parse_vyper_source``.

        Returns:
            A (possibly empty) list of findings.
        """

    # Convenience helpers shared by concrete detectors.

    def _make_result(
        self,
        title: str,
        description: str,
        confidence: Confidence,
        *,
        line_number: int | None = None,
        end_line_number: int | None = None,
        source_snippet: str | None = None,
        fix_suggestion: str | None = None,
        severity: Severity | None = None,
        why_flagged: str | None = None,
        evidence: list[str] | None = None,
        why_not_suppressed: str | None = None,
    ) -> DetectorResult:
        ev = list(evidence or [])
        if source_snippet:
            ev.append(source_snippet)
        if line_number is not None:
            ev.append(f"line:{line_number}")

        return DetectorResult(
            detector_name=self.NAME,
            severity=severity or self.SEVERITY,
            confidence=confidence,
            vulnerability_type=self.VULNERABILITY_TYPE,
            title=title,
            description=description,
            line_number=line_number,
            end_line_number=end_line_number,
            source_snippet=source_snippet,
            fix_suggestion=fix_suggestion,
            why_flagged=why_flagged or description,
            evidence=ev,
            why_not_suppressed=why_not_suppressed,
        )


# ---------------------------------------------------------------------------
# Functions to skip in most detectors
# ---------------------------------------------------------------------------

# __init__ is a constructor — only runs once during deployment.  It cannot
# be re-entered, does not need events, and legitimately sets initial state
# without access-control guards.
# __default__ is the fallback — may be too simple for most checks.
_CONSTRUCTOR_NAMES: set[str] = {"__init__"}
_LIFECYCLE_NAMES: set[str] = {"__init__", "__default__"}


def _find_pragma_line(contract: ContractInfo) -> tuple[int, str]:
    """Return (1-based line, source text) of the version pragma."""
    for i, line in enumerate(contract.lines):
        s = line.strip()
        lowered = s.lower()
        if not lowered.startswith("#"):
            continue
        if lowered.startswith("# pragma version") or lowered.startswith("#pragma version"):
            return i + 1, s
        if lowered.startswith("# @pragma") or lowered.startswith("# @version"):
            return i + 1, s
    return 1, ""


# ---------------------------------------------------------------------------
# Source-text helper patterns
# ---------------------------------------------------------------------------

# Matches calls that transfer value or make external calls.
_EXTERNAL_CALL_RE = re.compile(
    r"\b(send|raw_call|create_minimal_proxy_to|create_copy_of|create_from_blueprint)\s*\("
)
# Interface-style external calls: IERC20(token).transfer(...)
_INTERFACE_CALL_RE = re.compile(r"\b[A-Za-z_]\w*\s*\([^()\n]*\)\s*\.\s*[A-Za-z_]\w*\s*\(")
# Matches state mutations (self.xxx = ..., self.xxx[key] = ..., self.xxx[k].field = ...).
# Includes augmented assignments: +=, -=, *=, /=, %=, &=, |=, ^=, <<=, >>=
_STATE_WRITE_RE = re.compile(
    r"\bself\.\w+(?:\[.*?\])*(?:\.\w+)*\s*(?:(?:<<|>>|[+\-*/%&|^])?=)(?!=)"
)
# DynArray / mutable container operations that mutate state.
_STATE_MUTATION_CALL_RE = re.compile(
    r"\bself\.\w+(?:\[.*?\])*(?:\.\w+)*\.(append|pop|remove|clear|extend|insert)\s*\("
)
# Matches event emissions (log EventName(...)).
_LOG_RE = re.compile(r"\blog\s+\w+")
# Access-control assertion pattern (strict owner/admin equality).
_ACCESS_CONTROL_RE = re.compile(
    r"\bassert\b\s+"
    r"(?:msg\.sender\s*==\s*self\.[A-Za-z_]\w*|self\.[A-Za-z_]\w*\s*==\s*msg\.sender)\b"
)
# Timestamp usage in conditional.
_TIMESTAMP_COND_RE = re.compile(
    r"\b(?:assert|if|elif|while)\b[^\n#]*\bblock\.timestamp\b"
    r"|\bblock\.timestamp\b[^\n#]*(?:==|!=|<=|>=|<|>)"
)
_TIMESTAMP_USE_RE = re.compile(r"\bblock\.timestamp\b")
# raw_call with is_delegate_call=True/1 (supports multi-line calls)
_DELEGATECALL_RE = re.compile(
    r"\braw_call\s*\(.*?\bis_delegate_call\s*=\s*(?:True|true|1)\b",
    re.DOTALL,
)
# selfdestruct
_SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\s*\(")
# raw_call wrapped in assert  -or-  success checked
_SAFE_RAW_CALL_RE = re.compile(
    r"assert\s+raw_call\b"
    r"|if\s+not\s+raw_call\b"
    r"|success\s*[:,=].*raw_call"
    r"|raw_call\s*\(.*revert_on_failure\s*=\s*(?:True|true|1)\b"
    r"|raw_call\(.*\)\s*#\s*checked"
)
# Matches send() calls that are already checked inline.
_SAFE_SEND_RE = re.compile(r"assert\s+send\b|if\s+not\s+send\b|if\s+send\b")


def _strip_inline_comment(line: str) -> str:
    """Return line content before an inline comment marker."""
    return line.split("#", 1)[0]


# Strict owner-gate: msg.sender == self.<owner> (NOT balance lookups).
_STRICT_ACL_RE = re.compile(
    r"\bassert\b\s+msg\.sender\s*==\s*self\.[A-Za-z_]\w+"
    r"|\bassert\b\s+self\.[A-Za-z_]\w+\s*==\s*msg\.sender"
)


def _is_external_call_line(line: str) -> bool:
    """Return True if *line* looks like an external interaction."""
    clean = _strip_inline_comment(line).strip()
    if not clean or clean.startswith("log "):
        return False
    return bool(_EXTERNAL_CALL_RE.search(clean) or _INTERFACE_CALL_RE.search(clean))


def _is_state_write_line(line: str) -> bool:
    """Return True if *line* mutates contract state."""
    clean = _strip_inline_comment(line).strip()
    if not clean:
        return False
    return bool(_STATE_WRITE_RE.search(clean) or _STATE_MUTATION_CALL_RE.search(clean))


# ---------------------------------------------------------------------------
# 1. Missing @nonreentrant on external functions with value transfers
# ---------------------------------------------------------------------------


class MissingNonreentrantDetector(BaseDetector):
    NAME = "missing_nonreentrant"
    DESCRIPTION = (
        "Detect @external functions that perform value transfers, external "
        "calls, or state modifications without the @nonreentrant decorator."
    )
    SEVERITY = Severity.CRITICAL
    VULNERABILITY_TYPE = VulnerabilityType.REENTRANCY

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []

        def _contract_has_external_call_surface(exclude_name: str) -> bool:
            for f in contract.functions:
                if f.name == exclude_name:
                    continue
                sem = semantic.functions.get(f.name)
                if sem is not None and sem.external_calls > 0:
                    return True
                if any(_is_external_call_line(line) for line in f.body_lines):
                    return True
            return False

        for func in contract.functions:
            if func.name in _CONSTRUCTOR_NAMES:
                continue
            if not func.is_external:
                continue
            if func.is_view or func.is_pure:
                continue
            if func.is_nonreentrant:
                continue
            # Also skip functions decorated with @deploy (Vyper 0.4.x constructor)
            if "deploy" in func.decorators:
                continue

            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None:
                continue

            # Semantic-first gate: this detector is only relevant when a
            # function performs an external interaction and/or writes state.
            has_external_call_text = any(_is_external_call_line(line) for line in func.body_lines)
            has_state_write_text = any(_is_state_write_line(line) for line in func.body_lines)
            if (
                fn_sem.external_calls == 0
                and not fn_sem.state_writes
                and not has_external_call_text
                and not has_state_write_text
            ):
                continue

            if not has_external_call_text and not has_state_write_text:
                continue

            body = func.body_text
            has_external_call = fn_sem.external_calls > 0 or has_external_call_text
            has_state_write = bool(fn_sem.state_writes) or has_state_write_text

            if has_external_call:
                # CRITICAL: external call without reentrancy guard
                has_access_control = bool(_ACCESS_CONTROL_RE.search(body))
                severity = Severity.MEDIUM if has_access_control else Severity.CRITICAL
                confidence = Confidence.MEDIUM if has_access_control else Confidence.HIGH
                desc_suffix = (
                    " (Note: function has access-control checks, which "
                    "reduces the risk significantly.)"
                    if has_access_control
                    else ""
                )
                results.append(
                    self._make_result(
                        title=f"Missing @nonreentrant on {func.name}()",
                        description=(
                            f"Function ``{func.name}()`` is @external, performs an "
                            f"external call or value transfer, but does not use the "
                            f"@nonreentrant decorator. This exposes the contract to "
                            f"reentrancy attacks." + desc_suffix
                        ),
                        confidence=confidence,
                        severity=severity,
                        line_number=func.start_line,
                        end_line_number=func.end_line,
                        source_snippet=_excerpt(contract, func),
                        fix_suggestion=(
                            f"Add ``@nonreentrant`` before the ``@external`` "
                            f"decorator on ``{func.name}()``."
                        ),
                    )
                )
            elif has_state_write:
                # HIGH: state modification without reentrancy guard
                # Can be exploited via cross-function reentrancy
                # Only skip for strict owner-gated functions (msg.sender == self.owner)
                # NOT for balance lookups like self.balances[msg.sender]
                if _STRICT_ACL_RE.search(body):
                    continue  # owner-only state writes are acceptable
                if not _contract_has_external_call_surface(func.name):
                    continue
                results.append(
                    self._make_result(
                        title=f"Missing @nonreentrant on {func.name}()",
                        description=(
                            f"Function ``{func.name}()`` is @external and modifies "
                            f"state without the @nonreentrant decorator. This can be "
                            f"exploited via cross-function reentrancy if another "
                            f"function in the contract makes external calls."
                        ),
                        confidence=Confidence.MEDIUM,
                        severity=Severity.HIGH,
                        line_number=func.start_line,
                        end_line_number=func.end_line,
                        source_snippet=_excerpt(contract, func),
                        fix_suggestion=(
                            f"Add ``@nonreentrant`` before the ``@external`` "
                            f"decorator on ``{func.name}()``."
                        ),
                    )
                )
        return results


# ---------------------------------------------------------------------------
# 2. Unsafe raw_call without return-value check
# ---------------------------------------------------------------------------


class UnsafeRawCallDetector(BaseDetector):
    NAME = "unsafe_raw_call"
    DESCRIPTION = "Detect uses of raw_call() whose return value is not asserted or checked."
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.EXTERNAL_CALL

    # Matches: _response: Bytes[32] = raw_call(...)  or  _response = raw_call(...)
    _CAPTURED_RE = re.compile(r"(\w+)\s*(?::\s*\w+(?:\[\d+\])?\s*)?=\s*raw_call\s*\(")
    # Matches: if len(_response) > 0: assert convert(_response, bool)
    # or: assert convert(_response, bool)
    _RESPONSE_CHECK_RE = re.compile(
        r"assert\s+convert\s*\(\s*{var}\s*,\s*bool\s*\)"
        r"|if\s+len\s*\(\s*{var}\s*\)\s*>\s*0"
    )

    def _get_full_call(self, body_lines: list[str], call_idx: int) -> str:
        """Join a multi-line raw_call into a single string for analysis."""
        result = body_lines[call_idx].strip()
        # Count parens to find the end of the call
        depth = result.count("(") - result.count(")")
        j = call_idx + 1
        while depth > 0 and j < len(body_lines):
            line = body_lines[j].strip()
            result += " " + line
            depth += line.count("(") - line.count(")")
            j += 1
        return result

    def _is_safe_transfer_pattern(self, body_lines: list[str], call_idx: int) -> bool:
        """Return True if the raw_call at *call_idx* uses the safeTransfer idiom.

        The pattern is:
            _response: Bytes[32] = raw_call(..., max_outsize=32)
            if len(_response) > 0:
                assert convert(_response, bool)
        """
        full_call = self._get_full_call(body_lines, call_idx)

        # Check if the result is captured into a variable
        m = self._CAPTURED_RE.search(full_call)
        if not m:
            return False
        var_name = m.group(1)

        # Find where the raw_call ends in the body lines
        depth = body_lines[call_idx].count("(") - body_lines[call_idx].count(")")
        end_idx = call_idx + 1
        while depth > 0 and end_idx < len(body_lines):
            line = body_lines[end_idx].strip()
            depth += line.count("(") - line.count(")")
            end_idx += 1

        # Look in the next 5 lines after the call ends for the response check
        check_re = re.compile(
            rf"assert\s+convert\s*\(\s*{re.escape(var_name)}\s*,\s*bool\s*\)"
            rf"|if\s+len\s*\(\s*{re.escape(var_name)}\s*\)\s*>\s*0"
        )
        search_end = min(end_idx + 5, len(body_lines))
        return any(check_re.search(body_lines[j]) for j in range(end_idx, search_end))

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []
        for func in contract.functions:
            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None or fn_sem.external_calls == 0:
                continue

            for i, line in enumerate(func.body_lines):
                stripped = _strip_inline_comment(line).strip()
                if "raw_call(" not in stripped:
                    continue
                if _SAFE_RAW_CALL_RE.search(stripped):
                    continue
                # Check if the line is part of an assert on the previous line.
                if i > 0 and "assert" in func.body_lines[i - 1]:
                    continue
                # Check for safeTransfer pattern (result captured + checked)
                if self._is_safe_transfer_pattern(func.body_lines, i):
                    continue
                # For multi-line calls, join and check for captured + max_outsize
                full_call = self._get_full_call(func.body_lines, i)
                if _SAFE_RAW_CALL_RE.search(full_call):
                    continue
                if self._CAPTURED_RE.search(full_call) and "max_outsize" in full_call:
                    continue
                abs_line = func.end_line - len(func.body_lines) + 1 + i
                results.append(
                    self._make_result(
                        title=f"Unchecked raw_call in {func.name}()",
                        description=(
                            f"``raw_call()`` in ``{func.name}()`` does not have its "
                            f"return value asserted. If the external call fails "
                            f"silently, state may become inconsistent."
                        ),
                        confidence=Confidence.MEDIUM,
                        line_number=abs_line,
                        source_snippet=stripped,
                        fix_suggestion=(
                            "Wrap the call: ``assert raw_call(...)``, or capture "
                            "the success flag and assert it."
                        ),
                    )
                )
        return results


# ---------------------------------------------------------------------------
# 3. Unchecked send() return value
# ---------------------------------------------------------------------------


class UncheckedSendDetector(BaseDetector):
    NAME = "unchecked_send"
    DESCRIPTION = "Detect send() calls whose return value is not checked."
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.EXTERNAL_CALL

    _ASSIGN_RE = re.compile(r"(\w+)\s*(?::\s*\w+(?:\[\d+\])?\s*)?=\s*send\s*\(")

    def _get_full_call(self, body_lines: list[str], call_idx: int) -> str:
        """Join a multi-line send() call into a single string for analysis."""
        result = body_lines[call_idx].strip()
        depth = result.count("(") - result.count(")")
        j = call_idx + 1
        while depth > 0 and j < len(body_lines):
            line = body_lines[j].strip()
            result += " " + line
            depth += line.count("(") - line.count(")")
            j += 1
        return result

    def _find_call_end(self, body_lines: list[str], call_idx: int) -> int:
        depth = body_lines[call_idx].count("(") - body_lines[call_idx].count(")")
        end_idx = call_idx + 1
        while depth > 0 and end_idx < len(body_lines):
            line = body_lines[end_idx]
            depth += line.count("(") - line.count(")")
            end_idx += 1
        return end_idx

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        results: list[DetectorResult] = []
        for func in contract.functions:
            for i, line in enumerate(func.body_lines):
                stripped = _strip_inline_comment(line).strip()
                if "send(" not in stripped:
                    continue

                full_call = self._get_full_call(func.body_lines, i)
                if _SAFE_SEND_RE.search(full_call):
                    continue

                if i > 0 and "assert" in func.body_lines[i - 1] and "send(" in stripped:
                    continue

                m = self._ASSIGN_RE.search(full_call)
                if m:
                    var_name = m.group(1)
                    end_idx = self._find_call_end(func.body_lines, i)
                    check_re = re.compile(
                        rf"\bassert\s+{re.escape(var_name)}\b"
                        rf"|\bif\s+not\s+{re.escape(var_name)}\b"
                        rf"|\bif\s+{re.escape(var_name)}\b"
                    )
                    search_end = min(end_idx + 5, len(func.body_lines))
                    if any(check_re.search(func.body_lines[j]) for j in range(end_idx, search_end)):
                        continue

                abs_line = func.end_line - len(func.body_lines) + 1 + i
                results.append(
                    self._make_result(
                        title=f"Unchecked send() in {func.name}()",
                        description=(
                            f"``send()`` in ``{func.name}()`` does not have its "
                            "return value checked. If the transfer fails, the "
                            "contract can continue in an inconsistent state."
                        ),
                        confidence=Confidence.MEDIUM,
                        line_number=abs_line,
                        source_snippet=stripped,
                        fix_suggestion=(
                            "Wrap the call: ``assert send(...)`` or capture the "
                            "boolean result and check it."
                        ),
                    )
                )
        return results


# ---------------------------------------------------------------------------
# 4. Missing event emission after state change
# ---------------------------------------------------------------------------


class MissingEventEmissionDetector(BaseDetector):
    NAME = "missing_event_emission"
    DESCRIPTION = "Detect @external functions that modify state but do not emit an event."
    SEVERITY = Severity.LOW
    VULNERABILITY_TYPE = VulnerabilityType.CODE_QUALITY

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []
        for func in contract.functions:
            if func.name in _LIFECYCLE_NAMES:
                continue
            if not func.is_external:
                continue
            if "deploy" in func.decorators:
                continue
            if func.is_view or func.is_pure:
                continue

            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None:
                continue
            # Semantic-first gate: this detector is only relevant for
            # functions that mutate state and do not emit events.
            if not fn_sem.state_writes or fn_sem.emits_event:
                continue

            body = func.body_text
            has_state_write = any(_is_state_write_line(line) for line in func.body_lines)
            has_event = fn_sem.emits_event or bool(_LOG_RE.search(body))
            if has_state_write and not has_event:
                results.append(
                    self._make_result(
                        title=f"No event emitted in {func.name}()",
                        description=(
                            f"Function ``{func.name}()`` modifies contract state "
                            f"but does not emit an event (``log``).  Events are "
                            f"essential for off-chain indexers and transparency."
                        ),
                        confidence=Confidence.MEDIUM,
                        line_number=func.start_line,
                        source_snippet=_excerpt(contract, func),
                        fix_suggestion=(
                            f"Add a ``log`` statement at the end of ``{func.name}()``."
                        ),
                    )
                )
        return results


# ---------------------------------------------------------------------------
# 5. Timestamp dependence in conditionals
# ---------------------------------------------------------------------------


class TimestampDependenceDetector(BaseDetector):
    NAME = "timestamp_dependence"
    DESCRIPTION = (
        "Detect reliance on block.timestamp in conditional logic, which miners "
        "can manipulate within a small window (~15 seconds)."
    )
    SEVERITY = Severity.LOW
    VULNERABILITY_TYPE = VulnerabilityType.TIMESTAMP_DEPENDENCE

    # Matches large timestamp offset literals directly coupled to
    # block.timestamp arithmetic (e.g., block.timestamp + 86400).
    _TIMESTAMP_OFFSET_RE = re.compile(
        r"block\.timestamp\s*[+\-]\s*(\d+)"
        r"|(\d+)\s*[+\-]\s*block\.timestamp",
        re.IGNORECASE,
    )

    # Common timelock-related variable names
    _TIMELOCK_VAR_RE = re.compile(
        r"\b(deadline|delay|lock_time|timelock|min_ramp_time|ramp_time|"
        r"ADMIN_ACTIONS_DELAY|KILL_DEADLINE_DT|transfer_ownership_deadline|"
        r"admin_actions_deadline|future_|_deadline|_delay)\b",
        re.IGNORECASE,
    )

    def _is_timelock_context(self, line: str) -> bool:
        """Return True if the timestamp usage is in a timelock context.

        A timelock context is where:
        1. The line contains a variable name that suggests a delay/deadline, OR
        2. The line references a large constant (>= 3600 seconds = 1 hour), OR
        3. The comparison involves a state variable that represents a deadline
        """
        # Check for timelock variable names on the same line
        if self._TIMELOCK_VAR_RE.search(line):
            return True

        # Check for large timestamp offsets (>= 1 hour) directly tied to
        # block.timestamp arithmetic. Avoid broad numeric matching that can
        # hide real issues when unrelated constants are present on the line.
        for m in self._TIMESTAMP_OFFSET_RE.finditer(line):
            raw = m.group(1) or m.group(2)
            if raw is None:
                continue
            if int(raw) >= 3600:
                return True

        # Check for self.<something>_deadline or self.<something>_delay patterns
        return bool(
            re.search(
                r"\bself\.\w*(deadline|delay|timelock|lock_time|ramp_time)\w*\b",
                line,
                re.IGNORECASE,
            )
        )

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        results: list[DetectorResult] = []
        for func in contract.functions:
            for i, line in enumerate(func.body_lines):
                code_line = _strip_inline_comment(line)
                if _TIMESTAMP_COND_RE.search(code_line):
                    # Skip if this is a timelock comparison
                    if self._is_timelock_context(code_line):
                        continue
                    abs_line = func.end_line - len(func.body_lines) + 1 + i
                    results.append(
                        self._make_result(
                            title=f"Timestamp dependence in {func.name}()",
                            description=(
                                f"``block.timestamp`` is used in a conditional in "
                                f"``{func.name}()``. Miners can manipulate the "
                                f"timestamp by ~15 seconds. Avoid using it for "
                                f"critical logic such as random-number seeds."
                            ),
                            confidence=Confidence.MEDIUM,
                            line_number=abs_line,
                            source_snippet=code_line.strip(),
                            fix_suggestion=(
                                "If precision matters, use block.number instead "
                                "or accept the ~15 s manipulation window."
                            ),
                        )
                    )
        return results


# ---------------------------------------------------------------------------
# 6. Unsafe arithmetic operations (Vyper 0.4.0+)
# ---------------------------------------------------------------------------

# Matches Vyper 0.4.0+ unsafe_* operations that intentionally bypass
# overflow/underflow protection.
_UNSAFE_MATH_RE = re.compile(r"\b(unsafe_add|unsafe_sub|unsafe_mul|unsafe_div)\s*\(")


class IntegerOverflowDetector(BaseDetector):
    NAME = "integer_overflow"
    DESCRIPTION = (
        "Detect usage of unsafe_add/unsafe_sub/unsafe_mul/unsafe_div "
        "operations that bypass Vyper's built-in overflow protection."
    )
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.ARITHMETIC

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        # NOTE: Vyper has had built-in overflow/underflow protection since
        # v0.1.x — it was one of the language's core design goals. Older
        # versions (<0.4.0) ALWAYS check for overflow.  Starting from
        # Vyper 0.4.0, developers can opt-out via unsafe_add/unsafe_sub/
        # unsafe_mul/unsafe_div.  We flag those explicit opt-outs instead.
        results: list[DetectorResult] = []
        for func in contract.functions:
            for i, line in enumerate(func.body_lines):
                m = _UNSAFE_MATH_RE.search(line)
                if m:
                    abs_line = func.end_line - len(func.body_lines) + 1 + i
                    op = m.group(1)
                    results.append(
                        self._make_result(
                            title=f"Unsafe arithmetic ({op}) in {func.name}()",
                            description=(
                                f"``{op}()`` in ``{func.name}()`` bypasses "
                                f"Vyper's built-in overflow/underflow protection. "
                                f"Ensure the inputs are validated or bounded "
                                f"before this call to prevent silent wrap-around."
                            ),
                            confidence=Confidence.HIGH,
                            line_number=abs_line,
                            source_snippet=line.strip(),
                            fix_suggestion=(
                                f"Replace ``{op}()`` with the safe equivalent "
                                f"(e.g. ``{op.replace('unsafe_', '')}`` operator) "
                                f"or add input validation before the call."
                            ),
                        )
                    )
        return results


# ---------------------------------------------------------------------------
# 7. Unprotected selfdestruct
# ---------------------------------------------------------------------------


class UnprotectedSelfdestructDetector(BaseDetector):
    NAME = "unprotected_selfdestruct"
    DESCRIPTION = "Detect selfdestruct() calls without access-control checks."
    SEVERITY = Severity.CRITICAL
    VULNERABILITY_TYPE = VulnerabilityType.SELF_DESTRUCT

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        results: list[DetectorResult] = []
        for func in contract.functions:
            body = func.body_text
            if not _SELFDESTRUCT_RE.search(body):
                continue
            if _ACCESS_CONTROL_RE.search(body):
                continue
            results.append(
                self._make_result(
                    title=f"Unprotected selfdestruct in {func.name}()",
                    description=(
                        f"``selfdestruct()`` in ``{func.name}()`` can be called "
                        f"by anyone — no ``msg.sender`` check was found. An "
                        f"attacker can destroy the contract."
                    ),
                    confidence=Confidence.HIGH,
                    line_number=func.start_line,
                    source_snippet=_excerpt(contract, func),
                    fix_suggestion=(
                        "Add ``assert msg.sender == self.owner`` (or equivalent) "
                        "before the ``selfdestruct()`` call."
                    ),
                )
            )
        return results


# ---------------------------------------------------------------------------
# 8. Dangerous delegatecall via raw_call
# ---------------------------------------------------------------------------


class DangerousDelegatecallDetector(BaseDetector):
    NAME = "dangerous_delegatecall"
    DESCRIPTION = (
        "Detect raw_call() with is_delegate_call=True, which executes "
        "arbitrary code in the context of this contract."
    )
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.DELEGATE_CALL

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []
        for func in contract.functions:
            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None or not fn_sem.uses_delegatecall:
                continue

            body = func.body_text
            # Check each line and also the joined body (for multi-line calls)
            has_delegatecall = _DELEGATECALL_RE.search(body)
            if not has_delegatecall:
                # Try joining body lines (multi-line raw_call)
                joined = " ".join(line.strip() for line in func.body_lines)
                has_delegatecall = _DELEGATECALL_RE.search(joined)
            if not has_delegatecall:
                continue
            has_access_ctrl = bool(_ACCESS_CONTROL_RE.search(body))
            results.append(
                self._make_result(
                    title=f"Delegatecall in {func.name}()",
                    description=(
                        f"``raw_call()`` with ``is_delegate_call=True`` in "
                        f"``{func.name}()`` executes external code in this "
                        f"contract's storage context. "
                        + (
                            "An access-control check was detected, but "
                            "delegatecall is still inherently dangerous."
                            if has_access_ctrl
                            else "No access-control check was found."
                        )
                    ),
                    confidence=Confidence.HIGH if not has_access_ctrl else Confidence.MEDIUM,
                    severity=Severity.CRITICAL if not has_access_ctrl else Severity.HIGH,
                    line_number=func.start_line,
                    source_snippet=_excerpt(contract, func),
                    fix_suggestion=(
                        "Ensure strict access control and input validation "
                        "around any delegatecall usage."
                    ),
                )
            )
        return results


# ---------------------------------------------------------------------------
# 9. Unprotected state change (missing access control)
# ---------------------------------------------------------------------------


class UnprotectedStateChangeDetector(BaseDetector):
    NAME = "unprotected_state_change"
    DESCRIPTION = (
        "Detect @external functions that write to sensitive state variables "
        "(owner, admin, paused, …) without a msg.sender check."
    )
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.ACCESS_CONTROL

    _SENSITIVE_PATTERNS = re.compile(
        r"\bself\.(owner|admin|governance|paused|is_paused|pending_owner|"
        r"fee_recipient|minter|operator|controller|guardian|"
        r"total_supply|supply|total_shares|total_staked|total_deposited)"
        r"(?:\[.*?\])*\s*[+\-*]?=(?!=)"
    )

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []
        for func in contract.functions:
            if func.name in _CONSTRUCTOR_NAMES:
                continue
            if not func.is_external:
                continue
            if "deploy" in func.decorators:
                continue
            if func.is_view or func.is_pure:
                continue
            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None or not fn_sem.state_writes:
                continue

            body = func.body_text
            m = self._SENSITIVE_PATTERNS.search(body)
            if not m:
                continue
            if _ACCESS_CONTROL_RE.search(body):
                continue
            var_name = m.group(1)
            results.append(
                self._make_result(
                    title=f"Unprotected write to self.{var_name} in {func.name}()",
                    description=(
                        f"``{func.name}()`` writes to ``self.{var_name}`` without "
                        f"checking ``msg.sender``. Anyone can call this function "
                        f"and change a sensitive state variable."
                    ),
                    confidence=Confidence.HIGH,
                    line_number=func.start_line,
                    source_snippet=_excerpt(contract, func),
                    fix_suggestion=(
                        f"Add ``assert msg.sender == self.owner`` (or equivalent) "
                        f"at the top of ``{func.name}()``."
                    ),
                )
            )
        return results


# ---------------------------------------------------------------------------
# 10. Send / raw_call inside a for-loop (DoS via revert)
# ---------------------------------------------------------------------------


class SendInLoopDetector(BaseDetector):
    NAME = "send_in_loop"
    DESCRIPTION = (
        "Detect send() or raw_call() inside a for-loop. If any recipient "
        "reverts, the entire transaction fails (denial-of-service)."
    )
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.DENIAL_OF_SERVICE

    _LOOP_START_RE = re.compile(r"^\s*for\s+")
    # Matches: for i in range(N)  or  for i in range(N_COINS)
    _RANGE_LITERAL_RE = re.compile(r"for\s+\w+\s+in\s+range\s*\(\s*(\w+)\s*\)")
    # Maximum range constant considered "small" / bounded
    _SMALL_LOOP_THRESHOLD = 10

    def _is_small_constant_loop(self, line: str, contract: ContractInfo) -> bool:
        """Return True if the loop iterates over a small known constant."""
        m = self._RANGE_LITERAL_RE.search(line)
        if not m:
            return False
        bound = m.group(1)
        # Direct numeric literal
        try:
            n = int(bound)
            return n <= self._SMALL_LOOP_THRESHOLD
        except ValueError:
            pass
        # Check if it's a constant state variable with a known small value
        for var in contract.state_variables:
            if var.name == bound and var.is_constant:
                # Try to extract the value from the source
                for src_line in contract.lines:
                    if re.match(
                        rf"^\s*{re.escape(bound)}\s*:\s*constant\s*\(.*?\)\s*=\s*(\d+)",
                        src_line,
                    ):
                        val_match = re.search(r"=\s*(\d+)", src_line)
                        if val_match and int(val_match.group(1)) <= self._SMALL_LOOP_THRESHOLD:
                            return True
        # Unknown symbolic bounds are treated as untrusted unless we can
        # resolve a concrete small constant from source.
        return False

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []
        for func in contract.functions:
            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None:
                continue

            has_loop_external_call_text = False
            loop_stack_probe: list[int] = []
            for probe_line in func.body_lines:
                probe_stripped = probe_line.strip()
                if self._LOOP_START_RE.match(probe_line.lstrip() if probe_stripped else ""):
                    loop_stack_probe.append(len(probe_line) - len(probe_line.lstrip()))
                    continue
                while (
                    loop_stack_probe
                    and probe_stripped
                    and (len(probe_line) - len(probe_line.lstrip()) <= loop_stack_probe[-1])
                ):
                    loop_stack_probe.pop()
                if loop_stack_probe and _is_external_call_line(probe_stripped):
                    has_loop_external_call_text = True
                    break

            if not fn_sem.external_calls_in_loop and not has_loop_external_call_text:
                continue

            # Use a stack of (indent, is_small_loop) tuples
            loop_stack: list[tuple[int, bool]] = []
            for i, line in enumerate(func.body_lines):
                stripped = line.strip()
                if self._LOOP_START_RE.match(line.lstrip() if stripped else ""):
                    indent = len(line) - len(line.lstrip())
                    small = self._is_small_constant_loop(stripped, contract)
                    loop_stack.append((indent, small))
                    continue
                # Pop finished loops
                while (
                    loop_stack
                    and stripped
                    and (len(line) - len(line.lstrip()) <= loop_stack[-1][0])
                ):
                    loop_stack.pop()
                if loop_stack and _is_external_call_line(stripped):
                    # If ALL enclosing loops are small-constant, skip
                    if all(is_small for _, is_small in loop_stack):
                        continue
                    abs_line = func.end_line - len(func.body_lines) + 1 + i
                    results.append(
                        self._make_result(
                            title=f"External call inside loop in {func.name}()",
                            description=(
                                f"``{func.name}()`` performs an external call or "
                                f"value transfer (``send`` / ``raw_call``) inside "
                                f"a ``for`` loop. If any recipient reverts, the "
                                f"entire transaction fails — a classic "
                                f"denial-of-service vector. Use the **pull "
                                f"pattern** (let users withdraw individually) "
                                f"instead of pushing funds in a loop."
                            ),
                            confidence=Confidence.HIGH,
                            line_number=abs_line,
                            source_snippet=_excerpt(contract, func),
                            fix_suggestion=(
                                "Replace the push loop with a pull-based "
                                "withdrawal pattern: store amounts owed and "
                                "let each user call ``withdraw()`` individually."
                            ),
                        )
                    )
        return results


# ---------------------------------------------------------------------------
# 11. Unchecked subtraction (missing balance / allowance check)
# ---------------------------------------------------------------------------


class UncheckedSubtractionDetector(BaseDetector):
    NAME = "unchecked_subtraction"
    DESCRIPTION = (
        "Detect self.x -= y where there is no preceding assert self.x >= y, "
        "which can cause an underflow or unexpected revert."
    )
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.INPUT_VALIDATION

    # self.balances[msg.sender] -= amount   or   self.counter -= 1
    _SUB_RE = re.compile(r"\bself\.(\w+)(?:\[.*?\])*\s*-=\s*(\w+)")
    # assert self.balances[msg.sender] >= amount
    _CHECK_TEMPLATE = re.compile(r"\bassert\b.*\bself\.{var}(?:\[.*?\])*\s*>=\s*{rhs}")

    # Matches: amount = share_amount * self.total_assets / self.total_shares
    # => amount is a bounded fraction of self.total_assets (amount <= total_assets)
    _BOUNDED_FRACTION_RE = re.compile(r"\b(\w+)\s*(?:=|:.*=)\s*.*\bself\.(\w+)(?:\[.*?\])*\s*/\s*")

    def _has_indirect_guard(self, body: str, var_name: str, rhs: str, pos: int) -> bool:
        """Return *True* when a preceding assertion on a **related** variable
        logically covers ``self.<var_name> -= <rhs>``.

        One pattern is recognised:
        1. **Bounded-fraction derivation** - ``<rhs>`` was computed as
           ``… * self.<var_name> / …``, so ``<rhs> <= self.<var_name>``.
        """
        preceding = body[:pos]

        # --- Pattern: bounded fraction ---
        # rhs was computed from  ... * self.<var_name>[…] / ...
        for fm in self._BOUNDED_FRACTION_RE.finditer(preceding):
            assigned_var = fm.group(1)
            numerator_state = fm.group(2)
            if assigned_var == rhs and numerator_state == var_name:
                return True

        return False

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        results: list[DetectorResult] = []
        for func in contract.functions:
            body = func.body_text
            for m in self._SUB_RE.finditer(body):
                var_name = m.group(1)
                rhs = m.group(2)
                # Build a regex to see if there's a matching assert above
                check_re = re.compile(
                    rf"\bassert\b.*\bself\.{re.escape(var_name)}"
                    rf"(?:\[.*?\])*\s*>=\s*{re.escape(rhs)}\b"
                )
                # Look only at the body text BEFORE the subtraction
                preceding = body[: m.start()]
                if check_re.search(preceding):
                    continue
                # Check for indirect guards (related mapping assert or
                # bounded-fraction derivation)
                if self._has_indirect_guard(body, var_name, rhs, m.start()):
                    continue
                # Find the line number
                line_in_body = body[: m.start()].count("\n")
                abs_line = func.end_line - len(func.body_lines) + 1 + line_in_body
                results.append(
                    self._make_result(
                        title=f"Unchecked subtraction of self.{var_name} in {func.name}()",
                        description=(
                            f"``{func.name}()`` subtracts from "
                            f"``self.{var_name}`` without a preceding "
                            f"``assert self.{var_name} >= {rhs}`` check. "
                            f"If the caller does not have sufficient balance "
                            f"the transaction will revert with an opaque error "
                            f"(on Vyper >=0.4.0) or silently underflow (on older "
                            f"versions)."
                        ),
                        confidence=Confidence.MEDIUM,
                        line_number=abs_line,
                        source_snippet=_excerpt(contract, func),
                        fix_suggestion=(
                            f"Add ``assert self.{var_name}[…] >= {rhs}`` before the subtraction."
                        ),
                    )
                )
        return results


# ---------------------------------------------------------------------------
# 12. CEI violation — external call before state update
# ---------------------------------------------------------------------------


class CEIViolationDetector(BaseDetector):
    NAME = "cei_violation"
    DESCRIPTION = (
        "Detect functions where an external call (send / raw_call) occurs "
        "before a state update (self.x = …), violating the "
        "Checks-Effects-Interactions pattern."
    )
    SEVERITY = Severity.HIGH
    VULNERABILITY_TYPE = VulnerabilityType.REENTRANCY

    @staticmethod
    def _state_write_after_idx(body_lines: list[str], start_idx: int) -> int | None:
        for i in range(start_idx + 1, len(body_lines)):
            if _is_state_write_line(body_lines[i]):
                return i
        return None

    def _cei_violations(self, body_lines: list[str]) -> list[tuple[int, str]]:
        """Return all external calls that have a later state write."""
        out: list[tuple[int, str]] = []
        for i, line in enumerate(body_lines):
            stripped = _strip_inline_comment(line).strip()
            if not _is_external_call_line(stripped):
                continue
            if self._state_write_after_idx(body_lines, i) is not None:
                out.append((i, stripped))
        return out

    def detect(self, contract: ContractInfo) -> list[DetectorResult]:
        semantic = build_semantic_summary(contract)
        results: list[DetectorResult] = []
        for func in contract.functions:
            if func.name in _CONSTRUCTOR_NAMES:
                continue
            if "deploy" in func.decorators:
                continue
            if func.is_view or func.is_pure:
                continue

            fn_sem = semantic.functions.get(func.name)
            if fn_sem is None:
                continue
            # Semantic-first gate: CEI requires both an external interaction
            # and a state mutation within the same function.
            has_external_call_text = any(_is_external_call_line(line) for line in func.body_lines)
            has_state_write_text = any(_is_state_write_line(line) for line in func.body_lines)
            if (fn_sem.external_calls == 0 or not fn_sem.state_writes) and not (
                has_external_call_text and has_state_write_text
            ):
                continue

            body_lines = func.body_lines
            violations = self._cei_violations(body_lines)
            if not violations:
                continue
            for call_idx, call_line in violations:
                abs_line = func.end_line - len(func.body_lines) + 1 + call_idx
                is_guarded = func.is_nonreentrant
                results.append(
                    self._make_result(
                        title=f"CEI violation in {func.name}()",
                        description=(
                            f"``{func.name}()`` performs an external call "
                            f"(``{call_line.split('(')[0].strip()}``) "
                            f"**before** updating state. An attacker can "
                            f"re-enter the function before the state is "
                            f"updated. Move all state changes above the "
                            f"external call (Checks → Effects → Interactions)."
                            + (
                                " ``@nonreentrant`` is present, so this is "
                                "reported as a lower-severity hygiene issue."
                                if is_guarded
                                else ""
                            )
                        ),
                        confidence=Confidence.MEDIUM if is_guarded else Confidence.HIGH,
                        severity=Severity.LOW if is_guarded else self.SEVERITY,
                        line_number=abs_line,
                        source_snippet=_excerpt(contract, func),
                        fix_suggestion=(
                            "Reorder the function: perform all state updates "
                            "(self.x = …) BEFORE any external calls "
                            "(send / raw_call / interface calls). This is the "
                            "Checks-Effects-Interactions pattern."
                        ),
                    )
                )
        return results


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------

ALL_DETECTORS: list[type[BaseDetector]] = [
    MissingNonreentrantDetector,
    UnsafeRawCallDetector,
    UncheckedSendDetector,
    MissingEventEmissionDetector,
    TimestampDependenceDetector,
    IntegerOverflowDetector,
    UnprotectedSelfdestructDetector,
    DangerousDelegatecallDetector,
    UnprotectedStateChangeDetector,
    SendInLoopDetector,
    UncheckedSubtractionDetector,
    CEIViolationDetector,
]

DETECTOR_MAP: dict[str, type[BaseDetector]] = {cls.NAME: cls for cls in ALL_DETECTORS}


def get_detector(name: str) -> type[BaseDetector]:
    """Look up a detector class by its ``NAME``.

    Raises:
        KeyError: If the name is not registered.
    """
    return DETECTOR_MAP[name]


def list_detectors() -> list[dict[str, str]]:
    """Return metadata for all registered detectors."""
    return [
        {
            "name": cls.NAME,
            "severity": cls.SEVERITY.value,
            "vulnerability_type": cls.VULNERABILITY_TYPE.value,
            "description": cls.DESCRIPTION,
        }
        for cls in ALL_DETECTORS
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _excerpt(contract: ContractInfo, func: FunctionInfo, max_lines: int = 10) -> str:
    """Return the first *max_lines* of a function's definition for display."""
    start = func.start_line - 1  # 0-based
    end = min(start + max_lines, len(contract.lines))
    return "\n".join(contract.lines[start:end])
