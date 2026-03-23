"""Vyper compiler version vulnerability checker.

Checks the contract's ``# pragma version`` against a database of known
vulnerable Vyper compiler versions and emits findings when a contract
targets a version with documented security issues.
"""

from __future__ import annotations

import re

from guardian.analyzer.semantic import build_semantic_summary
from guardian.models import (
    Confidence,
    ContractInfo,
    DetectorResult,
    Severity,
    VulnerabilityType,
)

# ---------------------------------------------------------------------------
# Known vulnerable Vyper version ranges
# ---------------------------------------------------------------------------

# Each entry: (description, affected_range, severity, advisory_id, pattern_check_fn_name)
# pattern_check_fn_name: if set, a function that checks whether the contract
# actually uses the affected pattern. If the function returns False, the
# advisory is suppressed (the contract is not affected even if the compiler
# version is vulnerable).
_KNOWN_VULNERABILITIES: list[tuple[str, str, Severity, str, str | None]] = [
    (
        "Vyper <0.3.10 — malfunctioning re-entrancy guard due to incorrect "
        "storage slot allocation for @nonreentrant locks.",
        "<0.3.10",
        Severity.HIGH,
        "GHSA-5824-2926-9c37",
        None,  # Always relevant if version matches
    ),
    (
        "Vyper <0.3.8 — potential storage corruption when using dynamic arrays as mapping values.",
        "<0.3.8",
        Severity.HIGH,
        "GHSA-vxmm-c4qg-qc4v",
        "_uses_dynarray_in_mapping",  # Only if contract uses the affected pattern
    ),
]


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Extract a (major, minor, patch) tuple from a pragma string.

    Handles pragmas like ``^0.4.0``, ``>=0.3.10``, ``0.4.1``.
    Returns *None* if the string cannot be parsed.
    """
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _version_lt(version: tuple[int, ...], target_str: str) -> bool:
    """Return True if *version* is strictly less than the version in *target_str*."""
    target = _parse_version(target_str)
    if target is None:
        return False
    return version < target


def _find_pragma_source(contract: ContractInfo) -> tuple[int, str]:
    """Return (1-based line number, actual source text) of the version pragma."""
    if contract.pragma_version:
        for i, line in enumerate(contract.lines):
            s = line.strip()
            if s.startswith("#") and contract.pragma_version in s:
                return i + 1, s
    return 1, ""


# ---------------------------------------------------------------------------
# Pattern-check functions
# ---------------------------------------------------------------------------


def _uses_dynarray_in_mapping(contract: ContractInfo) -> bool:
    """Return True if the contract uses DynArray as a HashMap value type."""
    summary = build_semantic_summary(contract)
    return summary.uses_dynarray_in_mapping


_PATTERN_CHECKS: dict[str, object] = {
    "_uses_dynarray_in_mapping": _uses_dynarray_in_mapping,
}


def check_compiler_version(contract: ContractInfo) -> list[DetectorResult]:
    """Check the contract's pragma version against known vulnerabilities.

    Args:
        contract: A parsed ``ContractInfo``.

    Returns:
        A list of ``DetectorResult`` findings (may be empty).
    """
    results: list[DetectorResult] = []

    if not contract.pragma_version:
        results.append(
            DetectorResult(
                detector_name="compiler_version_check",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                vulnerability_type=VulnerabilityType.COMPILER_BUG,
                title="Missing version pragma",
                description=(
                    "The contract does not declare a ``# pragma version``. "
                    "It is strongly recommended to pin the Vyper compiler version "
                    "to avoid compiling with a vulnerable release."
                ),
                line_number=1,
                fix_suggestion="# pragma version ^0.4.0",
                why_flagged="Missing `# pragma version` makes compiler safety posture ambiguous.",
                evidence=["pragma:missing", "line:1"],
                why_not_suppressed="No pragma pin found, so suppression rules do not apply.",
            )
        )
        return results

    parsed = _parse_version(contract.pragma_version)
    if parsed is None:
        results.append(
            DetectorResult(
                detector_name="compiler_version_check",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                vulnerability_type=VulnerabilityType.COMPILER_BUG,
                title="Unparseable version pragma",
                description=(
                    f"Could not parse the pragma version string: ``{contract.pragma_version}``."
                ),
                line_number=1,
                why_flagged="Pragma string could not be parsed to semantic version.",
                evidence=[f"pragma:{contract.pragma_version}", "line:1"],
                why_not_suppressed="Version parsing failed before advisory suppression could run.",
            )
        )
        return results

    pragma_lineno, pragma_text = _find_pragma_source(contract)

    for desc, affected_range, severity, advisory, pattern_check_name in _KNOWN_VULNERABILITIES:
        # ``affected_range`` is always in the form ``<X.Y.Z``.
        threshold = affected_range.lstrip("<")
        if _version_lt(parsed, threshold):
            # If a pattern check is specified, only flag if the contract
            # actually uses the affected pattern.
            if pattern_check_name is not None:
                check_fn = _PATTERN_CHECKS.get(pattern_check_name)
                if check_fn and not check_fn(contract):
                    continue
            results.append(
                DetectorResult(
                    detector_name="compiler_version_check",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    vulnerability_type=VulnerabilityType.COMPILER_BUG,
                    title=f"Vulnerable compiler version ({advisory})",
                    description=desc,
                    line_number=pragma_lineno,
                    source_snippet=pragma_text or None,
                    fix_suggestion="# pragma version ^0.4.0",
                    why_flagged=(
                        f"Pragma version `{contract.pragma_version}` falls in advisory range "
                        f"`{affected_range}` for {advisory}."
                    ),
                    evidence=[
                        f"advisory:{advisory}",
                        f"affected_range:{affected_range}",
                        f"pragma:{contract.pragma_version}",
                        f"line:{pragma_lineno}",
                    ],
                    why_not_suppressed=(
                        "Pattern gate satisfied."
                        if pattern_check_name is not None
                        else "Advisory applies unconditionally for matching versions."
                    ),
                )
            )

    return results
