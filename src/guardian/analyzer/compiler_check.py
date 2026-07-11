"""Vyper compiler version vulnerability checker.

Checks the contract's ``# pragma version`` against a database of known
vulnerable Vyper compiler versions and emits findings when a contract
targets a version with documented security issues.
"""

from __future__ import annotations

import re

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
        "Vyper <=0.3.7 can underallocate storage for extremely large arrays.",
        "<0.3.8",
        Severity.HIGH,
        "GHSA-6m97-7527-mh74",
        "_uses_extremely_large_array",
    ),
    (
        "Vyper <0.3.8 incorrectly orders omitted defaults in calls to internal "
        "functions with more than one default argument.",
        "<0.3.8",
        Severity.HIGH,
        "GHSA-ph9x-4vc9-m39g",
        "_uses_multiple_internal_defaults",
    ),
]

# Range-based advisories where only specific windows are affected.
# Each entry: (description, min_version_inclusive, max_version_inclusive, severity, advisory)
_RANGED_VULNERABILITIES: list[
    tuple[str, tuple[int, int, int], tuple[int, int, int], Severity, str, str | None]
] = [
    (
        "Vyper 0.2.13-0.2.14 can allocate @nonreentrant locks over contract storage.",
        (0, 2, 13),
        (0, 2, 14),
        Severity.HIGH,
        "GHSA-7f92-rr6w-cq64",
        "_uses_nonreentrant",
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


def _version_between_inclusive(
    version: tuple[int, ...],
    lower: tuple[int, int, int],
    upper: tuple[int, int, int],
) -> bool:
    """Return True when *version* is within [lower, upper] inclusive."""
    v = tuple(version[:3])
    return lower <= v <= upper


def _find_pragma_source(contract: ContractInfo) -> tuple[int, str]:
    """Return (1-based line number, actual source text) of the version pragma."""
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
# Pattern-check functions
# ---------------------------------------------------------------------------


def _uses_nonreentrant(contract: ContractInfo) -> bool:
    return any(func.is_nonreentrant for func in contract.functions)


def _uses_extremely_large_array(contract: ContractInfo) -> bool:
    return any(
        int(match.group(1)) >= 46
        for match in re.finditer(r"\[\s*2\s*\*\*\s*(\d+)\s*(?:\+\s*1)?\s*\]", contract.source_code)
    )


def _uses_multiple_internal_defaults(contract: ContractInfo) -> bool:
    return any(func.is_internal and func.args.count("=") > 1 for func in contract.functions)


_PATTERN_CHECKS: dict[str, object] = {
    "_uses_nonreentrant": _uses_nonreentrant,
    "_uses_extremely_large_array": _uses_extremely_large_array,
    "_uses_multiple_internal_defaults": _uses_multiple_internal_defaults,
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

    for desc, vmin, vmax, severity, advisory, pattern_check_name in _RANGED_VULNERABILITIES:
        if not _version_between_inclusive(parsed, vmin, vmax):
            continue
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
                    f"Pragma version `{contract.pragma_version}` falls in affected range "
                    f"`{vmin[0]}.{vmin[1]}.{vmin[2]}..{vmax[0]}.{vmax[1]}.{vmax[2]}` "
                    f"for {advisory}."
                ),
                evidence=[
                    f"advisory:{advisory}",
                    f"affected_range:{vmin[0]}.{vmin[1]}.{vmin[2]}..{vmax[0]}.{vmax[1]}.{vmax[2]}",
                    f"pragma:{contract.pragma_version}",
                    f"line:{pragma_lineno}",
                ],
                why_not_suppressed=(
                    "Advisory range and feature gate match."
                    if pattern_check_name
                    else "Advisory range match."
                ),
            )
        )

    return results


def collapse_compiler_findings(findings: list[DetectorResult]) -> list[DetectorResult]:
    """Collapse applicable compiler advisories into one auditable exposure summary."""
    if len(findings) <= 1:
        return findings
    severity_rank = {severity: index for index, severity in enumerate(reversed(list(Severity)))}
    highest = max(findings, key=lambda item: severity_rank[item.severity])
    advisories = sorted(
        {
            evidence.split(":", 1)[1]
            for finding in findings
            for evidence in finding.evidence
            if evidence.startswith("advisory:")
        }
    )
    pragma = next(
        (
            evidence.split(":", 1)[1]
            for finding in findings
            for evidence in finding.evidence
            if evidence.startswith("pragma:")
        ),
        "unknown",
    )
    triggers: list[str] = []
    if any("reentr" in finding.description.lower() for finding in findings):
        triggers.append("nonreentrant")
    if any("dynamic arrays as mapping" in finding.description.lower() for finding in findings):
        triggers.append("dynarray_mapping")
    evidence = [f"pragma:{pragma}"]
    evidence.extend(f"advisory:{advisory}" for advisory in advisories)
    evidence.extend(f"trigger:{trigger}" for trigger in sorted(set(triggers)))
    evidence.append(f"applicable_advisories:{len(findings)}")
    return [
        DetectorResult(
            detector_name="compiler_version_check",
            severity=highest.severity,
            confidence=min((item.confidence for item in findings), key=list(Confidence).index),
            vulnerability_type=VulnerabilityType.COMPILER_BUG,
            title=f"Compiler exposure summary ({len(findings)} applicable advisories)",
            description=(
                f"The declared Vyper version `{pragma}` matches {len(findings)} applicable "
                f"compiler advisories: {', '.join(advisories) or 'unversioned advisory'}. "
                "Applicability is filtered by detected language features where supported."
            ),
            line_number=highest.line_number,
            source_snippet=highest.source_snippet,
            fix_suggestion=(
                "Reproduce the deployed bytecode with its original compiler, review each "
                "applicable advisory, and migrate through a separately audited deployment."
            ),
            why_flagged="The pragma and detected language features match known advisories.",
            evidence=evidence,
            why_not_suppressed=("At least one advisory remained applicable after feature checks."),
        )
    ]
