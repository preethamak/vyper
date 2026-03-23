"""Detector confidence calibration policy.

Keeps confidence scoring simple, deterministic, and explainable.
"""

from __future__ import annotations

from guardian.models import Confidence, DetectorResult, Severity

_CONF_ORDER: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}

_POLICY_BOUNDS: dict[str, tuple[Confidence, Confidence]] = {
    "unsafe_raw_call": (Confidence.MEDIUM, Confidence.HIGH),
    "missing_nonreentrant": (Confidence.MEDIUM, Confidence.HIGH),
    "dangerous_delegatecall": (Confidence.MEDIUM, Confidence.HIGH),
    "unprotected_selfdestruct": (Confidence.MEDIUM, Confidence.HIGH),
    "unprotected_state_change": (Confidence.MEDIUM, Confidence.HIGH),
    "send_in_loop": (Confidence.MEDIUM, Confidence.HIGH),
    "cei_violation": (Confidence.MEDIUM, Confidence.HIGH),
}


def _clamp(value: Confidence, low: Confidence, high: Confidence) -> Confidence:
    idx = _CONF_ORDER[value]
    if idx < _CONF_ORDER[low]:
        return low
    if idx > _CONF_ORDER[high]:
        return high
    return value


def _base_from_evidence(finding: DetectorResult) -> Confidence:
    score = 0
    if finding.why_flagged:
        score += 1
    if finding.evidence:
        score += 1
    if len(finding.evidence) >= 2:
        score += 1
    if finding.source_snippet:
        score += 1
    if finding.line_number is not None:
        score += 1

    if score >= 4:
        return Confidence.HIGH
    if score >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def calibrate_confidence(findings: list[DetectorResult]) -> list[DetectorResult]:
    """Apply deterministic confidence calibration to findings."""
    for finding in findings:
        # Compiler checker: version advisories are high-confidence; missing/unparseable pragma is low.
        if finding.detector_name == "compiler_version_check":
            if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
                finding.confidence = Confidence.HIGH
            else:
                finding.confidence = Confidence.LOW
            continue

        base = _base_from_evidence(finding)
        low, high = _POLICY_BOUNDS.get(
            finding.detector_name,
            (Confidence.LOW, Confidence.HIGH),
        )
        finding.confidence = _clamp(base, low, high)

    return findings
