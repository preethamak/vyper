"""Optional AI-assisted triage post-processor (Phase 4 kickoff).

Guardrails:
- Deterministic output (no remote/model calls)
- Never mutates detector findings or verdicts
- Produces schema-stable triage metadata with provenance
"""

from __future__ import annotations

from guardian.models import AnalysisReport, Severity

TRIAGE_POLICY_VERSION = "1.0.0"
TRIAGE_POLICY_STATUS = "stable"
SCORING_VERSION = "triage_scoring_v1"
_ALLOWED_POLICY_STATUS = {"stable", "experimental", "deprecated"}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_NEXT_STEP_BY_DETECTOR: dict[str, str] = {
    "missing_nonreentrant": "Add @nonreentrant and re-check all external entrypoints.",
    "unsafe_raw_call": "Assert/capture raw_call success and add failure handling.",
    "cei_violation": "Reorder logic to Checks → Effects → Interactions.",
    "dangerous_delegatecall": "Restrict access and validate implementation/target contracts.",
    "unprotected_state_change": "Add strict access-control assertion at function start.",
    "send_in_loop": "Replace push loop with pull-based withdrawal pattern.",
}


def _triage_bucket(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "review_now"
    if severity == Severity.MEDIUM:
        return "review_soon"
    return "review_later"


def _confidence(severity: Severity, evidence_count: int) -> float:
    base = {
        Severity.CRITICAL: 0.92,
        Severity.HIGH: 0.86,
        Severity.MEDIUM: 0.74,
        Severity.LOW: 0.64,
        Severity.INFO: 0.58,
    }[severity]
    bonus = min(0.06, max(0, evidence_count - 1) * 0.01)
    return round(min(0.98, base + bonus), 2)


def _scoring_rationale(severity: Severity, evidence_count: int) -> dict[str, float | int | str]:
    base = {
        Severity.CRITICAL: 0.92,
        Severity.HIGH: 0.86,
        Severity.MEDIUM: 0.74,
        Severity.LOW: 0.64,
        Severity.INFO: 0.58,
    }[severity]
    evidence_bonus = min(0.06, max(0, evidence_count - 1) * 0.01)
    final_score = round(min(0.98, base + evidence_bonus), 2)
    return {
        "version": SCORING_VERSION,
        "severity_base": round(base, 2),
        "evidence_bonus": round(evidence_bonus, 2),
        "evidence_count": evidence_count,
        "final_confidence": final_score,
    }


def _policy_warnings(status: str, announced: bool, sunset_after: str | None) -> list[str]:
    warnings: list[str] = []
    if status == "experimental":
        warnings.append("AI triage policy is experimental and may change in minor releases.")
    if status == "deprecated":
        warnings.append("AI triage policy is deprecated and should be migrated soon.")
    if announced:
        if sunset_after:
            warnings.append(f"AI triage policy deprecation announced; sunset after {sunset_after}.")
        else:
            warnings.append("AI triage policy deprecation announced; sunset date not yet published.")
    return warnings


def triage_policy_contract(
    *,
    status: str = TRIAGE_POLICY_STATUS,
    deprecation_announced: bool = False,
    deprecation_sunset_after: str | None = None,
) -> dict[str, object]:
    """Return the policy contract for AI triage metadata.

    This is emitted in reports so downstream consumers can enforce strict
    compatibility and deprecation checks.
    """
    normalized_status = status if status in _ALLOWED_POLICY_STATUS else TRIAGE_POLICY_STATUS
    warnings = _policy_warnings(
        normalized_status,
        deprecation_announced,
        deprecation_sunset_after,
    )

    return {
        "policy_version": TRIAGE_POLICY_VERSION,
        "status": normalized_status,
        "deterministic": True,
        "can_override_verdict": False,
        "deprecation": {
            "announced": deprecation_announced,
            "sunset_after": deprecation_sunset_after,
        },
        "warnings": warnings,
    }


def _meets_min_severity(severity: Severity, min_severity: Severity) -> bool:
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[min_severity]


def apply_ai_triage(
    report: AnalysisReport,
    *,
    max_items: int | None = None,
    min_severity: Severity = Severity.LOW,
    policy_status: str = TRIAGE_POLICY_STATUS,
    deprecation_announced: bool = False,
    deprecation_sunset_after: str | None = None,
) -> AnalysisReport:
    """Attach optional triage metadata without changing findings."""
    ordered = sorted(
        enumerate(report.findings),
        key=lambda item: (_SEVERITY_RANK[item[1].severity], -(item[1].line_number or 0)),
        reverse=True,
    )

    ordered = [item for item in ordered if _meets_min_severity(item[1].severity, min_severity)]
    if max_items is not None:
        ordered = ordered[: max(1, max_items)]

    triage: list[dict[str, object]] = []
    for rank, (idx, finding) in enumerate(ordered, start=1):
        triage.append(
            {
                "finding_index": idx,
                "priority_rank": rank,
                "detector": finding.detector_name,
                "title": finding.title,
                "severity": finding.severity.value,
                "triage_bucket": _triage_bucket(finding.severity),
                "confidence": _confidence(finding.severity, len(finding.evidence)),
                "scoring_rationale": _scoring_rationale(
                    finding.severity,
                    len(finding.evidence),
                ),
                "suggested_next_step": _NEXT_STEP_BY_DETECTOR.get(
                    finding.detector_name,
                    "Review finding context and apply the provided deterministic fix suggestion.",
                ),
                "evidence_refs": finding.evidence,
                "provenance": {
                    "mode": "heuristic_postprocessor_v1",
                    "policy_version": TRIAGE_POLICY_VERSION,
                    "deterministic": True,
                    "model": None,
                    "can_override_verdict": False,
                },
            }
        )

    report.ai_triage = triage
    report.ai_triage_policy = triage_policy_contract(
        status=policy_status,
        deprecation_announced=deprecation_announced,
        deprecation_sunset_after=deprecation_sunset_after,
    )
    return report
