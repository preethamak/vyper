"""Security score computation.

The scoring logic lives in ``analyzer.static._compute_score`` so it can
run inside the pipeline.  This module re-exports the grade helper and
provides a standalone ``score_report`` convenience function.
"""

from __future__ import annotations

from guardian.analyzer.static import _compute_score
from guardian.models import AnalysisReport, SecurityGrade, Severity


def score_report(report: AnalysisReport) -> tuple[int, SecurityGrade]:
    """Return the (numeric_score, letter_grade) for a report.

    This is a thin wrapper — the report already stores these values, but
    callers may want a standalone function for re-calculation.
    """
    score = _compute_score(report.findings)
    return score, SecurityGrade.from_score(score)


# New helper to deduplicate findings based on detector, severity and location
def deduplicate_findings(report: AnalysisReport) -> None:
    """Remove exact duplicate DetectorResult entries from report.findings.
    Mutates the report in-place.
    """
    seen = set()
    unique = []
    for f in report.findings:
        key = (
            f.detector_name,
            f.severity,
            f.line_number,
            f.end_line_number,
            f.title,
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    report.findings = unique


def severity_breakdown(report: AnalysisReport) -> dict[str, int]:
    """Return a dict mapping severity names to counts."""
    return {
        Severity.CRITICAL.value: report.critical_count,
        Severity.HIGH.value: report.high_count,
        Severity.MEDIUM.value: report.medium_count,
        Severity.LOW.value: report.low_count,
        Severity.INFO.value: report.info_count,
    }
