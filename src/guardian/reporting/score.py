"""Security score computation.

The scoring logic lives in ``analyzer.static._compute_score`` so it can
run inside the pipeline.  This module re-exports the grade helper and
provides a standalone ``score_report`` convenience function.
"""

from __future__ import annotations

from guardian.models import AnalysisReport, SecurityGrade, Severity


def score_report(report: AnalysisReport) -> tuple[int, SecurityGrade]:
    """Return the (numeric_score, letter_grade) for a report.

    This is a thin wrapper — the report already stores these values, but
    callers may want a standalone function for re-calculation.
    """
    score = 100
    for f in report.findings:
        score -= f.severity.score_penalty
    score = max(0, score)
    return score, SecurityGrade.from_score(score)


def severity_breakdown(report: AnalysisReport) -> dict[str, int]:
    """Return a dict mapping severity names to counts."""
    return {
        Severity.CRITICAL.value: report.critical_count,
        Severity.HIGH.value: report.high_count,
        Severity.MEDIUM.value: report.medium_count,
        Severity.LOW.value: report.low_count,
        Severity.INFO.value: report.info_count,
    }
