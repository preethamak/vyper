"""Concise deterministic triage summaries for auditor-facing reports."""

from __future__ import annotations

from collections import Counter

from guardian.models import AnalysisReport, Confidence, Severity

_SEVERITY_RANK = {severity: index for index, severity in enumerate(Severity)}
_CONFIDENCE_RANK = {confidence: index for index, confidence in enumerate(Confidence)}


def build_triage_summary(report: AnalysisReport, max_candidates: int = 12) -> dict[str, object]:
    groups = Counter(finding.detector_name for finding in report.findings)
    ranked = sorted(
        report.findings,
        key=lambda finding: (
            _SEVERITY_RANK[finding.severity],
            _CONFIDENCE_RANK[finding.confidence],
            finding.detector_name,
            finding.line_number or 0,
        ),
    )
    candidates = []
    seen: set[tuple[str, str]] = set()
    for finding in ranked:
        function = str(finding.semantic_context.get("function", ""))
        key = (finding.detector_name, function)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "detector": finding.detector_name,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "title": finding.title,
                "line": finding.line_number,
                "classification": finding.audit_classification.get(
                    "classification", "new_candidate"
                ),
                "occurrences": groups[finding.detector_name],
            }
        )
        if len(candidates) >= max_candidates:
            break
    return {
        "raw_findings": len(report.findings),
        "grouped_detectors": dict(sorted(groups.items())),
        "candidates_shown": len(candidates),
        "candidates": candidates,
        "omitted_repetitions": max(0, len(report.findings) - len(candidates)),
    }
