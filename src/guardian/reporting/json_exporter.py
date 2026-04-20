"""JSON report exporter.

Produces machine-readable JSON reports suitable for CI pipelines,
SARIF-adjacent tooling, and downstream integrations.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from pathlib import Path
from typing import Any

from guardian import __version__
from guardian.models import AnalysisReport


def _fingerprint(finding_dict: dict[str, Any]) -> str:
    """Compute a stable fingerprint for a finding (for dedup / baseline diffing)."""

    def _norm(value: object) -> str:
        text = str(value or "").strip().lower()
        return re.sub(r"\s+", " ", text)

    key = "|".join(
        [
            _norm(finding_dict.get("detector")),
            _norm(finding_dict.get("vulnerability_type")),
            _norm(finding_dict.get("severity")),
            _norm(finding_dict.get("title")),
            _norm(finding_dict.get("description")),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _prepare_output_path(output_path: str | Path) -> Path:
    path = Path(output_path).expanduser()
    if path.exists():
        if path.is_symlink():
            raise ValueError(f"Refusing to write through symlink: {path}")
        if not path.is_file():
            raise ValueError(f"Refusing to write to non-file path: {path}")
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise ValueError(f"Refusing to write into symlink directory: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    return path


def report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    """Convert an ``AnalysisReport`` to a plain dict ready for JSON serialisation."""
    findings = []
    for f in report.findings:
        fd: dict[str, Any] = {
            "detector": f.detector_name,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "vulnerability_type": f.vulnerability_type.value,
            "title": f.title,
            "description": f.description,
            "line_number": f.line_number,
            "end_line_number": f.end_line_number,
            "source_snippet": f.source_snippet,
            "fix_suggestion": f.fix_suggestion,
        }
        if f.why_flagged:
            fd["why_flagged"] = f.why_flagged
        if f.evidence:
            fd["evidence"] = f.evidence
        if f.why_not_suppressed:
            fd["why_not_suppressed"] = f.why_not_suppressed
        if f.semantic_context:
            fd["semantic_context"] = f.semantic_context
        fd["fingerprint"] = _fingerprint(fd)
        findings.append(fd)

    payload = {
        "$schema": "vyper-guard-report/v1",
        "tool": {
            "name": "vyper-guard",
            "version": __version__,
            "url": "https://deepwiki.com/preethamak/vyper",
        },
        "environment": {
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        },
        "file_path": report.file_path,
        "timestamp": report.timestamp.isoformat(),
        "vyper_version": report.vyper_version,
        "security_score": report.security_score,
        "grade": report.grade.value,
        "grade_label": report.grade.label,
        "summary": {
            "total": len(report.findings),
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "info": report.info_count,
        },
        "findings": findings,
        "detectors_run": report.detectors_run,
    }

    if report.failed_detectors:
        payload["failed_detectors"] = report.failed_detectors
    if report.detector_errors:
        payload["detector_errors"] = report.detector_errors
    if report.analysis_context:
        payload["analysis_context"] = report.analysis_context

    if report.ai_triage:
        payload["ai_triage"] = report.ai_triage
    if report.ai_triage_policy:
        payload["ai_triage_policy"] = report.ai_triage_policy

    return payload


def export_json(report: AnalysisReport, output_path: str | Path | None = None) -> str:
    """Serialise the report as a JSON string.

    If *output_path* is given the JSON is also written to that file.

    Returns:
        The JSON string.
    """
    data = report_to_dict(report)
    text = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        path = _prepare_output_path(output_path)
        path.write_text(text, encoding="utf-8")

    return text
