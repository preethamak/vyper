"""JSON report exporter.

Produces machine-readable JSON reports suitable for CI pipelines,
SARIF-adjacent tooling, and downstream integrations.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

from guardian import __version__
from guardian.models import AnalysisReport


def _fingerprint(finding_dict: dict[str, Any]) -> str:
    """Compute a stable fingerprint for a finding (for dedup / baseline diffing)."""
    key = f"{finding_dict['detector']}:{finding_dict['title']}:{finding_dict['line_number']}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


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
        fd["fingerprint"] = _fingerprint(fd)
        findings.append(fd)

    return {
        "$schema": "vyper-guard-report/v1",
        "tool": {
            "name": "vyper-guard",
            "version": __version__,
            "url": "https://github.com/preethamak/vyper",
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


def export_json(report: AnalysisReport, output_path: str | Path | None = None) -> str:
    """Serialise the report as a JSON string.

    If *output_path* is given the JSON is also written to that file.

    Returns:
        The JSON string.
    """
    data = report_to_dict(report)
    text = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    return text
