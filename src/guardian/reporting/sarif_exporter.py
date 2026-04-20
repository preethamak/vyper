"""SARIF report exporter.

Produces SARIF 2.1.0 output suitable for code-scanning ingestion in CI/CD.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from guardian import __version__
from guardian.models import AnalysisReport, Severity
from guardian.reporting.json_exporter import _prepare_output_path

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _severity_to_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _result_fingerprint(rule_id: str, title: str, description: str, line_number: int | None) -> str:
    key = "|".join(
        [
            rule_id.strip().lower(),
            title.strip().lower(),
            description.strip().lower(),
            str(line_number or ""),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def report_to_sarif_dict(report: AnalysisReport) -> dict[str, Any]:
    """Convert an ``AnalysisReport`` to SARIF 2.1.0."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        rule_id = finding.detector_name
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {
                    "text": finding.fix_suggestion
                    or "Review the finding and remediate according to secure Vyper practices."
                },
                "properties": {
                    "tags": [
                        f"severity:{finding.severity.value}",
                        f"confidence:{finding.confidence.value}",
                        f"vulnerability_type:{finding.vulnerability_type.value}",
                    ]
                },
            }

        sarif_result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_to_level(finding.severity),
            "message": {
                "text": f"{finding.title}: {finding.description}",
            },
            "partialFingerprints": {
                "primaryLocationLineHash": _result_fingerprint(
                    rule_id,
                    finding.title,
                    finding.description,
                    finding.line_number,
                )
            },
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "vulnerability_type": finding.vulnerability_type.value,
            },
        }

        if finding.line_number is not None:
            region: dict[str, Any] = {"startLine": finding.line_number}
            if finding.end_line_number is not None:
                region["endLine"] = finding.end_line_number
            sarif_result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.file_path},
                        "region": region,
                    }
                }
            ]

        results.append(sarif_result)

    payload: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vyper-guard",
                        "version": __version__,
                        "informationUri": "https://deepwiki.com/preethamak/vyper",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "file_path": report.file_path,
                    "security_score": report.security_score,
                    "grade": report.grade.value,
                    "summary": {
                        "total": len(report.findings),
                        "critical": report.critical_count,
                        "high": report.high_count,
                        "medium": report.medium_count,
                        "low": report.low_count,
                        "info": report.info_count,
                    },
                },
            }
        ],
    }

    return payload


def export_sarif(report: AnalysisReport, output_path: str | Path | None = None) -> str:
    """Serialise the report as SARIF text.

    If *output_path* is given, the SARIF is also written to that file.
    """
    data = report_to_sarif_dict(report)
    text = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        path = _prepare_output_path(output_path)
        path.write_text(text, encoding="utf-8")

    return text
