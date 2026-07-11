"""Match scanner findings against independently reviewed audit labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from guardian.models import AnalysisReport, DetectorResult


@dataclass(frozen=True)
class AuditLabel:
    file: str
    detector: str
    verdict: str
    reviewer: str
    reviewed_at: str
    evidence: str
    finding_id: str | None = None
    function: str | None = None


def load_audit_labels(path: Path) -> tuple[AuditLabel, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("$schema") != "vyper-guard-labels/v2":
        raise ValueError("Audit labels require vyper-guard-labels/v2.")
    labels: list[AuditLabel] = []
    for index, item in enumerate(payload.get("labels", [])):
        required = ("file", "detector", "verdict", "reviewer", "reviewed_at", "evidence")
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) and item[key].strip() for key in required
        ):
            raise ValueError(f"Audit label {index} has incomplete provenance.")
        labels.append(
            AuditLabel(
                **{key: item[key] for key in required},
                finding_id=item.get("finding_id"),
                function=item.get("function"),
            )
        )
    return tuple(labels)


def classify_report(report: AnalysisReport, labels: tuple[AuditLabel, ...]) -> dict[str, int]:
    counts = {
        "known_issue_rediscovered": 0,
        "known_false_positive": 0,
        "new_candidate": 0,
    }
    for finding in report.findings:
        matched = next((label for label in labels if _matches(report, finding, label)), None)
        if matched is None:
            classification = "new_candidate"
            finding.audit_classification = {"classification": classification}
        else:
            classification = (
                "known_issue_rediscovered"
                if matched.verdict in {"true_positive", "false_negative"}
                else "known_false_positive"
            )
            finding.audit_classification = {
                "classification": classification,
                "finding_id": matched.finding_id,
                "reviewer": matched.reviewer,
                "reviewed_at": matched.reviewed_at,
                "evidence": matched.evidence,
            }
        counts[classification] += 1
    return counts


def _matches(report: AnalysisReport, finding: DetectorResult, label: AuditLabel) -> bool:
    if Path(report.file_path).name != Path(label.file).name:
        return False
    if finding.detector_name != label.detector:
        return False
    return label.function is None or label.function.lower() in finding.title.lower()
