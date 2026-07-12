"""Independent-label quality gates for detector maturity promotion."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from guardian.analyzer.audit_labels import AuditLabel, load_audit_labels
from guardian.analyzer.vyper_detector import DETECTOR_MATURITY


@dataclass(frozen=True)
class DetectorLabelQuality:
    detector: str
    maturity: str
    positive: int
    negative: int
    reviewers: int
    eligible: bool
    reasons: tuple[str, ...]


def _independent_units(labels: list[AuditLabel], verdicts: set[str]) -> int:
    units: set[tuple[str, ...]] = set()
    for label in labels:
        if label.verdict not in verdicts:
            continue
        if label.finding_id:
            units.add(("audit_finding", label.finding_id, label.evidence))
        else:
            units.add(("review_case", label.file, label.function or "", label.evidence))
    return len(units)


def evaluate_label_quality(
    labels_file: Path,
    *,
    min_positive: int = 25,
    min_negative: int = 25,
    min_reviewers: int = 2,
) -> dict[str, object]:
    labels = load_audit_labels(labels_file)
    detectors = sorted(set(DETECTOR_MATURITY) | {label.detector for label in labels})
    results: list[DetectorLabelQuality] = []
    for detector in detectors:
        detector_labels = [label for label in labels if label.detector == detector]
        positive = _independent_units(detector_labels, {"true_positive", "false_negative"})
        negative = _independent_units(detector_labels, {"true_negative", "false_positive"})
        reviewers = len({label.reviewer for label in detector_labels})
        reasons: list[str] = []
        if positive < min_positive:
            reasons.append(f"positive labels {positive}/{min_positive}")
        if negative < min_negative:
            reasons.append(f"negative labels {negative}/{min_negative}")
        if reviewers < min_reviewers:
            reasons.append(f"independent reviewers {reviewers}/{min_reviewers}")
        results.append(
            DetectorLabelQuality(
                detector=detector,
                maturity=DETECTOR_MATURITY.get(detector, "unregistered"),
                positive=positive,
                negative=negative,
                reviewers=reviewers,
                eligible=not reasons,
                reasons=tuple(reasons),
            )
        )

    supported_failures = [
        result.detector
        for result in results
        if result.maturity == "supported" and not result.eligible
    ]
    return {
        "schema": "vyper-guard-label-quality/v1",
        "labels_file": str(labels_file),
        "requirements": {
            "min_positive": min_positive,
            "min_negative": min_negative,
            "min_reviewers": min_reviewers,
        },
        "detectors": [asdict(result) for result in results],
        "supported_gate_passed": not supported_failures,
        "supported_failures": supported_failures,
    }
