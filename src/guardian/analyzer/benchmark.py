"""Lightweight benchmark runner for detector quality tracking."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guardian.analyzer.static import StaticAnalyzer
from guardian.models import Severity

_DETECTOR_KEYWORDS: dict[str, tuple[str, ...]] = {
    "missing_nonreentrant": ("reentrancy", "classic_reentrancy"),
    "unsafe_raw_call": ("unsafe_raw_call", "raw_call"),
    "missing_event_emission": ("missing_events", "event"),
    "timestamp_dependence": ("timestamp", "timestamp_dependence", "timestamp_manipulation"),
    "integer_overflow": ("integer_overflow", "overflow", "underflow", "unchecked_subtraction"),
    "unprotected_selfdestruct": ("selfdestruct", "unprotected_selfdestruct"),
    "dangerous_delegatecall": ("delegatecall", "dangerous_delegatecall"),
    "unprotected_state_change": ("unprotected_state", "state_change", "unprotected_state_change"),
    "send_in_loop": ("send_in_loop",),
    "unchecked_subtraction": ("unchecked_subtraction", "underflow"),
    "cei_violation": ("cei", "cei_violation"),
    "compiler_version_check": ("old_compiler", "compiler", "pragma"),
}


@dataclass(frozen=True)
class DetectorBenchmark:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    support: int


@dataclass(frozen=True)
class BenchmarkResult:
    files_total: int
    vulnerable_expected: int
    safe_expected: int
    predicted_vulnerable: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    by_detector: dict[str, DetectorBenchmark]


def _expected_vulnerable(path: Path) -> bool:
    name = path.name.lower()
    if "safe" in name:
        return False
    return ".fixed." not in name


def _expected_detectors(path: Path) -> set[str]:
    name = path.name.lower()
    if not _expected_vulnerable(path):
        return set()

    expected: set[str] = set()
    for detector, keywords in _DETECTOR_KEYWORDS.items():
        if any(keyword in name for keyword in keywords):
            expected.add(detector)
    return expected


def _load_labels(labels_file: Path) -> dict[str, tuple[bool, set[str]]]:
    """Load optional external labels file.

    Supported minimal schema:
    {
      "files": {
        "contract.vy": {"vulnerable": true, "detectors": ["unsafe_raw_call"]}
      }
    }
    """
    raw: dict[str, Any] = json.loads(labels_file.read_text(encoding="utf-8"))
    files = raw.get("files", {})
    if not isinstance(files, dict):
        return {}

    labels: dict[str, tuple[bool, set[str]]] = {}
    for filename, spec in files.items():
        if not isinstance(filename, str) or not isinstance(spec, dict):
            continue
        vulnerable = bool(spec.get("vulnerable", True))
        detectors_raw = spec.get("detectors", [])
        if isinstance(detectors_raw, list):
            detectors = {d for d in detectors_raw if isinstance(d, str)}
        else:
            detectors = set()
        labels[filename] = (vulnerable, detectors)
    return labels


def run_corpus_benchmark(corpus_dir: Path, labels_file: Path | None = None) -> BenchmarkResult:
    files = sorted(p for p in corpus_dir.glob("*.vy") if p.is_file())
    external_labels = _load_labels(labels_file) if labels_file else {}

    analyzer = StaticAnalyzer(severity_threshold=Severity.LOW)

    tp = fp = tn = fn = 0
    vulnerable_expected = 0
    safe_expected = 0
    predicted_vulnerable = 0
    detector_counts: dict[str, dict[str, int]] = {
        name: {"tp": 0, "fp": 0, "fn": 0} for name in _DETECTOR_KEYWORDS
    }

    for path in files:
        if path.name in external_labels:
            expected_vuln, expected_detectors = external_labels[path.name]
        else:
            expected_vuln = _expected_vulnerable(path)
            expected_detectors = _expected_detectors(path)
        if expected_vuln:
            vulnerable_expected += 1
        else:
            safe_expected += 1

        report = analyzer.analyze_file(path)
        predicted_vuln = len(report.findings) > 0
        predicted_detectors = {f.detector_name for f in report.findings}
        if predicted_vuln:
            predicted_vulnerable += 1

        if expected_vuln and predicted_vuln:
            tp += 1
        elif (not expected_vuln) and predicted_vuln:
            fp += 1
        elif (not expected_vuln) and (not predicted_vuln):
            tn += 1
        else:
            fn += 1

        for detector_name, counts in detector_counts.items():
            in_expected = detector_name in expected_detectors
            in_predicted = detector_name in predicted_detectors

            if in_expected and in_predicted:
                counts["tp"] += 1
            elif (not in_expected) and in_predicted:
                counts["fp"] += 1
            elif in_expected and (not in_predicted):
                counts["fn"] += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    by_detector: dict[str, DetectorBenchmark] = {}
    for detector_name in sorted(detector_counts):
        counts = detector_counts[detector_name]
        d_tp = counts["tp"]
        d_fp = counts["fp"]
        d_fn = counts["fn"]
        d_precision = d_tp / (d_tp + d_fp) if (d_tp + d_fp) else 0.0
        d_recall = d_tp / (d_tp + d_fn) if (d_tp + d_fn) else 0.0
        d_f1 = (
            2 * d_precision * d_recall / (d_precision + d_recall)
            if (d_precision + d_recall)
            else 0.0
        )
        support = d_tp + d_fn
        by_detector[detector_name] = DetectorBenchmark(
            tp=d_tp,
            fp=d_fp,
            fn=d_fn,
            precision=d_precision,
            recall=d_recall,
            f1=d_f1,
            support=support,
        )

    return BenchmarkResult(
        files_total=len(files),
        vulnerable_expected=vulnerable_expected,
        safe_expected=safe_expected,
        predicted_vulnerable=predicted_vulnerable,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        by_detector=by_detector,
    )
