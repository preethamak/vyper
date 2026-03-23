"""Static analysis orchestrator.

This is the top-level entry point for analysing a Vyper contract.  It:

1. Loads the source file.
2. Parses it into a ``ContractInfo`` (no compiler needed).
3. Runs the compiler-version checker.
4. Runs every enabled detector.
5. Computes the security score.
6. Returns an ``AnalysisReport``.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.compiler_check import check_compiler_version
from guardian.analyzer.confidence import calibrate_confidence
from guardian.analyzer.semantic import build_semantic_summary
from guardian.analyzer.vyper_detector import ALL_DETECTORS, DETECTOR_MAP, BaseDetector
from guardian.models import (
    AnalysisReport,
    ContractInfo,
    DetectorResult,
    SecurityGrade,
    Severity,
)
from guardian.utils.helpers import load_vyper_source
from guardian.utils.logger import get_logger

log = get_logger("analyzer.static")


class StaticAnalyzer:
    """Configurable static-analysis pipeline for ``.vy`` contracts.

    Args:
        enabled_detectors: List of detector names to run.  ``["all"]`` (the
            default) enables every registered detector.
        disabled_detectors: Detector names to skip even when *enabled_detectors*
            is ``["all"]``.
        severity_threshold: Minimum severity to include in the report.
    """

    def __init__(
        self,
        enabled_detectors: Sequence[str] = ("all",),
        disabled_detectors: Sequence[str] = (),
        severity_threshold: Severity = Severity.INFO,
    ) -> None:
        self._detectors = self._resolve_detectors(enabled_detectors, disabled_detectors)
        self._severity_threshold = severity_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: str | Path) -> AnalysisReport:
        """Analyse a single ``.vy`` file end-to-end.

        Args:
            file_path: Path to the Vyper contract source.

        Returns:
            A complete ``AnalysisReport``.

        Raises:
            FileLoadError: If the file cannot be loaded.
            AnalysisError: If something goes wrong during analysis.
        """
        path = Path(file_path).resolve()
        source = load_vyper_source(path)
        contract = parse_vyper_source(source, str(path))
        return self.analyze_contract(contract)

    def analyze_source(self, source: str, file_path: str = "<stdin>") -> AnalysisReport:
        """Analyse raw Vyper source code (useful for testing)."""
        contract = parse_vyper_source(source, file_path)
        return self.analyze_contract(contract)

    def analyze_contract(self, contract: ContractInfo) -> AnalysisReport:
        """Run all detectors against an already-parsed ``ContractInfo``."""
        all_findings: list[DetectorResult] = []
        detector_names_run: list[str] = []

        # 1. Compiler-version check (always runs).
        version_findings = check_compiler_version(contract)
        all_findings.extend(version_findings)
        detector_names_run.append("compiler_version_check")

        # 2. Run each detector.
        for detector_cls in self._detectors:
            detector = detector_cls()
            detector_names_run.append(detector.NAME)
            try:
                findings = detector.detect(contract)
                all_findings.extend(findings)
            except Exception as exc:
                log.warning("Detector %s failed: %s", detector.NAME, exc)

        # 3. Filter by severity threshold.
        severity_order = list(Severity)
        threshold_idx = severity_order.index(self._severity_threshold)
        filtered = [f for f in all_findings if severity_order.index(f.severity) <= threshold_idx]
        calibrate_confidence(filtered)
        _attach_semantic_context(filtered, contract)

        # 4. Compute score.
        score = _compute_score(filtered)
        grade = SecurityGrade.from_score(score)

        return AnalysisReport(
            file_path=contract.file_path,
            vyper_version=contract.pragma_version,
            findings=filtered,
            detectors_run=detector_names_run,
            security_score=score,
            grade=grade,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_detectors(
        enabled: Sequence[str],
        disabled: Sequence[str],
    ) -> list[type[BaseDetector]]:
        """Build the final list of detector classes to run."""
        disabled_set = set(disabled)
        if "all" in enabled:
            return [d for d in ALL_DETECTORS if d.NAME not in disabled_set]

        resolved: list[type[BaseDetector]] = []
        for name in enabled:
            if name in disabled_set:
                continue
            if name not in DETECTOR_MAP:
                log.warning("Unknown detector: %s (skipped)", name)
                continue
            resolved.append(DETECTOR_MAP[name])
        return resolved


# Maximum total deduction allowed per severity tier.
# This prevents many LOW findings from destroying the score.
_TIER_CAPS: dict[Severity, int] = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 40,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
    Severity.INFO: 5,
}


def _compute_score(findings: list[DetectorResult]) -> int:
    """Compute a 0-100 security score from findings.

    Scoring logic:
      Base score = 100
      Per-finding penalties: CRITICAL -40, HIGH -20, MEDIUM -8, LOW -3, INFO -1
      Per-tier caps limit total deduction from any one severity level.
      Floor is 0.
    """
    tier_totals: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        tier_totals[f.severity] += f.severity.score_penalty

    total_deduction = 0
    for sev, raw in tier_totals.items():
        total_deduction += min(raw, _TIER_CAPS[sev])

    return max(0, 100 - total_deduction)


def _attach_semantic_context(findings: list[DetectorResult], contract: ContractInfo) -> None:
    """Attach semantic summary snippets to findings when a containing function is known."""
    summary = build_semantic_summary(contract)

    for finding in findings:
        if finding.line_number is None:
            continue

        func = next(
            (
                f
                for f in contract.functions
                if f.start_line <= finding.line_number <= f.end_line
            ),
            None,
        )
        if func is None:
            continue

        sem = summary.functions.get(func.name)
        if sem is None:
            continue

        finding.semantic_context = {
            "function": sem.name,
            "state_reads": sorted(sem.state_reads),
            "state_writes": sorted(sem.state_writes),
            "external_calls": sem.external_calls,
            "external_calls_in_loop": sem.external_calls_in_loop,
            "emits_event": sem.emits_event,
            "uses_delegatecall": sem.uses_delegatecall,
        }
