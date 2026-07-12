#!/usr/bin/env python3
"""Run Vyper Guard against an independently audited, commit-pinned engagement."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardian import __version__
from guardian.analyzer.static import StaticAnalyzer
from guardian.models import Severity
from guardian.reporting.json_exporter import report_to_dict


def _load_engagement(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("$schema") != "vyper-guard-audit-engagement/v1":
        raise ValueError("unsupported engagement schema")
    for key in ("id", "protocol", "audited_commit", "auditor", "audit_report"):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            raise ValueError(f"engagement field is required: {key}")
    if not isinstance(payload.get("sources"), list) or not payload["sources"]:
        raise ValueError("engagement sources are required")
    if not isinstance(payload.get("coverage"), list) or not payload["coverage"]:
        raise ValueError("engagement coverage is required")
    if not isinstance(payload.get("cases"), list):
        raise ValueError("engagement cases must be a list")
    return payload


def _resolve_source(source_dir: Path, repository_path: str) -> Path:
    nested = source_dir / repository_path
    if nested.is_file():
        return nested
    flat = source_dir / Path(repository_path).name
    if flat.is_file():
        return flat
    raise ValueError(f"source file is missing: {repository_path}")


def _verify_sources(engagement: dict[str, Any], source_dir: Path) -> dict[str, Path]:
    verified: dict[str, Path] = {}
    for source in engagement["sources"]:
        if not isinstance(source, dict):
            raise ValueError("source entries must be objects")
        repository_path = str(source.get("path") or "")
        expected = str(source.get("sha256") or "")
        path = _resolve_source(source_dir, repository_path)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(
                f"SHA-256 mismatch for {repository_path}: expected {expected}, got {actual}"
            )
        verified[Path(repository_path).name] = path
    return verified


def _finding_payload(file_name: str, finding: dict[str, Any]) -> dict[str, Any]:
    semantic_context = finding.get("semantic_context", {})
    if not isinstance(semantic_context, dict):
        semantic_context = {}
    return {
        "file": file_name,
        "detector": finding["detector"],
        "severity": finding["severity"],
        "confidence": finding["confidence"],
        "title": finding["title"],
        "function": str(semantic_context.get("function") or ""),
        "line": finding.get("line_number"),
        "fingerprint": finding["fingerprint"],
        "review_status": "unreviewed",
    }


def run(engagement_path: Path, source_dir: Path) -> dict[str, Any]:
    engagement = _load_engagement(engagement_path)
    sources = _verify_sources(engagement, source_dir)
    analyzer = StaticAnalyzer(severity_threshold=Severity.LOW, semantic_mode="source")

    findings: list[dict[str, Any]] = []
    detector_failures: dict[str, list[str]] = {}
    trust_levels: Counter[str] = Counter()
    for file_name, source_path in sorted(sources.items()):
        report = analyzer.analyze_file(source_path)
        exported = report_to_dict(report)
        exported_findings = exported.get("findings", [])
        if isinstance(exported_findings, list):
            findings.extend(
                _finding_payload(file_name, finding)
                for finding in exported_findings
                if isinstance(finding, dict)
            )
        if report.failed_detectors:
            detector_failures[file_name] = list(report.failed_detectors)
        trust = report.analysis_context.get("analysis_trust", {})
        if isinstance(trust, dict):
            trust_levels[str(trust.get("level") or "unknown")] += 1

    cases: list[dict[str, Any]] = []
    matched_fingerprints: set[str] = set()
    for case in engagement["cases"]:
        matches = [
            finding
            for finding in findings
            if finding["file"] == case["file"]
            and finding["detector"] == case["detector"]
            and finding["function"].lower() == str(case["function"]).lower()
        ]
        status = "rediscovered" if matches else "missed"
        matched_fingerprints.update(str(match["fingerprint"]) for match in matches)
        cases.append(
            {
                **case,
                "status": status,
                "matches": [match["fingerprint"] for match in matches],
            }
        )

    for finding in findings:
        if finding["fingerprint"] in matched_fingerprints:
            finding["review_status"] = "known_issue_rediscovered"

    coverage = engagement["coverage"]
    supported_findings = [item for item in coverage if item.get("support") == "supported"]
    supported_ids = {str(item["finding_id"]) for item in supported_findings}
    rediscovered_ids = {
        str(case["finding_id"]) for case in cases if case["status"] == "rediscovered"
    }
    rediscovered_cases = sum(case["status"] == "rediscovered" for case in cases)
    unreviewed_candidates = [
        finding for finding in findings if finding["review_status"] == "unreviewed"
    ]
    case_recall = rediscovered_cases / len(cases) if cases else None
    audit_coverage = len(supported_findings) / len(coverage)

    return {
        "$schema": "vyper-guard-public-benchmark/v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "tool": {"name": "vyper-guard", "version": __version__},
        "method": {
            "semantic_mode": "source",
            "severity_threshold": "LOW",
            "source_integrity": "sha256_verified",
            "candidate_review_status": "unreviewed",
        },
        "engagement": {
            key: engagement[key]
            for key in (
                "id",
                "protocol",
                "repository",
                "audited_commit",
                "verified_fix_commit",
                "auditor",
                "engagement_end",
                "audit_report",
            )
        },
        "summary": {
            "audit_findings_total": len(coverage),
            "audit_findings_supported": len(supported_findings),
            "audit_findings_unsupported": len(coverage) - len(supported_findings),
            "audit_findings_rediscovered": len(rediscovered_ids & supported_ids),
            "supported_cases_total": len(cases),
            "supported_cases_rediscovered": rediscovered_cases,
            "supported_cases_missed": len(cases) - rediscovered_cases,
            "supported_case_recall": case_recall,
            "audit_finding_coverage": audit_coverage,
            "scanner_findings_total": len(findings),
            "unreviewed_candidates": len(unreviewed_candidates),
            "false_positives": None,
            "precision": None,
        },
        "analysis_health": {
            "detector_failures": detector_failures,
            "trust_levels": dict(sorted(trust_levels.items())),
        },
        "coverage": coverage,
        "cases": cases,
        "candidates": findings,
    }


def render_markdown(result: dict[str, Any]) -> str:
    engagement = result["engagement"]
    summary = result["summary"]
    recall = summary["supported_case_recall"]
    recall_text = "not measurable" if recall is None else f"{recall:.1%}"
    lines = [
        f"# {engagement['protocol']} benchmark",
        "",
        f"- Auditor: {engagement['auditor']}",
        f"- Audited commit: `{engagement['audited_commit']}`",
        f"- Vyper Guard: `{result['tool']['version']}`",
        f"- Source integrity: {result['method']['source_integrity']}",
        "",
        "## Result",
        "",
        f"- Published audit findings: {summary['audit_findings_total']}",
        f"- Findings supported by current detectors: {summary['audit_findings_supported']}",
        f"- Supported benchmark locations: {summary['supported_cases_total']}",
        f"- Locations rediscovered: {summary['supported_cases_rediscovered']}",
        f"- Supported-case recall: {recall_text}",
        f"- Scanner candidates: {summary['scanner_findings_total']}",
        f"- Unreviewed candidates: {summary['unreviewed_candidates']}",
        "- Precision: not measured; candidates have not been independently reviewed",
        "",
        "## Supported cases",
        "",
        "| Case | File | Function | Detector | Result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in result["cases"]:
        lines.append(
            f"| {case['id']} | `{case['file']}` | `{case['function']}` | "
            f"`{case['detector']}` | **{case['status']}** |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This benchmark measures only detector behavior that maps directly to published audit",
            "evidence. Unsupported findings remain visible as coverage gaps. Scanner candidates are",
            "not called false positives until a reviewer labels them.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engagement", type=Path)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    result = run(args.engagement.resolve(), args.source_dir.resolve())
    json_text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    markdown_text = render_markdown(result)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json_text, encoding="utf-8")
    else:
        print(json_text, end="")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(markdown_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
