"""Markdown report exporter.

Generates well-structured Markdown reports suitable for GitHub PRs,
wikis, or documentation archives.
"""

from __future__ import annotations

from pathlib import Path

from guardian import __version__
from guardian.models import AnalysisReport, Severity

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_GRADE_EMOJI: dict[str, str] = {
    "A+": "🏆",
    "A": "✅",
    "B": "⚠️",
    "C": "🚨",
    "F": "💀",
}


def _verification_section(report: AnalysisReport) -> list[str]:
    verification = (
        report.analysis_context.get("verification")
        if isinstance(report.analysis_context, dict)
        else None
    )
    if not isinstance(verification, dict):
        return []

    summary = (
        verification.get("summary", {}) if isinstance(verification.get("summary"), dict) else {}
    )
    lines: list[str] = ["## ✅ Verification", ""]
    if summary:
        lines.append(
            f"- Summary: passed={summary.get('passed', 0)}, "
            f"failed={summary.get('failed', 0)}, "
            f"skipped={summary.get('skipped', 0)}, "
            f"errors={summary.get('errors', 0)}"
        )
        lines.append("")

    lines.extend(
        [
            "| Suite | Status | Duration (ms) | Exit | Notes | Command |",
            "|---|---|---:|---:|---|---|",
        ]
    )
    for key, label in (("unit", "Unit tests"), ("fuzz", "Fuzz tests")):
        result = verification.get(key, {})
        if not isinstance(result, dict):
            continue
        status = str(result.get("status") or "—").upper()
        duration = result.get("duration_ms")
        exit_code = result.get("exit_code")
        reason = result.get("reason") or "—"
        command = result.get("command") or []
        if isinstance(command, list):
            command_text = " ".join(str(part) for part in command)
        else:
            command_text = str(command)
        lines.append(
            f"| {label} | {status} | {duration if duration is not None else '—'} | "
            f"{exit_code if exit_code is not None else '—'} | {reason} | `{command_text}` |"
        )

    lines.append("")
    return lines


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


def export_markdown(report: AnalysisReport, output_path: str | Path | None = None) -> str:
    """Render the report as Markdown.

    If *output_path* is given the text is also written to that file.

    Returns:
        The Markdown string.
    """
    lines: list[str] = []
    w = lines.append

    grade_emoji = _GRADE_EMOJI.get(report.grade.value, "🔎")

    w("# 🛡️ Vyper Guard — Security Report")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")
    w(f"| **File** | `{report.file_path}` |")
    w(f"| **Date** | {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')} |")
    if report.vyper_version:
        w(f"| **Vyper Pragma** | `{report.vyper_version}` |")
    w(f"| **Security Score** | **{report.security_score}/100** |")
    w(f"| **Grade** | {grade_emoji} **{report.grade.value}** — {report.grade.label} |")
    w(f"| **Detectors Run** | {len(report.detectors_run)} |")
    if report.failed_detectors:
        w(f"| **Failed Detectors** | {len(report.failed_detectors)} |")
    w(f"| **Tool Version** | `vyper-guard v{__version__}` |")
    w("")

    if report.failed_detectors:
        w("## ⚠️ Detector Runtime Failures")
        w("")

    trust = report.analysis_context.get("analysis_trust", {})
    triage = report.analysis_context.get("triage_summary", {})
    if isinstance(trust, dict) and isinstance(triage, dict):
        w("## Analysis Trust and Triage")
        w("")
        w(f"- **Trust level:** `{trust.get('level', 'unknown')}`")
        w(f"- **Semantic engine:** `{report.analysis_context.get('semantic_engine', 'unknown')}`")
        w(f"- **Raw findings:** {triage.get('raw_findings', len(report.findings))}")
        w(f"- **Grouped repetitions:** {triage.get('omitted_repetitions', 0)}")
        for reason in trust.get("degradation_reasons", []):
            w(f"- **Degraded:** {reason}")
        w("")
        w(
            "> One or more detectors crashed during analysis. Results may be incomplete and should be "
            "treated as degraded until failures are resolved."
        )
        w("")
        for name in report.failed_detectors:
            err = report.detector_errors.get(name, "unknown error")
            w(f"- `{name}`: {err}")
        w("")

    # Score bar (text-based for Markdown)
    filled = max(0, min(20, int(report.security_score / 5)))
    bar = "█" * filled + "░" * (20 - filled)
    w(f"**Score:** `{bar}` {report.security_score}/100")
    w("")

    # Summary table
    w("## 📊 Summary")
    w("")
    w("| Severity | Count | Indicator |")
    w("|----------|------:|-----------|")

    for sev, emoji in _SEVERITY_EMOJI.items():
        count = sum(1 for f in report.findings if f.severity == sev)
        bar_len = min(count * 2, 20) if count else 0
        indicator = "█" * bar_len if bar_len else "—"
        w(f"| {emoji} **{sev.value}** | {count} | `{indicator}` |")

    w(f"| **TOTAL** | **{len(report.findings)}** | |")
    w("")

    verification_lines = _verification_section(report)
    if verification_lines:
        lines.extend(verification_lines)

    if not report.findings:
        w("> ✅ **No vulnerabilities detected!**")
        w(">")
        w("> Your contract passed all enabled detectors.")
        w("> This does not guarantee safety — consider a professional audit.")
        w("")
    else:
        # Findings overview table
        w("## 🔍 Findings Overview")
        w("")
        w("| # | Severity | Detector | Title | Line | Confidence |")
        w("|--:|----------|----------|-------|-----:|------------|")

        for i, f in enumerate(report.findings, 1):
            emoji = _SEVERITY_EMOJI[f.severity]
            line = str(f.line_number) if f.line_number else "—"
            w(
                f"| {i} | {emoji} {f.severity.value} | "
                f"`{f.detector_name}` | {f.title} | {line} | {f.confidence.value} |"
            )

        w("")

        # Detailed findings
        w("## 📋 Detailed Findings")
        w("")
        for i, f in enumerate(report.findings, 1):
            emoji = _SEVERITY_EMOJI[f.severity]
            w(f"### {i}. {emoji} {f.title}")
            w("")
            w("| Property | Value |")
            w("|----------|-------|")
            w(f"| **Severity** | {f.severity.value} |")
            w(f"| **Confidence** | {f.confidence.value} |")
            w(f"| **Category** | {f.vulnerability_type.value} |")
            w(f"| **Detector** | `{f.detector_name}` |")
            classification = f.audit_classification.get("classification", "new_candidate")
            w(f"| **Audit Status** | `{classification}` |")
            if f.line_number:
                loc = str(f.line_number)
                if f.end_line_number and f.end_line_number != f.line_number:
                    loc += f"-{f.end_line_number}"
                w(f"| **Location** | Line {loc} |")
            w("")
            w(f"{f.description}")
            w("")
            if f.why_flagged:
                w(f"> 🧠 **Why flagged:** {f.why_flagged}")
                w("")
            if f.evidence:
                w("**Evidence:**")
                for item in f.evidence:
                    w(f"- `{item}`")
                w("")
            if f.why_not_suppressed:
                w(f"> 🔎 **Why not suppressed:** {f.why_not_suppressed}")
                w("")
            if f.semantic_context:
                w("**Semantic Context:**")
                for key, value in f.semantic_context.items():
                    w(f"- `{key}`: `{value}`")
                w("")
            if f.source_snippet:
                w("<details><summary>📝 Source Code</summary>")
                w("")
                w("```vyper")
                w(f.source_snippet)
                w("```")
                w("")
                w("</details>")
                w("")
            if f.fix_suggestion:
                w(f"> 💡 **Suggested Fix:** {f.fix_suggestion}")
                w("")

    if report.ai_triage:
        policy_version = report.ai_triage_policy.get("policy_version", "unknown")
        policy_status = report.ai_triage_policy.get("status", "unknown")

        w("## 🤖 AI-Assisted Triage")
        w("")
        w(
            f"> Policy: `v{policy_version}` (`{policy_status}`) — deterministic advisory metadata only."
        )
        policy_warnings = report.ai_triage_policy.get("warnings", [])
        if policy_warnings:
            w("> Policy warnings: " + "; ".join(str(item) for item in policy_warnings))
        w(
            "> Guardrail: triage is advisory only and cannot override deterministic detector verdicts."
        )
        w(
            "> Confidence uses deterministic scoring (`severity_base + evidence_bonus`, capped at `0.98`)."
        )
        w("")
        w("| Rank | Bucket | Detector | Severity | Confidence | Scoring | Next Step |")
        w("|-----:|--------|----------|----------|-----------:|---------|-----------|")

        for item in report.ai_triage:
            scoring = item.get("scoring_rationale", {})
            scoring_str = (
                f"{scoring.get('version', '—')} / base={scoring.get('severity_base', '—')} "
                f"+ bonus={scoring.get('evidence_bonus', '—')}"
            )
            w(
                "| "
                f"{item.get('priority_rank', '—')} | "
                f"{item.get('triage_bucket', '—')} | "
                f"`{item.get('detector', '—')}` | "
                f"{item.get('severity', '—')} | "
                f"{item.get('confidence', '—')} | "
                f"{scoring_str} | "
                f"{item.get('suggested_next_step', '—')} |"
            )
        w("")

    w("---")
    w("")
    w(
        f"*Generated by [vyper-guard](https://deepwiki.com/preethamak/vyper) "
        f"v{__version__} • "
        f"{len(report.detectors_run)} detectors • "
        f"{len(report.findings)} finding(s)*"
    )
    w("")

    text = "\n".join(lines)

    if output_path:
        path = _prepare_output_path(output_path)
        path.write_text(text, encoding="utf-8")

    return text
