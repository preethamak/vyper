"""Rich terminal formatter for analysis reports."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from guardian import __version__
from guardian.models import AnalysisReport, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_SCORE_ICON = {"A+": "🏆", "A": "✅", "B": "⚠️", "C": "🚨", "F": "💀"}


def print_report(report: AnalysisReport, *, console: Console | None = None) -> None:
    """Render an ``AnalysisReport`` to the terminal using Rich."""
    con = console or Console(stderr=True)

    # ── Header ───────────────────────────────────────────────────
    con.print()
    con.print(
        Panel(
            f"[bold]🛡️  Vyper Guard[/bold]  [dim]v{__version__}[/dim]",
            expand=False,
            border_style="bright_cyan",
        )
    )
    con.print()

    filename = Path(report.file_path).name
    con.print(f"  [bold]File:[/bold]    {filename}")
    if report.vyper_version:
        con.print(f"  [bold]Pragma:[/bold]  [dim]{report.vyper_version}[/dim]")
    con.print()

    # ── Score card ───────────────────────────────────────────────
    score = report.security_score
    grade_val = report.grade.value
    grade_icon = _SCORE_ICON.get(grade_val, "")
    score_colour = "green" if score >= 75 else "yellow" if score >= 45 else "red"

    # Score bar: filled blocks
    filled = max(0, min(20, score // 5))
    bar = f"[{score_colour}]{'━' * filled}[/{score_colour}][dim]{'╌' * (20 - filled)}[/dim]"

    con.print(
        f"  {bar}  [{score_colour} bold]{score}/100[/]  "
        f"{grade_icon} [bold]{grade_val}[/bold] — {report.grade.label}"
    )
    con.print()

    if report.failed_detectors:
        failed = ", ".join(report.failed_detectors)
        con.print(f"  [bold red]⚠ Detector failures:[/bold red] [red]{failed}[/red]")
        con.print("  [dim]Analysis may be incomplete due to detector runtime errors.[/dim]")
        con.print()

    _print_verification_section(con, report)
    _print_triage_section(con, report)

    if not report.findings:
        con.print("  [green bold]✅ No issues found — looking good![/green bold]")
        con.print()
        _print_footer(con, report)
        return

    # ── Severity breakdown ───────────────────────────────────────
    counts: Counter[Severity] = Counter()
    for f in report.findings:
        counts[f.severity] += 1

    parts: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        if n > 0:
            icon = _SEVERITY_ICONS[sev]
            style = _SEVERITY_STYLES[sev]
            parts.append(f"{icon} [{style}]{n} {sev.value}[/]")
    con.print("  " + "  ".join(parts))
    con.print()

    # ── Findings table ───────────────────────────────────────────
    table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=True,
        pad_edge=True,
    )
    table.add_column("Sev", width=10, justify="center")
    table.add_column("Detector", width=26)
    table.add_column("Title", ratio=1)
    table.add_column("Line", width=6, justify="right")

    for finding in report.findings:
        icon = _SEVERITY_ICONS.get(finding.severity, "")
        sev_text = Text(
            f"{icon} {finding.severity.value}",
            style=_SEVERITY_STYLES[finding.severity],
        )
        line_str = str(finding.line_number) if finding.line_number else "—"
        table.add_row(sev_text, finding.detector_name, finding.title, line_str)

    con.print(table)
    con.print()

    # ── Detailed findings ────────────────────────────────────────
    for finding in report.findings:
        style = _SEVERITY_STYLES[finding.severity]
        icon = _SEVERITY_ICONS.get(finding.severity, "")
        con.print(f"  {icon} [{style}]{finding.severity.value}[/]  {finding.title}")
        con.print(f"    [dim]{finding.description}[/dim]")
        if finding.source_snippet:
            con.print("    [dim]Source:[/dim]")
            for snippet_line in finding.source_snippet.splitlines()[:8]:
                con.print(f"      [dim]{snippet_line}[/dim]")
        if finding.fix_suggestion:
            con.print(f"    [green]💡 Fix:[/green] {finding.fix_suggestion}")
        if finding.exploit_verification:
            _print_exploit_verification(con, finding.exploit_verification)
        con.print()

    _print_footer(con, report)


def _print_triage_section(con: Console, report: AnalysisReport) -> None:
    if not report.ai_triage:
        return

    policy = report.ai_triage_policy if isinstance(report.ai_triage_policy, dict) else {}
    policy_version = str(policy.get("policy_version") or "unknown")
    policy_status = str(policy.get("status") or "unknown")
    scoring = str(policy.get("scoring") or "triage_scoring_v1")

    con.print("  [bold]AI-Assisted Triage[/bold]")
    con.print(
        f"  [dim]policy={policy_version} status={policy_status} scoring={scoring}; "
        "advisory metadata only[/dim]"
    )

    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Rank", justify="right", width=5)
    table.add_column("Bucket", style="bold", width=16)
    table.add_column("Detector", width=26)
    table.add_column("Severity", width=10)
    table.add_column("Next Step", ratio=1)

    for item in report.ai_triage[:10]:
        if not isinstance(item, dict):
            continue
        table.add_row(
            str(item.get("rank") or "—"),
            str(item.get("bucket") or "—"),
            str(item.get("detector") or "—"),
            str(item.get("severity") or "—"),
            str(item.get("next_step") or "—"),
        )

    con.print(table)
    con.print()


def _print_exploit_verification(con: Console, verification: dict[str, object]) -> None:
    status = str(verification.get("status") or "unknown")
    confidence = str(verification.get("confidence") or "unknown")
    klass = str(verification.get("vulnerability_class") or "unknown")
    context = str(verification.get("protocol_context") or "unknown context")
    con.print(
        f"    [bold cyan]Exploit verification:[/bold cyan] "
        f"{klass} / {status} / confidence={confidence}"
    )
    con.print(f"    [dim]Context:[/dim] {context}")

    path = verification.get("path")
    if isinstance(path, list) and path:
        con.print("    [dim]Proof path:[/dim]")
        for item in path[:4]:
            if not isinstance(item, dict):
                continue
            step = str(item.get("step") or "step")
            line = item.get("line")
            evidence = str(item.get("evidence") or "")
            line_text = f"line {line}" if line else "line —"
            con.print(f"      [dim]- {step} ({line_text}): {evidence}[/dim]")

    patch = verification.get("patch")
    if isinstance(patch, dict):
        summary = str(patch.get("summary") or "")
        if summary:
            con.print(f"    [green]Patch strategy:[/green] {summary}")

    regression = verification.get("regression_test")
    if isinstance(regression, dict):
        name = str(regression.get("name") or "")
        status = str(regression.get("status") or "planned")
        if name:
            con.print(f"    [cyan]Regression test:[/cyan] {name} ({status})")


def _print_footer(con: Console, report: AnalysisReport) -> None:
    """Print the summary footer line."""
    health_msg = ""
    if report.failed_detectors:
        health_msg = f" │ Score trust: DEGRADED │ Failed detectors: {len(report.failed_detectors)}"
    con.print(
        f"  [dim]Detectors run: {len(report.detectors_run)} │ "
        f"Findings: {len(report.findings)}"
        f"{health_msg} │ "
        f"Use [bold]--fix[/bold] to auto-patch[/dim]"
    )
    con.print()


def _print_verification_section(con: Console, report: AnalysisReport) -> None:
    verification = (
        report.analysis_context.get("verification")
        if isinstance(report.analysis_context, dict)
        else None
    )
    if not isinstance(verification, dict):
        return

    con.print("  [bold]Verification[/bold]")
    summary = (
        verification.get("summary", {}) if isinstance(verification.get("summary"), dict) else {}
    )
    if summary:
        con.print(
            f"  [dim]passed={summary.get('passed', 0)}, failed={summary.get('failed', 0)}, "
            f"skipped={summary.get('skipped', 0)}, errors={summary.get('errors', 0)}[/dim]"
        )

    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Suite", style="bold")
    table.add_column("Status")
    table.add_column("Duration (ms)", justify="right")
    table.add_column("Exit", justify="right")
    table.add_column("Notes")

    for key, label in (("unit", "Unit tests"), ("fuzz", "Fuzz tests")):
        result = verification.get(key, {})
        if not isinstance(result, dict):
            continue
        status = str(result.get("status") or "—")
        duration = result.get("duration_ms")
        exit_code = result.get("exit_code")
        reason = str(result.get("reason") or "—")
        table.add_row(
            label,
            status,
            str(duration if duration is not None else "—"),
            str(exit_code if exit_code is not None else "—"),
            reason,
        )

    con.print(table)
    con.print()
