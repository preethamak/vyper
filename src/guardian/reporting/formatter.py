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
        con.print()

    _print_footer(con, report)


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
