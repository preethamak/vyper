"""Vyper Guard — CLI interface.

Built with Typer + Rich for a polished developer experience.
Works cross-platform on Linux, macOS, and Windows.
"""

from __future__ import annotations

import json as _json
import sys
import time as _time
from collections import Counter
from pathlib import Path

import typer
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from guardian import __app_name__, __version__
from guardian.analyzer.static import StaticAnalyzer
from guardian.analyzer.vyper_detector import list_detectors as _list_detectors
from guardian.models import AnalysisReport, DetectorResult, Severity
from guardian.reporting.formatter import print_report  # noqa: F401  - public API
from guardian.reporting.json_exporter import export_json
from guardian.reporting.markdown_exporter import export_markdown
from guardian.utils.config import load_config
from guardian.utils.helpers import FileLoadError, GuardianError
from guardian.utils.logger import setup_logging

# ── Branded colours ──────────────────────────────────────────────
ACCENT = "bright_cyan"
DIM = "dim"
OK = "bold green"
ERR = "bold red"
WARN = "bold yellow"

# ── Console (stderr so stdout stays clean for JSON/piping) ───────
console = Console(stderr=True)

# ── Typer app ────────────────────────────────────────────────────
app = typer.Typer(
    name=__app_name__,
    help="🛡️  Vyper Guard — static analysis for Vyper smart contracts.",
    add_completion=True,
    no_args_is_help=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


# ═══════════════════════════════════════════════════════════════════
#  Branded output helpers
# ═══════════════════════════════════════════════════════════════════

# Large block-letter logo — the face of the tool.
_LOGO = """[bold bright_cyan]
 ██╗   ██╗██╗   ██╗██████╗ ███████╗██████╗
 ██║   ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║   ██║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ╚██╗ ██╔╝  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗
  ╚████╔╝    ██║   ██║     ███████╗██║  ██║
   ╚═══╝     ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝[/bold bright_cyan]"""

# Compact logo for sub-commands — same block-letter style, clean proportions.
_LOGO_COMPACT = """[bold bright_cyan]
 ██╗   ██╗██╗   ██╗██████╗ ███████╗██████╗
 ██║   ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║   ██║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ╚██╗ ██╔╝  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗
  ╚████╔╝    ██║   ██║     ███████╗██║  ██║
   ╚═══╝     ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝
         ━━━━  [bold white]G  U  A  R  D[/bold white]  ━━━━[/bold bright_cyan]"""

_SEV_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim",
}
_SEV_ICONS: dict[str, str] = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
    "INFO": "\u26aa",
}
_GRADE_ICON: dict[str, str] = {
    "A+": "\U0001f3c6",
    "A": "\u2705",
    "B": "\u26a0\ufe0f",
    "C": "\U0001f6a8",
    "F": "\U0001f480",
}
_GRADE_STYLE: dict[str, str] = {
    "A+": "bold bright_green",
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "F": "bold red",
}


def _print_banner() -> None:
    """Print the compact branded banner for sub-commands."""
    console.print(_LOGO_COMPACT)
    console.print(
        f"  [dim]v{__version__}[/dim]  "
        f"[dim]|[/dim]  [dim]Vyper-native smart contract security toolkit[/dim]"
    )
    console.print()


def _print_help_screen() -> None:
    """Show the full branded help screen when user types just `vyper-guard`."""
    # Full large logo
    console.print(_LOGO)
    console.print(
        f"  [bold white]v{__version__}[/bold white]  "
        f"[dim]|[/dim]  [dim]Vyper smart contract security toolkit[/dim]"
    )
    console.print()

    # ── Commands table ───────────────────────────────────────────
    console.print(Rule("[bold]Commands[/bold]", style=ACCENT))
    console.print()

    cmd_table = Table(
        show_header=True,
        header_style="bold",
        box=box.SIMPLE_HEAVY,
        expand=False,
        padding=(0, 2),
    )
    cmd_table.add_column("Command", style=f"bold {ACCENT}", min_width=28)
    cmd_table.add_column("Description")

    cmd_table.add_row("analyze <contract.vy>", "Scan any .vy contract for vulnerabilities")
    cmd_table.add_row("analyze <contract.vy> --fix", "Scan + auto-patch detected issues")
    cmd_table.add_row("scan <contract.vy>", "Alias for analyze")
    cmd_table.add_row("stats <contract.vy>", "Show contract statistics & structure")
    cmd_table.add_row("diff <old.vy> <new.vy>", "Compare security of two contracts")
    cmd_table.add_row("detectors", "List all available security detectors")
    cmd_table.add_row("init", "Create a .guardianrc config file")
    cmd_table.add_row("monitor <address>", "Live-monitor a deployed contract")
    cmd_table.add_row("baseline <address>", "Build normal-behaviour baseline")
    cmd_table.add_row("version", "Show version and environment info")

    console.print(cmd_table)
    console.print()

    # ── Quick examples ───────────────────────────────────────────
    console.print(Rule("[bold]Quick Start[/bold]", style=ACCENT))
    console.print()
    examples = [
        ("Scan any contract", "vyper-guard analyze my_contract.vy"),
        ("Scan + auto-fix", "vyper-guard analyze my_contract.vy --fix"),
        ("Contract overview", "vyper-guard stats my_contract.vy"),
        ("Compare two versions", "vyper-guard diff v1.vy v2.vy"),
        ("JSON for CI pipelines", "vyper-guard analyze my_contract.vy -f json -o report.json"),
        ("CI gate (exit 1 on HIGH+)", "vyper-guard analyze my_contract.vy --ci -s HIGH"),
        ("List all detectors", "vyper-guard detectors"),
    ]
    for label, cmd in examples:
        console.print(f"    [dim]{label}:[/dim]")
        console.print(f"    [bold white]$ {cmd}[/bold white]")
        console.print()

    # ── Footer ───────────────────────────────────────────────────
    console.print(
        Rule(
            "[dim]Docs: https://github.com/preethamak/vyper  |  "
            "vyper-guard <command> -h for help[/dim]",
            style="dim",
        )
    )
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  Root callback (version flag + no-args-is-help)
# ═══════════════════════════════════════════════════════════════════


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[{ACCENT}]{__app_name__}[/{ACCENT}] [bold]{__version__}[/bold]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """🛡️ Vyper Guard — Vyper-native smart contract security analysis."""
    if ctx.invoked_subcommand is None:
        _print_help_screen()
        raise typer.Exit()


# ═══════════════════════════════════════════════════════════════════
#  Input validation (works for ANY contract from anywhere)
# ═══════════════════════════════════════════════════════════════════


def _validate_contract_path(file_path: Path) -> None:
    """Validate the contract file before analysis.

    Provides clear, actionable error messages so users piping in
    arbitrary contracts get helpful feedback instead of tracebacks.
    """
    if file_path.suffix != ".vy":
        console.print(
            Panel(
                f"[{ERR}]Expected a .vy file, got: [bold]{file_path.suffix or '(no extension)'}[/bold][/{ERR}]\n\n"
                f"  File: {file_path}\n\n"
                "  [dim]Vyper Guard analyses Vyper smart contracts (.vy files).\n"
                "  If this is a Solidity file, try Slither or Mythril instead.[/dim]",
                title="[bold red]Invalid File Type[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(code=2)

    size = file_path.stat().st_size
    if size == 0:
        console.print(
            Panel(
                f"[{ERR}]The file is empty (0 bytes).[/{ERR}]\n\n  File: {file_path}",
                title="[bold red]Empty File[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(code=2)

    max_mb = 10
    if size > max_mb * 1024 * 1024:
        mb = size / (1024 * 1024)
        console.print(
            Panel(
                f"[{ERR}]File is too large: {mb:.1f} MB (limit: {max_mb} MB)[/{ERR}]\n\n"
                f"  File: {file_path}",
                title="[bold red]File Too Large[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(code=2)


# ═══════════════════════════════════════════════════════════════════
#  analyze
# ═══════════════════════════════════════════════════════════════════


@app.command()
def analyze(
    file_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the .vy contract to analyse.",
        exists=True,
        readable=True,
    ),
    format: str = typer.Option(
        "cli",
        "--format",
        "-f",
        help="Output format: cli, json, markdown.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "-o",
        help="Write report to this file (json/markdown only).",
    ),
    detectors: str | None = typer.Option(
        None,
        "--detectors",
        "-d",
        help="Comma-separated detector names to run (default: all).",
    ),
    severity_threshold: str = typer.Option(
        "INFO",
        "--severity-threshold",
        "-s",
        help="Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO.",
    ),
    config: Path | None = typer.Option(  # noqa: B008
        None,
        "--config",
        "-c",
        help="Path to a .guardianrc config file.",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode — exit with code 1 if findings exceed the severity threshold.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose / debug output.",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Auto-generate fixes for detected issues and optionally apply them.",
    ),
) -> None:
    """Analyse a Vyper contract for security vulnerabilities."""
    setup_logging(verbose)

    # Validate the file before doing anything else
    _validate_contract_path(file_path)

    # Resolve config
    cfg = load_config(str(config) if config else None)

    # Determine which detectors to run
    enabled = ["all"]
    if detectors:
        enabled = [d.strip() for d in detectors.split(",")]
    elif cfg.analysis.enabled_detectors != ["all"]:
        enabled = cfg.analysis.enabled_detectors

    # Severity threshold
    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[{ERR}]Invalid severity threshold: {severity_threshold}[/{ERR}]")
        raise typer.Exit(code=2) from None

    # Run analysis with a progress bar
    analyzer = StaticAnalyzer(
        enabled_detectors=enabled,
        disabled_detectors=cfg.analysis.disabled_detectors,
        severity_threshold=threshold,
    )

    fmt = format.lower()

    try:
        t0 = _time.perf_counter()

        if fmt == "cli":
            with Progress(
                SpinnerColumn("dots"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=25),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(f"[{ACCENT}]Scanning {file_path.name}…", total=100)
                progress.update(task, completed=15, description="Parsing source…")
                report = analyzer.analyze_file(file_path)
                progress.update(task, completed=100, description="Done!")
        else:
            report = analyzer.analyze_file(file_path)

        elapsed_ms = (_time.perf_counter() - t0) * 1000

    except FileLoadError as exc:
        console.print(f"[{ERR}]Error:[/{ERR}] {exc}")
        raise typer.Exit(code=2) from exc
    except GuardianError as exc:
        console.print(f"[{ERR}]Analysis failed:[/{ERR}] {exc}")
        raise typer.Exit(code=2) from exc

    # Output
    if fmt == "json":
        text = export_json(report, output)
        if not output:
            typer.echo(text)
    elif fmt == "markdown":
        text = export_markdown(report, output)
        if not output:
            typer.echo(text)
    else:
        _print_rich_report(report, elapsed_ms)
        if output:
            export_json(report, output)

    # --fix: auto-remediation
    if fix and report.findings:
        _run_fix_mode(file_path, report, console)

    # CI exit code
    if ci and report.findings:
        raise typer.Exit(code=1)


# ═══════════════════════════════════════════════════════════════════
#  scan — alias for analyze (friendlier name for public users)
# ═══════════════════════════════════════════════════════════════════


@app.command(hidden=True)
def scan(
    file_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the .vy contract to analyse.",
        exists=True,
        readable=True,
    ),
    format: str = typer.Option("cli", "--format", "-f"),
    output: Path | None = typer.Option(None, "--output", "-o"),  # noqa: B008
    detectors: str | None = typer.Option(None, "--detectors", "-d"),
    severity_threshold: str = typer.Option("INFO", "--severity-threshold", "-s"),
    config: Path | None = typer.Option(None, "--config", "-c"),  # noqa: B008
    ci: bool = typer.Option(False, "--ci"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    fix: bool = typer.Option(False, "--fix"),
) -> None:
    """Alias for 'analyze' — scan a Vyper contract for vulnerabilities."""
    analyze(
        file_path=file_path,
        format=format,
        output=output,
        detectors=detectors,
        severity_threshold=severity_threshold,
        config=config,
        ci=ci,
        verbose=verbose,
        fix=fix,
    )


# ═══════════════════════════════════════════════════════════════════
#  Rich report renderer (the beautiful one)
# ═══════════════════════════════════════════════════════════════════


def _print_rich_report(report: AnalysisReport, elapsed_ms: float = 0.0) -> None:
    """Render a stunning analysis report to the terminal."""
    console.print(_LOGO_COMPACT)
    console.print(
        f"  [bold white]v{__version__}[/bold white]  [dim]|[/dim]  [bold]Security Report[/bold]"
    )
    console.print()

    # ── Contract metadata panel ──
    filename = Path(report.file_path).name
    meta_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), expand=True)
    meta_table.add_column("Key", style=f"bold {ACCENT}", min_width=20)
    meta_table.add_column("Value")

    meta_table.add_row("📄 File", filename)
    meta_table.add_row("📁 Path", report.file_path)
    if report.vyper_version:
        meta_table.add_row("🐍 Vyper Version", report.vyper_version)

    # Count functions and LOC
    try:
        from guardian.analyzer.ast_parser import parse_vyper_source
        from guardian.utils.helpers import load_vyper_source

        source = load_vyper_source(report.file_path)
        contract = parse_vyper_source(source, report.file_path)
        loc = sum(1 for ln in contract.lines if ln.strip() and not ln.strip().startswith("#"))
        meta_table.add_row("📏 Lines of Code", f"{loc:,}")
        meta_table.add_row("🔍 Functions", str(len(contract.functions)))
        meta_table.add_row("📊 State Variables", str(len(contract.state_variables)))
        meta_table.add_row("📢 Events", str(len(contract.events)))
    except Exception:
        pass

    meta_table.add_row("🔧 Detectors Run", str(len(report.detectors_run)))
    if elapsed_ms > 0:
        meta_table.add_row("⏱️  Duration", f"{elapsed_ms:.0f} ms")
    meta_table.add_row("🏷️  Tool Version", __version__)

    console.print(meta_table)
    console.print()

    # ── Score card + Severity breakdown side by side ──
    score = report.security_score
    grade_val = report.grade.value
    grade_icon = _GRADE_ICON.get(grade_val, "🔎")
    grade_style = _GRADE_STYLE.get(grade_val, "white")

    # Score bar
    filled = max(0, min(30, int(score / 100 * 30)))
    bar_color = grade_style.replace("bold ", "")
    bar = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * (30 - filled)}[/dim]"

    score_content = (
        f"\n  {grade_icon}  [{grade_style}]{grade_val}[/{grade_style}]"
        f"  [bold]{score}[/bold] / 100\n"
        f"  [{DIM}]{report.grade.label}[/{DIM}]\n\n"
        f"  {bar}\n"
    )
    score_panel = Panel(
        score_content,
        title="[bold]Security Score[/bold]",
        border_style=grade_style,
        padding=(0, 2),
        width=45,
    )

    # Severity breakdown with bars
    counts = Counter(f.severity for f in report.findings)
    max_count = max(counts.values()) if counts else 1

    bd_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    bd_table.add_column("Icon", width=3, justify="center")
    bd_table.add_column("Severity", min_width=10)
    bd_table.add_column("Count", justify="right", min_width=5)
    bd_table.add_column("Bar", min_width=20)

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        icon = _SEV_ICONS.get(sev.value, "")
        style = _SEV_STYLES.get(sev.value, "dim")
        bar_len = int((n / max_count) * 20) if max_count > 0 and n > 0 else 0
        bbar = f"[{style}]{'█' * bar_len}{'░' * (20 - bar_len)}[/{style}]"
        bd_table.add_row(icon, f"[{style}]{sev.value}[/{style}]", str(n), bbar)

    breakdown_panel = Panel(
        bd_table,
        title="[bold]Severity Breakdown[/bold]",
        border_style=ACCENT,
        padding=(0, 1),
        width=45,
    )

    console.print(Columns([score_panel, breakdown_panel], padding=2, expand=True))
    console.print()

    # ── No findings? ──
    if not report.findings:
        console.print(
            Panel(
                "[bold green]✅ No vulnerabilities detected![/bold green]\n\n"
                "  Your contract passed all enabled detectors.\n"
                "  [dim]This does not guarantee safety — consider a professional audit.[/dim]",
                border_style="green",
                padding=(1, 3),
            )
        )
        console.print()
        _print_analysis_footer(report)
        return

    # ── Findings table (compact overview) ──
    console.print(
        Rule(
            f"[bold]🔍 Findings ({len(report.findings)})[/bold]",
            style=ACCENT,
        )
    )
    console.print()

    table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=True,
        pad_edge=True,
        show_lines=True,
    )
    table.add_column("Sev", width=12, justify="center")
    table.add_column("Detector", style=f"bold {ACCENT}", width=28)
    table.add_column("Title", ratio=1)
    table.add_column("Conf", width=8, justify="center")
    table.add_column("Line", width=6, justify="right")

    for finding in report.findings:
        icon = _SEV_ICONS.get(finding.severity.value, "")
        sev_text = Text(
            f"{icon} {finding.severity.value}",
            style=_SEV_STYLES.get(finding.severity.value, ""),
        )
        line_str = str(finding.line_number) if finding.line_number else "—"
        conf_text = Text(
            finding.confidence.value,
            style="green" if finding.confidence.value == "HIGH" else "yellow",
        )
        table.add_row(sev_text, finding.detector_name, finding.title, conf_text, line_str)

    console.print(table)
    console.print()

    # ── Detailed finding panels ──
    console.print(Rule("[bold]📋 Detailed Findings[/bold]", style=ACCENT))
    console.print()

    for idx, finding in enumerate(report.findings):
        _print_finding_panel(idx, finding)

    _print_analysis_footer(report)


def _print_finding_panel(idx: int, finding: DetectorResult) -> None:
    """Render a single finding as a beautiful panel."""
    sev = finding.severity.value
    style = _SEV_STYLES.get(sev, "dim")
    icon = _SEV_ICONS.get(sev, "⚪")

    content_parts: list[str] = []
    content_parts.append(f"[bold]Description:[/bold] {finding.description}")

    if finding.line_number:
        loc = f"Line {finding.line_number}"
        if finding.end_line_number and finding.end_line_number != finding.line_number:
            loc += f"-{finding.end_line_number}"
        content_parts.append(f"[bold]Location:[/bold] {loc}")

    content_parts.append(f"[bold]Detector:[/bold] [dim]{finding.detector_name}[/dim]")
    content_parts.append(f"[bold]Category:[/bold] [dim]{finding.vulnerability_type.value}[/dim]")

    if finding.source_snippet:
        snippet = finding.source_snippet.strip()
        lines = snippet.split("\n")
        if len(lines) > 8:
            snippet = "\n".join(lines[:8]) + "\n  ..."
        content_parts.append(f"\n[bold]Source:[/bold]\n[on #1a1a2e]{snippet}[/on #1a1a2e]")

    if finding.fix_suggestion:
        content_parts.append(f"\n[bold green]💡 Fix:[/bold green] {finding.fix_suggestion}")

    content = "\n".join(content_parts)

    console.print(
        Panel(
            content,
            title=f"[bold]#{idx + 1}[/bold] {icon} {finding.title}",
            subtitle=f"[{style}]{sev}[/{style}] • Confidence: {finding.confidence.value}",
            border_style=style,
            padding=(1, 2),
            expand=True,
        )
    )
    console.print()


def _print_analysis_footer(report: AnalysisReport) -> None:
    """Print the summary footer with detectors tree."""
    # Detectors tree
    det_tree = Tree(f"[bold {ACCENT}]🔧 Detectors Run[/bold {ACCENT}]")
    for d in sorted(report.detectors_run):
        det_tree.add(f"[dim]•[/dim] {d}")
    console.print(det_tree)
    console.print()

    console.print(
        Rule(
            f"[dim]{__app_name__} v{__version__} • https://github.com/preethamak/vyper[/dim]",
            style="dim",
        )
    )
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  --fix mode
# ═══════════════════════════════════════════════════════════════════


def _run_fix_mode(file_path: Path, report: AnalysisReport, con: Console) -> None:
    """Auto-remediation flow: generate fixes, show diffs, prompt, apply."""
    from rich.syntax import Syntax

    from guardian.analyzer.ast_parser import parse_vyper_source
    from guardian.remediation.fix_generator import FixGenerator

    source = file_path.read_text(encoding="utf-8")
    contract = parse_vyper_source(source, str(file_path))
    source_lines = source.splitlines()

    gen = FixGenerator(source_lines, contract)
    results = gen.generate_all(report.findings)

    applied = [r for r in results if r.applied]
    skipped = [r for r in results if not r.applied]

    if not applied:
        con.print(f"\n  [{WARN}]⚠  No auto-fixes available for these findings.[/{WARN}]\n")
        return

    # Header
    con.print()
    con.print(
        Panel(
            f"[{OK}]🔧  Auto-Remediation  —  {len(applied)} fix(es) generated[/{OK}]",
            expand=False,
            border_style="green",
        )
    )
    con.print()

    for i, result in enumerate(applied, 1):
        sev = result.finding.severity.value
        con.print(f"  [bold]Fix {i}/{len(applied)}:[/bold] {result.description}")
        con.print(f"    Severity: [bold]{sev}[/bold]  |  Detector: {result.finding.detector_name}")
        if result.diff:
            con.print()
            con.print(Syntax(result.diff, "diff", theme="monokai", line_numbers=False))
        if result.warnings:
            for w in result.warnings:
                con.print(f"    [{WARN}]⚠ {w}[/{WARN}]")
        con.print()

    if skipped:
        con.print(
            f"  [{DIM}]{len(skipped)} finding(s) have no auto-fix (manual review needed).[/{DIM}]"
        )
        for s in skipped:
            con.print(f"    [{DIM}]• {s.finding.detector_name}: {s.description}[/{DIM}]")
        con.print()

    # Get patched source
    patched = gen.patched_source()

    # Write to .fixed.vy file
    fixed_path = file_path.with_suffix(".fixed.vy")
    fixed_path.write_text(patched, encoding="utf-8")
    con.print(f"  [{OK}]✅  Patched contract written to:[/{OK}] [bold]{fixed_path}[/bold]")

    # Ask user if they want to overwrite the original
    try:
        overwrite = typer.confirm(
            f"\n  Overwrite original file ({file_path.name})?",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        overwrite = False

    if overwrite:
        file_path.write_text(patched, encoding="utf-8")
        con.print(f"  [{OK}]✅  Original file updated:[/{OK}] [bold]{file_path}[/bold]")
        if fixed_path.exists():
            fixed_path.unlink()
    else:
        con.print(
            f"  [{DIM}]Original unchanged. Review {fixed_path.name} and apply manually.[/{DIM}]"
        )

    con.print()


# ═══════════════════════════════════════════════════════════════════
#  detectors
# ═══════════════════════════════════════════════════════════════════

_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


@app.command(name="detectors")
def detectors_cmd() -> None:
    """List all available vulnerability detectors."""
    _print_banner()

    dets = _list_detectors()

    table = Table(
        title="[bold]Security Detectors[/bold]",
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=True,
        padding=(0, 1),
        show_lines=True,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Detector", style=f"bold {ACCENT}", min_width=26)
    table.add_column("Severity", width=12, justify="center")
    table.add_column("Category", width=22)
    table.add_column("Description", ratio=1)

    for i, d in enumerate(dets, 1):
        sev = d["severity"]
        icon = _SEV_ICONS.get(sev, "")
        sev_text = Text(f"{icon} {sev}", style=_SEVERITY_COLOURS.get(sev, ""))
        table.add_row(
            str(i),
            d["name"],
            sev_text,
            d["vulnerability_type"],
            d["description"],
        )

    console.print(table)
    console.print()
    console.print(f"  [{DIM}]{len(dets)} detectors available  •  all enabled by default[/{DIM}]")
    console.print(
        f"  [{DIM}]Docs: https://github.com/preethamak/vyper/blob/main/docs/DETECTORS.md[/{DIM}]"
    )
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  stats — contract overview
# ═══════════════════════════════════════════════════════════════════


@app.command()
def stats(
    file_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the .vy contract.",
        exists=True,
        readable=True,
    ),
) -> None:
    """Show contract statistics, structure & complexity overview."""
    from guardian.analyzer.ast_parser import parse_vyper_source
    from guardian.utils.helpers import load_vyper_source as _load

    _validate_contract_path(file_path)
    _print_banner()

    try:
        source = _load(file_path)
        contract = parse_vyper_source(source, str(file_path))
    except GuardianError as exc:
        console.print(
            Panel(
                f"[{ERR}]{exc}[/{ERR}]",
                title="[bold red]Parse Error[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(code=2) from exc

    total_lines = len(contract.lines)
    code_lines = sum(1 for ln in contract.lines if ln.strip() and not ln.strip().startswith("#"))
    comment_lines = sum(1 for ln in contract.lines if ln.strip().startswith("#"))
    blank_lines = total_lines - code_lines - comment_lines

    # ── Overview table ──
    console.print(Rule(f"[bold {ACCENT}]📊 Contract Statistics — {file_path.name}[/bold {ACCENT}]"))
    console.print()

    overview = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), expand=True)
    overview.add_column("Metric", style=f"bold {ACCENT}", min_width=22)
    overview.add_column("Value")
    overview.add_row("📄 File", str(file_path))
    if contract.pragma_version:
        overview.add_row("🐍 Pragma Version", contract.pragma_version)
    overview.add_row("📏 Total Lines", f"{total_lines:,}")
    overview.add_row("💻 Code Lines", f"{code_lines:,}")
    overview.add_row("💬 Comment Lines", f"{comment_lines:,}")
    overview.add_row("⬜ Blank Lines", f"{blank_lines:,}")
    overview.add_row("🔍 Functions", str(len(contract.functions)))
    overview.add_row("📊 State Variables", str(len(contract.state_variables)))
    overview.add_row("📢 Events", str(len(contract.events)))
    overview.add_row("📦 Imports", str(len(contract.imports)))
    console.print(overview)
    console.print()

    # ── Lines of code breakdown bar ──
    if total_lines > 0:
        code_pct = code_lines / total_lines * 100
        comment_pct = comment_lines / total_lines * 100
        blank_pct = blank_lines / total_lines * 100
        code_bar = int(code_pct / 100 * 40)
        comment_bar = int(comment_pct / 100 * 40)
        blank_bar = 40 - code_bar - comment_bar

        bar_str = (
            f"[green]{'█' * code_bar}[/green]"
            f"[blue]{'█' * comment_bar}[/blue]"
            f"[dim]{'░' * blank_bar}[/dim]"
        )
        console.print(f"  {bar_str}")
        console.print(
            f"  [green]■ Code {code_pct:.0f}%[/green]  "
            f"[blue]■ Comments {comment_pct:.0f}%[/blue]  "
            f"[dim]■ Blank {blank_pct:.0f}%[/dim]"
        )
        console.print()

    # ── Functions tree ──
    if contract.functions:
        console.print(Rule("[bold]🔍 Functions[/bold]", style=ACCENT))
        console.print()

        func_table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
            expand=True,
        )
        func_table.add_column("Function", style="bold white", min_width=20)
        func_table.add_column("Visibility", width=12, justify="center")
        func_table.add_column("Decorators", ratio=1)
        func_table.add_column("Lines", width=10, justify="right")

        for func in sorted(contract.functions, key=lambda f: f.start_line):
            vis = ""
            if func.is_external:
                vis = "[green]@external[/green]"
            elif func.is_internal:
                vis = "[yellow]@internal[/yellow]"
            else:
                vis = "[dim]—[/dim]"

            decs = []
            for d in func.decorators:
                if d == "nonreentrant":
                    decs.append("[green]@nonreentrant[/green]")
                elif d == "payable":
                    decs.append("[yellow]@payable[/yellow]")
                elif d in ("view", "pure"):
                    decs.append(f"[blue]@{d}[/blue]")
                elif d not in ("external", "internal"):
                    decs.append(f"[dim]@{d}[/dim]")

            dec_str = " ".join(decs) if decs else "[dim]—[/dim]"
            line_range = f"{func.start_line}-{func.end_line}"
            func_table.add_row(func.name, vis, dec_str, line_range)

        console.print(func_table)
        console.print()

    # ── State variables ──
    if contract.state_variables:
        console.print(Rule("[bold]📊 State Variables[/bold]", style=ACCENT))
        console.print()

        var_table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
            expand=True,
        )
        var_table.add_column("Name", style="bold white", min_width=16)
        var_table.add_column("Type", ratio=1)
        var_table.add_column("Flags", width=24)
        var_table.add_column("Line", width=6, justify="right")

        for var in contract.state_variables:
            flags = []
            if var.is_public:
                flags.append("[green]public[/green]")
            if var.is_constant:
                flags.append("[blue]constant[/blue]")
            if var.is_immutable:
                flags.append("[yellow]immutable[/yellow]")
            flags_str = " ".join(flags) if flags else "[dim]private[/dim]"
            var_table.add_row(var.name, var.type_annotation, flags_str, str(var.line_number))

        console.print(var_table)
        console.print()

    console.print(Rule(f"[dim]{__app_name__} v{__version__}[/dim]", style="dim"))
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  diff — compare two contracts' security
# ═══════════════════════════════════════════════════════════════════


@app.command()
def diff(
    file_a: Path = typer.Argument(  # noqa: B008
        ...,
        help="First .vy contract (baseline / old version).",
        exists=True,
        readable=True,
    ),
    file_b: Path = typer.Argument(  # noqa: B008
        ...,
        help="Second .vy contract (new version).",
        exists=True,
        readable=True,
    ),
) -> None:
    """Compare the security posture of two Vyper contracts side-by-side."""
    _validate_contract_path(file_a)
    _validate_contract_path(file_b)
    _print_banner()

    analyzer = StaticAnalyzer()
    try:
        report_a = analyzer.analyze_file(file_a)
        report_b = analyzer.analyze_file(file_b)
    except GuardianError as exc:
        console.print(f"[{ERR}]Analysis failed:[/{ERR}] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(Rule(f"[bold {ACCENT}]🔀 Security Diff[/bold {ACCENT}]"))
    console.print()

    # Side-by-side comparison
    comp_table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        expand=True,
        show_lines=True,
    )
    comp_table.add_column("Metric", style="bold", min_width=18)
    comp_table.add_column(f"📄 {file_a.name}", justify="center", min_width=20)
    comp_table.add_column(f"📄 {file_b.name}", justify="center", min_width=20)
    comp_table.add_column("Δ Change", justify="center", min_width=14)

    # Score
    delta_score = report_b.security_score - report_a.security_score
    delta_style = "green" if delta_score > 0 else "red" if delta_score < 0 else "dim"
    delta_str = f"+{delta_score}" if delta_score > 0 else str(delta_score)
    comp_table.add_row(
        "Security Score",
        f"{report_a.security_score}/100",
        f"{report_b.security_score}/100",
        f"[{delta_style}]{delta_str}[/{delta_style}]",
    )

    # Grade
    g_a_style = _GRADE_STYLE.get(report_a.grade.value, "white")
    g_b_style = _GRADE_STYLE.get(report_b.grade.value, "white")
    comp_table.add_row(
        "Grade",
        f"[{g_a_style}]{report_a.grade.value}[/{g_a_style}]",
        f"[{g_b_style}]{report_b.grade.value}[/{g_b_style}]",
        "—",
    )

    # Total findings
    delta_f = len(report_b.findings) - len(report_a.findings)
    delta_f_style = "green" if delta_f < 0 else "red" if delta_f > 0 else "dim"
    delta_f_str = f"+{delta_f}" if delta_f > 0 else str(delta_f)
    comp_table.add_row(
        "Total Findings",
        str(len(report_a.findings)),
        str(len(report_b.findings)),
        f"[{delta_f_style}]{delta_f_str}[/{delta_f_style}]",
    )

    # Per-severity
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        icon = _SEV_ICONS.get(sev.value, "")
        count_a = sum(1 for f in report_a.findings if f.severity == sev)
        count_b = sum(1 for f in report_b.findings if f.severity == sev)
        delta = count_b - count_a
        ds = "green" if delta < 0 else "red" if delta > 0 else "dim"
        dstr = f"+{delta}" if delta > 0 else str(delta)
        comp_table.add_row(
            f"{icon} {sev.value}",
            str(count_a),
            str(count_b),
            f"[{ds}]{dstr}[/{ds}]",
        )

    console.print(comp_table)
    console.print()

    # ── New findings in B ──
    names_a = {(f.detector_name, f.line_number) for f in report_a.findings}
    new_in_b = [f for f in report_b.findings if (f.detector_name, f.line_number) not in names_a]

    names_b = {(f.detector_name, f.line_number) for f in report_b.findings}
    fixed_in_b = [f for f in report_a.findings if (f.detector_name, f.line_number) not in names_b]

    if fixed_in_b:
        console.print(f"  [green]✅ {len(fixed_in_b)} finding(s) fixed in {file_b.name}:[/green]")
        for f in fixed_in_b:
            console.print(f"    [green]  ✓ {f.detector_name}: {f.title}[/green]")
        console.print()

    if new_in_b:
        console.print(f"  [red]🆕 {len(new_in_b)} new finding(s) in {file_b.name}:[/red]")
        for f in new_in_b:
            icon = _SEV_ICONS.get(f.severity.value, "")
            console.print(f"    [red]  {icon} {f.detector_name}: {f.title}[/red]")
        console.print()

    if not new_in_b and not fixed_in_b:
        console.print(f"  [{DIM}]No changes in findings between the two contracts.[/{DIM}]")
        console.print()

    # Verdict
    if delta_score > 0:
        console.print(
            Panel(
                f"[bold green]📈 Security improved by {delta_score} points![/bold green]",
                border_style="green",
                expand=False,
            )
        )
    elif delta_score < 0:
        console.print(
            Panel(
                f"[bold red]📉 Security regressed by {abs(delta_score)} points![/bold red]",
                border_style="red",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                "[bold]🔄 Same security score.[/bold]",
                border_style="yellow",
                expand=False,
            )
        )

    console.print()


# ═══════════════════════════════════════════════════════════════════
#  init — create config file
# ═══════════════════════════════════════════════════════════════════

_DEFAULT_CONFIG = """\
# .guardianrc — Vyper Guard configuration
# Docs: https://github.com/preethamak/vyper

analysis:
  # Which detectors to enable ("all" or a list)
  enabled_detectors:
    - all
  # Detectors to skip
  disabled_detectors: []
  # Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO
  severity_threshold: LOW

reporting:
  # Default output format: cli, json, markdown
  default_format: cli
  show_source_snippets: true
  show_fix_suggestions: true

performance:
  max_file_size_mb: 10
  cache_enabled: true
"""


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config."),
) -> None:
    """Create a .guardianrc configuration file in the current directory."""
    _print_banner()

    config_path = Path.cwd() / ".guardianrc"

    if config_path.exists() and not force:
        console.print(f"  [{WARN}]{config_path} already exists. Use --force to overwrite.[/{WARN}]")
        raise typer.Exit(1)

    config_path.write_text(_DEFAULT_CONFIG, encoding="utf-8")
    console.print(f"  [{OK}]✅ Created {config_path}[/{OK}]")
    console.print(f"  [{DIM}]Edit the file to customise analysis settings.[/{DIM}]")
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  version (dedicated subcommand)
# ═══════════════════════════════════════════════════════════════════


@app.command(name="version")
def version_cmd() -> None:
    """Show version and environment info."""
    _print_banner()

    info_table = Table(
        show_header=False,
        box=box.ROUNDED,
        expand=False,
        padding=(0, 2),
    )
    info_table.add_column("Key", style="bold")
    info_table.add_column("Value")

    info_table.add_row("Version", __version__)
    info_table.add_row(
        "Python",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )

    console.print(info_table)
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  monitor
# ═══════════════════════════════════════════════════════════════════


@app.command()
def monitor(
    address: str = typer.Argument(
        ...,
        help="Contract address to monitor (checksummed or lowercase).",
    ),
    rpc: str = typer.Option(
        "http://localhost:8545",
        "--rpc",
        "-r",
        help="JSON-RPC endpoint (HTTP, HTTPS, WS, WSS).",
    ),
    poll_interval: float = typer.Option(
        2.0,
        "--poll-interval",
        "-p",
        help="Seconds between block polls.",
    ),
    alert_webhook: str | None = typer.Option(
        None,
        "--alert-webhook",
        "-w",
        help="Slack / Discord webhook URL for alert notifications.",
    ),
    severity: str = typer.Option(
        "INFO",
        "--severity",
        "-s",
        help="Minimum alert severity: CRITICAL, WARNING, INFO.",
    ),
    baseline_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--baseline",
        "-b",
        help="Path to a saved baseline profile JSON.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Live-monitor a deployed Vyper contract for suspicious activity."""
    setup_logging(verbose)
    _print_banner()

    try:
        from guardian.monitor.chain_watcher import ChainWatcher, Web3NotAvailableError
    except Exception as exc:
        console.print(f"[{ERR}]Error loading monitor module:[/{ERR}] {exc}")
        console.print(
            f"\n  [{DIM}]Install monitoring dependencies:[/{DIM}]  pip install vyper-guard[monitor]"
        )
        raise typer.Exit(code=2) from exc

    from guardian.models import AlertSeverity
    from guardian.monitor.alerting import AlertManager
    from guardian.monitor.pattern_matcher import PatternMatcher
    from guardian.monitor.tx_analyzer import TxAnalyzer

    try:
        min_sev = AlertSeverity(severity.upper())
    except ValueError:
        console.print(f"[{ERR}]Invalid severity:[/{ERR}] {severity}. Use CRITICAL, WARNING, INFO.")
        raise typer.Exit(code=2) from None

    try:
        watcher = ChainWatcher(
            contract_address=address,
            rpc_url=rpc,
            poll_interval=poll_interval,
        )
    except Web3NotAvailableError as exc:
        console.print(f"[{ERR}]{exc}[/{ERR}]")
        console.print(
            f"\n  [{DIM}]Install monitoring dependencies:[/{DIM}]  pip install vyper-guard[monitor]"
        )
        raise typer.Exit(code=2) from exc

    if not watcher.is_connected():
        console.print(f"[{ERR}]Cannot connect to RPC endpoint:[/{ERR}] {rpc}")
        raise typer.Exit(code=2)

    console.print(f"  [{OK}]Connected[/{OK}] to {rpc}  •  Block: {watcher.get_latest_block()}")

    tx_analyzer = TxAnalyzer()
    alert_mgr = AlertManager(
        webhook_url=alert_webhook,
        min_severity=min_sev,
        enable_console=True,
    )

    matcher = None
    if baseline_file and baseline_file.exists():
        data = _json.loads(baseline_file.read_text(encoding="utf-8"))
        from guardian.models import BaselineProfile

        baseline = BaselineProfile.model_validate(data)
        matcher = PatternMatcher(baseline)
        console.print(f"  [{ACCENT}]Baseline loaded — anomaly detection active[/{ACCENT}]")
    else:
        console.print(f"  [{WARN}]No baseline — monitoring without anomaly detection[/{WARN}]")

    def _on_tx(record):  # type: ignore[no-untyped-def]
        tx_analyzer.ingest(record)
        style = "green" if record.success else "red"
        console.print(
            f"  [{style}]Tx {record.tx_hash[:16]}… "
            f"gas={record.gas_used:,} value={record.value_wei}[/{style}]"
        )
        if matcher:
            alerts = matcher.check(record)
            alert_mgr.dispatch_many(alerts)

    watcher.on_transaction = _on_tx
    console.print(
        f"\n  [{ACCENT} bold]Monitoring {address}[/{ACCENT} bold]  •  "
        f"[dim]press Ctrl+C to stop[/dim]\n"
    )
    watcher.run_sync()


# ═══════════════════════════════════════════════════════════════════
#  baseline
# ═══════════════════════════════════════════════════════════════════


@app.command()
def baseline(
    address: str = typer.Argument(
        ...,
        help="Contract address to profile.",
    ),
    rpc: str = typer.Option(
        "http://localhost:8545",
        "--rpc",
        "-r",
        help="JSON-RPC endpoint.",
    ),
    duration: int = typer.Option(
        60,
        "--duration",
        "-d",
        help="Seconds to observe before saving the baseline.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "-o",
        help="Output file for the baseline JSON.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Build a normal-behaviour baseline for a deployed contract."""
    setup_logging(verbose)
    _print_banner()

    try:
        from guardian.monitor.chain_watcher import ChainWatcher, Web3NotAvailableError
    except Exception as exc:
        console.print(f"[{ERR}]Error loading monitor module:[/{ERR}] {exc}")
        console.print(
            f"\n  [{DIM}]Install monitoring dependencies:[/{DIM}]  pip install vyper-guard[monitor]"
        )
        raise typer.Exit(code=2) from exc

    from guardian.monitor.baseline import BaselineProfiler

    try:
        watcher = ChainWatcher(
            contract_address=address,
            rpc_url=rpc,
            poll_interval=2.0,
        )
    except Web3NotAvailableError as exc:
        console.print(f"[{ERR}]{exc}[/{ERR}]")
        raise typer.Exit(code=2) from exc

    if not watcher.is_connected():
        console.print(f"[{ERR}]Cannot connect to RPC endpoint:[/{ERR}] {rpc}")
        raise typer.Exit(code=2)

    profiler = BaselineProfiler(
        contract_address=address,
        storage_dir=output.parent if output else None,
    )

    def _on_tx(record):  # type: ignore[no-untyped-def]
        profiler.ingest(record)
        console.print(f"    [{DIM}]Tx {record.tx_hash[:16]}…[/{DIM}]")

    watcher.on_transaction = _on_tx

    console.print(
        f"  [{ACCENT} bold]Building baseline for {address}[/{ACCENT} bold]\n"
        f"  [{DIM}]Observing for {duration}s…[/{DIM}]\n"
    )

    start = _time.monotonic()
    try:
        while _time.monotonic() - start < duration:
            watcher.poll_once()
            _time.sleep(min(2.0, max(0.5, duration / 30)))
    except KeyboardInterrupt:
        console.print(f"\n  [{WARN}]Interrupted early.[/{WARN}]")

    profile = profiler.build()

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"\n  [{OK}]Baseline saved →[/{OK}] {output}")
    else:
        saved = profiler.save(profile)
        console.print(f"\n  [{OK}]Baseline saved →[/{OK}] {saved}")

    console.print(f"    Transactions observed: {profile.tx_count}")
    console.print(f"    Avg gas: {profile.avg_gas:,.0f}  |  Std gas: {profile.std_gas:,.0f}")
    console.print(f"    Failed tx ratio: {profile.failed_tx_ratio:.2%}")
    console.print()
