"""Vyper Guard — CLI interface.

Built with Typer + Rich for a polished developer experience.
Works cross-platform on Linux, macOS, and Windows.
"""

from __future__ import annotations

import contextlib
import html as _html
import json as _json
import math
import re
import sys
import time as _time
from collections import Counter
from pathlib import Path

import typer
import yaml
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
from guardian.analyzer.ai_triage import apply_ai_triage
from guardian.analyzer.benchmark import run_corpus_benchmark
from guardian.analyzer.static import StaticAnalyzer
from guardian.analyzer.vyper_detector import list_detectors as _list_detectors
from guardian.models import AnalysisReport, Confidence, DetectorResult, Severity, VulnerabilityType
from guardian.reporting.formatter import print_report  # noqa: F401  - public API
from guardian.reporting.json_exporter import export_json
from guardian.reporting.markdown_exporter import export_markdown
from guardian.utils.config import load_config
from guardian.utils.helpers import FileLoadError, GuardianError
from guardian.utils.logger import setup_logging

# ── Branded colours ──────────────────────────────────────────────
ACCENT = "#7f56d9"
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
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Sub-command groups
ai_app = typer.Typer(help="AI orchestration controls.")
ai_config_app = typer.Typer(help="Manage AI configuration.")
ai_app.add_typer(ai_config_app, name="config")
app.add_typer(ai_app, name="ai")


@ai_app.callback(invoke_without_command=True)
def ai_root(ctx: typer.Context) -> None:
    """AI orchestration controls."""
    if ctx.invoked_subcommand is None:
        table = Table(title="AI Commands", box=box.SIMPLE_HEAVY)
        table.add_column("Command", style=f"bold {ACCENT}")
        table.add_column("Purpose")
        table.add_row("vyper-guard ai config show", "Show effective AI provider/model settings")
        table.add_row("vyper-guard ai config set provider <name>", "Set AI provider")
        table.add_row("vyper-guard ai config set model <name>", "Set model override")
        table.add_row("vyper-guard ai config set api-key", "Store/redact API key in user config")
        console.print(table)
        console.print(
            f"[{DIM}]Tip:[/{DIM}] run [bold]vyper-guard agent -h[/bold] for prompt, file, and address usage."
        )
        raise typer.Exit(code=0)


# ═══════════════════════════════════════════════════════════════════
#  Branded output helpers
# ═══════════════════════════════════════════════════════════════════

# Large block-letter logo — the face of the tool.
_LOGO = """[bold #7f56d9]
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
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝[/bold #7f56d9]"""

# Compact logo for sub-commands — same block-letter style, clean proportions.
_LOGO_COMPACT = """[bold #7f56d9]
 ██╗   ██╗██╗   ██╗██████╗ ███████╗██████╗
 ██║   ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║   ██║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ╚██╗ ██╔╝  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗
  ╚████╔╝    ██║   ██║     ███████╗██║  ██║
   ╚═══╝     ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝
     ━━━━  [bold white]G  U  A  R  D[/bold white]  ━━━━[/bold #7f56d9]"""

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

_RISK_TIER_ORDER: dict[str, int] = {"A": 1, "B": 2, "C": 3}


def _resolve_ai_triage_settings(
    *,
    cfg,
    ai: bool,
    ai_triage: bool | None,
    ai_triage_min_severity: str | None,
    ai_triage_max_items: int | None,
    ai_triage_mode: str | None,
    ai_allow_fallback: bool,
) -> tuple[bool, Severity, int, str, bool]:
    """Resolve canonical AI-triage execution settings."""
    triage_enabled = True if ai else (ai_triage if ai_triage is not None else cfg.ai_triage.enabled)

    triage_min_name = (ai_triage_min_severity or cfg.ai_triage.min_severity).upper()
    try:
        triage_min = Severity(triage_min_name)
    except ValueError:
        console.print(f"[{ERR}]Invalid ai-triage minimum severity: {triage_min_name}[/{ERR}]")
        raise typer.Exit(code=2) from None

    triage_max_items = ai_triage_max_items or cfg.ai_triage.max_items

    if ai_triage_mode is not None:
        triage_mode = ai_triage_mode.strip().lower()
    elif ai:
        has_llm_config = bool(cfg.llm.enabled or (cfg.llm.api_key and str(cfg.llm.api_key).strip()))
        triage_mode = "llm" if has_llm_config else "deterministic"
    else:
        triage_mode = "deterministic"

    if triage_mode not in {"deterministic", "llm"}:
        console.print(
            f"[{ERR}]Invalid ai-triage mode: {triage_mode}. Use deterministic or llm.[/{ERR}]"
        )
        raise typer.Exit(code=2)

    fallback_allowed = ai_allow_fallback or (ai and ai_triage_mode is None)
    return triage_enabled, triage_min, triage_max_items, triage_mode, fallback_allowed


def _apply_deterministic_triage(
    report: AnalysisReport, *, cfg, triage_min: Severity, triage_max_items: int
) -> None:
    deprecation_sunset_after = cfg.ai_triage.deprecation_sunset_after
    apply_ai_triage(
        report,
        max_items=triage_max_items,
        min_severity=triage_min,
        policy_status=cfg.ai_triage.policy_status,
        deprecation_announced=cfg.ai_triage.deprecation_announced,
        deprecation_sunset_after=(
            str(deprecation_sunset_after) if deprecation_sunset_after is not None else None
        ),
    )


def _annotate_llm_fallback(report: AnalysisReport, reason: str) -> None:
    """Record explicit fallback provenance when LLM triage degrades to deterministic mode."""
    policy = report.ai_triage_policy if isinstance(report.ai_triage_policy, dict) else {}
    warnings = policy.get("warnings", [])
    if not isinstance(warnings, list):
        warnings = []
    warnings.append(f"LLM triage fallback activated: {reason}")
    policy["warnings"] = warnings
    policy["fallback_reason"] = reason
    policy["fallback_from"] = "llm"
    report.ai_triage_policy = policy


def _user_config_path() -> Path:
    return Path.home() / ".guardianrc"


def _load_user_config_yaml() -> dict[str, object]:
    path = _user_config_path()
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _save_user_config_yaml(data: dict[str, object]) -> None:
    path = _user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def _set_user_config_value(section: str, key: str, value: object) -> None:
    data = _load_user_config_yaml()
    section_obj = data.setdefault(section, {})
    if not isinstance(section_obj, dict):
        section_obj = {}
        data[section] = section_obj
    section_obj[key] = value
    _save_user_config_yaml(data)


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
    # Restore the large logo users expect on root command.
    console.print(_LOGO)
    console.print(
        f"  [bold white]v{__version__}[/bold white]  "
        f"[dim]|[/dim]  [dim]Vyper smart contract security toolkit[/dim]"
    )
    console.print()

    groups = Table(show_header=True, header_style="bold bright_white", box=box.SIMPLE_HEAVY)
    groups.add_column("Workflow", style="bold bright_cyan", width=24)
    groups.add_column("Commands", style="white")
    groups.add_row("Analyze", "analyze, scan, ast, flow, fix, diff, stats")
    groups.add_row("Deployed Contracts", "explorer, analyze-address")
    groups.add_row("AI", "ai config, agent, agent-memory")
    groups.add_row("Operations", "detectors, benchmark, init, baseline, monitor, version")

    quick = Text.from_markup(
        "[bold]Quick Start[/bold]\n\n"
        "[dim]1)[/dim] [bold white]vyper-guard analyze contract.vy[/bold white]\n"
        "[dim]2)[/dim] [bold white]vyper-guard analyze contract.vy --ai[/bold white]\n"
        "[dim]3)[/dim] [bold white]vyper-guard stats contract.vy --graph[/bold white]\n"
        "[dim]4)[/dim] [bold white]vyper-guard analyze-address 0x... --provider auto[/bold white]\n"
        "[dim]5)[/dim] [bold white]vyper-guard analyze contract.vy -f json -o report.json[/bold white]"
    )

    console.print(
        Columns(
            [
                Panel(
                    groups, title="[bold]Command Map[/bold]", border_style=ACCENT, box=box.ROUNDED
                ),
                Panel(quick, title="[bold]Examples[/bold]", border_style=ACCENT, box=box.ROUNDED),
            ],
            equal=True,
            expand=True,
        )
    )
    console.print()
    console.print(
        Panel(
            Text.from_markup(
                "[bold white]Tips[/bold white]\n"
                "• Use [bold]vyper-guard <command> -h[/bold] for command-specific options\n"
                "• CLI output is on [bold]stderr[/bold], JSON/Markdown outputs stay clean on [bold]stdout[/bold]\n"
                "• Docs: [underline]https://github.com/preethamak/vyper[/underline]"
            ),
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 1),
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

    # Reject files with only comments/whitespace because they cannot be analysed meaningfully.
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    code_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not code_lines:
        console.print(
            Panel(
                f"[{ERR}]No contract code found (only comments/blank lines).[/{ERR}]\n\n"
                f"  File: {file_path}\n\n"
                "  [dim]Add Vyper declarations (state vars, functions, interfaces, etc.) and try again.[/dim]",
                title="[bold red]No Contract Code[/bold red]",
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
    file_path: Path = typer.Argument(
        ...,
        help="Path to the .vy contract to analyse.",
        exists=True,
        readable=True,
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: cli, json, markdown (default from config if set).",
    ),
    output: Path | None = typer.Option(
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
    severity_threshold: str | None = typer.Option(
        None,
        "--severity-threshold",
        "-s",
        help="Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO (default from config if set).",
    ),
    config: Path | None = typer.Option(
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
    fix_dry_run: bool = typer.Option(
        False,
        "--fix-dry-run",
        help="Preview auto-remediation output without writing any patched file.",
    ),
    fix_report: Path | None = typer.Option(
        None,
        "--fix-report",
        help="Write remediation planning/execution report as JSON (requires --fix or --fix-dry-run).",
    ),
    max_auto_fix_tier: str | None = typer.Option(
        None,
        "--max-auto-fix-tier",
        help="Maximum remediation risk tier to auto-apply (A, B, C; default from config if set).",
    ),
    ai_triage: bool | None = typer.Option(
        None,
        "--ai-triage/--no-ai-triage",
        help="Enable/disable optional AI-assisted triage metadata (post-processor; does not alter findings).",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable AI-assisted audit orchestration (preferred alias for AI triage mode).",
    ),
    ai_triage_min_severity: str | None = typer.Option(
        None,
        "--ai-triage-min-severity",
        help="Minimum severity to include in triage: CRITICAL, HIGH, MEDIUM, LOW, INFO (default from config if set).",
    ),
    ai_triage_max_items: int | None = typer.Option(
        None,
        "--ai-triage-max-items",
        min=1,
        help="Maximum number of triage items to emit (default from config if set).",
    ),
    ai_triage_mode: str | None = typer.Option(
        None,
        "--ai-triage-mode",
        help="AI triage mode: deterministic | llm (default from config if set).",
    ),
    ai_llm_model: str | None = typer.Option(
        None,
        "--ai-llm-model",
        help="Override LLM model for --ai-triage-mode llm.",
    ),
    ai_allow_fallback: bool = typer.Option(
        False,
        "--allow-ai-fallback",
        help="Allow deterministic fallback when LLM triage fails (disabled by default).",
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
    threshold_name = (severity_threshold or cfg.analysis.severity_threshold).upper()
    try:
        threshold = Severity(threshold_name)
    except ValueError:
        console.print(f"[{ERR}]Invalid severity threshold: {threshold_name}[/{ERR}]")
        raise typer.Exit(code=2) from None

    # Run analysis with a progress bar
    analyzer = StaticAnalyzer(
        enabled_detectors=enabled,
        disabled_detectors=cfg.analysis.disabled_detectors,
        severity_threshold=threshold,
    )

    fmt = (format or cfg.reporting.default_format).lower()
    if fmt not in {"cli", "json", "markdown"}:
        console.print(f"[{ERR}]Invalid format: {fmt}. Use one of: cli, json, markdown.[/{ERR}]")
        raise typer.Exit(code=2)

    def _build_runtime_fallback_report(error: Exception) -> AnalysisReport:
        return AnalysisReport(
            file_path=str(file_path),
            vyper_version=None,
            findings=[
                DetectorResult(
                    detector_name="analyzer_runtime_error",
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    vulnerability_type=VulnerabilityType.CODE_QUALITY,
                    title="Analysis fallback mode",
                    description=(
                        "Vyper Guard encountered an unexpected analyzer runtime error and returned "
                        "a best-effort fallback report so output remains structured. "
                        "Treat this contract as requiring manual review."
                    ),
                    line_number=None,
                    fix_suggestion=(
                        "Retry with --verbose and share the failing contract snippet with maintainers."
                    ),
                    why_flagged="Analyzer runtime exception prevented full detector execution.",
                    evidence=[f"{type(error).__name__}: {error}"],
                    why_not_suppressed="Fallback finding is intentionally always emitted to avoid silent pass.",
                )
            ],
            detectors_run=["analyzer_runtime_error"],
            security_score=0,
        )

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
    except Exception as exc:
        elapsed_ms = (_time.perf_counter() - t0) * 1000
        report = _build_runtime_fallback_report(exc)
        console.print(
            f"[{WARN}]Analyzer fallback:[/{WARN}] encountered runtime error; returning structured best-effort output."
        )

    # Optional AI-assisted triage post-processor (deterministic, verdict-preserving).
    triage_enabled, triage_min, triage_max_items, triage_mode, fallback_allowed = (
        _resolve_ai_triage_settings(
            cfg=cfg,
            ai=ai,
            ai_triage=ai_triage,
            ai_triage_min_severity=ai_triage_min_severity,
            ai_triage_max_items=ai_triage_max_items,
            ai_triage_mode=ai_triage_mode,
            ai_allow_fallback=ai_allow_fallback,
        )
    )
    if triage_enabled:
        if triage_mode == "llm":
            from guardian.agents.llm_triage import LLMTriageError, apply_llm_triage

            llm_model = ai_llm_model or cfg.llm.model
            llm_key = cfg.llm.api_key or ""
            try:
                apply_llm_triage(
                    report,
                    file_path.read_text(encoding="utf-8"),
                    api_key=llm_key,
                    model=llm_model,
                    provider=cfg.llm.provider,
                    base_url=cfg.llm.base_url,
                    min_severity=triage_min,
                    max_items=triage_max_items,
                    temperature=cfg.llm.temperature,
                )
            except LLMTriageError as exc:
                if not fallback_allowed:
                    console.print(
                        f"[{ERR}]LLM triage failed:[/{ERR}] {exc}. "
                        "Re-run with --allow-ai-fallback to enable deterministic fallback."
                    )
                    raise typer.Exit(code=2) from exc
                console.print(
                    f"[{WARN}]LLM triage unavailable:[/{WARN}] {exc} — falling back to deterministic triage (--allow-ai-fallback)."
                )
                _apply_deterministic_triage(
                    report,
                    cfg=cfg,
                    triage_min=triage_min,
                    triage_max_items=triage_max_items,
                )
                _annotate_llm_fallback(report, str(exc))
        else:
            _apply_deterministic_triage(
                report,
                cfg=cfg,
                triage_min=triage_min,
                triage_max_items=triage_max_items,
            )

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
    if fix_dry_run and not fix:
        fix = True

    if fix and report.findings:
        max_tier = (max_auto_fix_tier or cfg.remediation.max_auto_fix_tier).upper()
        if max_tier not in _RISK_TIER_ORDER:
            console.print(f"[{ERR}]Invalid max auto-fix tier: {max_tier}. Use A, B, or C.[/{ERR}]")
            raise typer.Exit(code=2)
        remediation_report = _run_fix_mode(
            file_path,
            report,
            console,
            max_auto_fix_tier=max_tier,
            dry_run=fix_dry_run,
        )
        if fix_report:
            fix_report.parent.mkdir(parents=True, exist_ok=True)
            fix_report.write_text(
                _json.dumps(remediation_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            console.print(f"[{OK}]Remediation report written:[/{OK}] [bold]{fix_report}[/bold]")

    if fix_report and not fix:
        console.print(f"[{ERR}]--fix-report requires --fix or --fix-dry-run.[/{ERR}]")
        raise typer.Exit(code=2)

    # CI exit code
    if ci and report.findings:
        raise typer.Exit(code=1)


# ═══════════════════════════════════════════════════════════════════
#  scan — alias for analyze (friendlier name for public users)
# ═══════════════════════════════════════════════════════════════════


@app.command(hidden=True)
def scan(
    file_path: Path = typer.Argument(
        ...,
        help="Path to the .vy contract to analyse.",
        exists=True,
        readable=True,
    ),
    format: str | None = typer.Option(None, "--format", "-f"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    detectors: str | None = typer.Option(None, "--detectors", "-d"),
    severity_threshold: str | None = typer.Option(None, "--severity-threshold", "-s"),
    config: Path | None = typer.Option(None, "--config", "-c"),
    ci: bool = typer.Option(False, "--ci"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    fix: bool = typer.Option(False, "--fix"),
    fix_dry_run: bool = typer.Option(False, "--fix-dry-run"),
    fix_report: Path | None = typer.Option(None, "--fix-report"),
    max_auto_fix_tier: str | None = typer.Option(None, "--max-auto-fix-tier"),
    ai_triage: bool | None = typer.Option(None, "--ai-triage/--no-ai-triage"),
    ai: bool = typer.Option(False, "--ai"),
    ai_triage_min_severity: str | None = typer.Option(None, "--ai-triage-min-severity"),
    ai_triage_max_items: int | None = typer.Option(None, "--ai-triage-max-items", min=1),
    ai_triage_mode: str | None = typer.Option(None, "--ai-triage-mode"),
    ai_llm_model: str | None = typer.Option(None, "--ai-llm-model"),
    ai_allow_fallback: bool = typer.Option(False, "--allow-ai-fallback"),
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
        fix_dry_run=fix_dry_run,
        fix_report=fix_report,
        max_auto_fix_tier=max_auto_fix_tier,
        ai_triage=ai_triage,
        ai=ai,
        ai_triage_min_severity=ai_triage_min_severity,
        ai_triage_max_items=ai_triage_max_items,
        ai_triage_mode=ai_triage_mode,
        ai_llm_model=ai_llm_model,
        ai_allow_fallback=ai_allow_fallback,
    )


@ai_config_app.command(name="set")
def ai_config_set(
    key: str = typer.Argument(
        ..., help="Config key: provider | model | api-key | base-url | enabled."
    ),
    value: str | None = typer.Argument(
        None, help="Config value. Omit for interactive secret prompt for api-key."
    ),
) -> None:
    """Set user-level AI config in ~/.guardianrc."""
    normalized = key.strip().lower()
    key_map = {
        "provider": "provider",
        "model": "model",
        "api-key": "api_key",
        "base-url": "base_url",
        "enabled": "enabled",
    }
    if normalized not in key_map:
        console.print(
            f"[{ERR}]Unsupported ai config key:[/{ERR}] {key}. "
            "Use provider, model, api-key, base-url, or enabled."
        )
        raise typer.Exit(code=2)

    target_key = key_map[normalized]
    resolved: object
    if normalized == "api-key":
        if value is None:
            value = typer.prompt("Enter AI API key", hide_input=True, confirmation_prompt=True)
        resolved = value.strip()
        if not resolved:
            console.print(f"[{ERR}]API key cannot be empty.[/{ERR}]")
            raise typer.Exit(code=2)
    elif normalized == "enabled":
        text = (value or "").strip().lower()
        if text not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
            console.print(f"[{ERR}]enabled expects true/false.[/{ERR}]")
            raise typer.Exit(code=2)
        resolved = text in {"1", "true", "yes", "on"}
    else:
        if value is None or not value.strip():
            console.print(f"[{ERR}]Missing value for key:[/{ERR}] {key}")
            raise typer.Exit(code=2)
        resolved = value.strip()

    _set_user_config_value("llm", target_key, resolved)
    if normalized == "provider":
        provider_value = str(resolved).strip().lower()
        if provider_value in {"gemini", "google", "google_gemini"}:
            # Apply Gemini OpenAI-compatible defaults for immediate usability.
            _set_user_config_value(
                "llm", "base_url", "https://generativelanguage.googleapis.com/v1beta/openai"
            )
            current = load_config().llm.model
            if current.startswith("gpt-"):
                _set_user_config_value("llm", "model", "gemini-2.0-flash")

    if normalized == "api-key":
        # Setting an API key should make AI features immediately usable.
        _set_user_config_value("llm", "enabled", True)
    if normalized == "api-key":
        console.print(
            f"[{OK}]AI API key saved to user config:[/{OK}] [bold]{_user_config_path()}[/bold] "
            f"[{WARN}](consider env/keyring for stronger secret hygiene)[/{WARN}]"
        )
    else:
        console.print(
            f"[{OK}]AI config updated:[/{OK}] llm.{target_key} = {resolved} "
            f"([bold]{_user_config_path()}[/bold])"
        )


@ai_config_app.command(name="show")
def ai_config_show() -> None:
    """Show effective AI config (API key redacted)."""
    cfg = load_config()
    api_key = cfg.llm.api_key or ""
    redacted = ""
    if api_key:
        redacted = (api_key[:4] + "..." + api_key[-4:]) if len(api_key) > 8 else "***"

    payload = {
        "provider": cfg.llm.provider,
        "model": cfg.llm.model,
        "base_url": cfg.llm.base_url,
        "enabled": cfg.llm.enabled,
        "temperature": cfg.llm.temperature,
        "max_items": cfg.llm.max_items,
        "memory_file": cfg.llm.memory_file,
        "memory_max_entries": cfg.llm.memory_max_entries,
        "api_key_set": bool(api_key),
        "api_key": redacted,
        "user_config_path": str(_user_config_path()),
    }
    typer.echo(_json.dumps(payload, indent=2, ensure_ascii=False))


def _infer_internal_call_edges(
    function_names: list[str], body_text: str, caller: str
) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for name in function_names:
        if name == caller:
            continue
        if re.search(rf"\b{name}\s*\(", body_text):
            edges.append((caller, name))
    return edges


@app.command(name="ast")
def ast_view(
    file_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to the .vy contract."
    ),
    format: str = typer.Option(
        "cli", "--format", "-f", help="Output format: cli, json, markdown, mermaid."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write output artifact to file."
    ),
) -> None:
    """Show parsed contract structure (AST-like summary)."""
    _validate_contract_path(file_path)
    from guardian.analyzer.ast_parser import parse_vyper_source
    from guardian.utils.helpers import load_vyper_source

    source = load_vyper_source(file_path)
    contract = parse_vyper_source(source, str(file_path))

    payload = {
        "file_path": str(file_path),
        "pragma_version": contract.pragma_version,
        "imports": contract.imports,
        "state_variables": [
            {
                "name": v.name,
                "type": v.type_annotation,
                "line": v.line_number,
                "public": v.is_public,
                "constant": v.is_constant,
                "immutable": v.is_immutable,
            }
            for v in contract.state_variables
        ],
        "events": [
            {
                "name": e.name,
                "line": e.line_number,
                "fields": e.fields,
            }
            for e in contract.events
        ],
        "functions": [
            {
                "name": f.name,
                "decorators": f.decorators,
                "args": f.args,
                "return_type": f.return_type,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "is_external": f.is_external,
                "is_view": f.is_view,
                "is_nonreentrant": f.is_nonreentrant,
            }
            for f in contract.functions
        ],
    }

    fmt = format.lower()
    if fmt not in {"cli", "json", "markdown", "mermaid"}:
        console.print(f"[{ERR}]Invalid format: {format}. Use cli, json, markdown, mermaid.[/{ERR}]")
        raise typer.Exit(code=2)

    if fmt == "json":
        text = _json.dumps(payload, indent=2, ensure_ascii=False)
    elif fmt == "markdown":
        lines = [
            f"# AST View — {file_path.name}",
            "",
            f"- Pragma: `{contract.pragma_version or 'unknown'}`",
            f"- Imports: {len(contract.imports)}",
            f"- State variables: {len(contract.state_variables)}",
            f"- Events: {len(contract.events)}",
            f"- Functions: {len(contract.functions)}",
            "",
            "## Functions",
            "",
        ]
        for func in contract.functions:
            lines.append(
                f"- `{func.name}` lines {func.start_line}-{func.end_line} decorators={func.decorators or []}"
            )
        text = "\n".join(lines)
    elif fmt == "mermaid":
        lines = ["graph TD", "  Contract[Contract]"]
        for sv in contract.state_variables:
            node = f"SV_{sv.name}"
            lines.append(f"  {node}[state: {sv.name}]")
            lines.append(f"  Contract --> {node}")
        for ev in contract.events:
            node = f"EV_{ev.name}"
            lines.append(f"  {node}[event: {ev.name}]")
            lines.append(f"  Contract --> {node}")
        for fn in contract.functions:
            node = f"FN_{fn.name}"
            lines.append(f"  {node}[fn: {fn.name}]")
            lines.append(f"  Contract --> {node}")
        text = "\n".join(lines)
    else:
        table = Table(title=f"AST View — {file_path.name}", box=box.SIMPLE_HEAVY)
        table.add_column("Item", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("Imports", str(len(contract.imports)))
        table.add_row("State variables", str(len(contract.state_variables)))
        table.add_row("Events", str(len(contract.events)))
        table.add_row("Functions", str(len(contract.functions)))
        console.print(table)
        text = ""

    if output and fmt != "cli":
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    elif fmt != "cli":
        typer.echo(text)


@app.command(name="flow")
def flow_view(
    file_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to the .vy contract."
    ),
    format: str = typer.Option(
        "cli", "--format", "-f", help="Output format: cli, json, markdown, mermaid."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write output artifact to file."
    ),
) -> None:
    """Show function/call-flow summary using semantic extraction."""
    _validate_contract_path(file_path)
    from guardian.analyzer.ast_parser import parse_vyper_source
    from guardian.analyzer.semantic import build_semantic_summary
    from guardian.utils.helpers import load_vyper_source

    source = load_vyper_source(file_path)
    contract = parse_vyper_source(source, str(file_path))
    summary = build_semantic_summary(contract)

    fn_names = [f.name for f in contract.functions]
    edges: list[tuple[str, str]] = []
    for fn in contract.functions:
        edges.extend(_infer_internal_call_edges(fn_names, fn.body_text, fn.name))

    payload = {
        "file_path": str(file_path),
        "functions": [
            {
                "name": f.name,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "internal_calls": [dst for src, dst in edges if src == f.name],
                "state_reads": sorted(summary.functions.get(f.name).state_reads)
                if f.name in summary.functions
                else [],
                "state_writes": sorted(summary.functions.get(f.name).state_writes)
                if f.name in summary.functions
                else [],
                "external_calls": summary.functions.get(f.name).external_calls
                if f.name in summary.functions
                else 0,
                "external_calls_in_loop": summary.functions.get(f.name).external_calls_in_loop
                if f.name in summary.functions
                else False,
                "emits_event": summary.functions.get(f.name).emits_event
                if f.name in summary.functions
                else False,
            }
            for f in contract.functions
        ],
        "edges": [{"from": src, "to": dst} for src, dst in sorted(set(edges))],
    }

    fmt = format.lower()
    if fmt not in {"cli", "json", "markdown", "mermaid"}:
        console.print(f"[{ERR}]Invalid format: {format}. Use cli, json, markdown, mermaid.[/{ERR}]")
        raise typer.Exit(code=2)

    if fmt == "json":
        text = _json.dumps(payload, indent=2, ensure_ascii=False)
    elif fmt == "markdown":
        lines = [f"# Flow View — {file_path.name}", "", "## Functions", ""]
        for item in payload["functions"]:
            lines.append(
                f"- `{item['name']}` calls={item['internal_calls']} ext_calls={item['external_calls']} "
                f"reads={item['state_reads']} writes={item['state_writes']}"
            )
        text = "\n".join(lines)
    elif fmt == "mermaid":
        lines = ["graph TD"]
        for fn in fn_names:
            lines.append(f"  {fn}[{fn}]")
        for src, dst in sorted(set(edges)):
            lines.append(f"  {src} --> {dst}")
        if not edges:
            lines.append("  note[No internal function-call edges detected]")
        text = "\n".join(lines)
    else:
        table = Table(title=f"Flow View — {file_path.name}", box=box.SIMPLE_HEAVY)
        table.add_column("Function", style="bold")
        table.add_column("Internal calls")
        table.add_column("External calls", justify="right")
        table.add_column("Writes")
        for item in payload["functions"]:
            table.add_row(
                str(item["name"]),
                ", ".join(item["internal_calls"]) or "—",
                str(item["external_calls"]),
                ", ".join(item["state_writes"]) or "—",
            )
        console.print(table)
        text = ""

    if output and fmt != "cli":
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    elif fmt != "cli":
        typer.echo(text)


@app.command(name="fix")
def fix_cmd(
    file_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to the .vy contract."
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Enable AI-assisted audit orchestration before remediation."
    ),
    format: str | None = typer.Option(None, "--format", "-f"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    detectors: str | None = typer.Option(None, "--detectors", "-d"),
    severity_threshold: str | None = typer.Option(None, "--severity-threshold", "-s"),
    config: Path | None = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    fix_dry_run: bool = typer.Option(False, "--fix-dry-run"),
    fix_report: Path | None = typer.Option(None, "--fix-report"),
    max_auto_fix_tier: str | None = typer.Option(None, "--max-auto-fix-tier"),
    ai_triage: bool | None = typer.Option(None, "--ai-triage/--no-ai-triage"),
    ai_triage_min_severity: str | None = typer.Option(None, "--ai-triage-min-severity"),
    ai_triage_max_items: int | None = typer.Option(None, "--ai-triage-max-items", min=1),
    ai_triage_mode: str | None = typer.Option(None, "--ai-triage-mode"),
    ai_llm_model: str | None = typer.Option(None, "--ai-llm-model"),
    ai_allow_fallback: bool = typer.Option(
        False,
        "--allow-ai-fallback",
        help="Allow deterministic fallback when LLM triage fails (disabled by default).",
    ),
) -> None:
    """Dedicated remediation command with tier-safe fix pipeline."""
    analyze(
        file_path=file_path,
        format=format,
        output=output,
        detectors=detectors,
        severity_threshold=severity_threshold,
        config=config,
        ci=False,
        verbose=verbose,
        fix=True,
        fix_dry_run=fix_dry_run,
        fix_report=fix_report,
        max_auto_fix_tier=max_auto_fix_tier,
        ai_triage=ai_triage,
        ai=ai,
        ai_triage_min_severity=ai_triage_min_severity,
        ai_triage_max_items=ai_triage_max_items,
        ai_triage_mode=ai_triage_mode,
        ai_llm_model=ai_llm_model,
        ai_allow_fallback=ai_allow_fallback,
    )


@app.command(name="analyze-address")
def analyze_address(
    address: str = typer.Argument(
        ..., help="Contract address to analyze via block explorer source."
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="Explorer provider (default from config)."
    ),
    network: str | None = typer.Option(
        None, "--network", help="Network name (default from config)."
    ),
    api_key: str | None = typer.Option(None, "--api-key", help="Explorer API key (or config/env)."),
    format: str | None = typer.Option(
        None, "--format", "-f", help="Output format: cli, json, markdown."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to this file."),
    save_source: Path | None = typer.Option(
        None, "--save-source", help="Persist fetched source to file."
    ),
    detectors: str | None = typer.Option(
        None, "--detectors", "-d", help="Comma-separated detector names."
    ),
    severity_threshold: str | None = typer.Option(None, "--severity-threshold", "-s"),
    ci: bool = typer.Option(False, "--ci"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable AI-assisted audit orchestration (preferred alias for AI triage mode).",
    ),
    ai_triage: bool | None = typer.Option(None, "--ai-triage/--no-ai-triage"),
    ai_triage_min_severity: str | None = typer.Option(None, "--ai-triage-min-severity"),
    ai_triage_max_items: int | None = typer.Option(None, "--ai-triage-max-items", min=1),
    ai_triage_mode: str | None = typer.Option(None, "--ai-triage-mode"),
    ai_llm_model: str | None = typer.Option(None, "--ai-llm-model"),
    ai_allow_fallback: bool = typer.Option(
        False,
        "--allow-ai-fallback",
        help="Allow deterministic fallback when LLM triage fails (disabled by default).",
    ),
) -> None:
    """Analyze a deployed contract address by fetching verified source from explorer."""
    setup_logging(verbose)
    from guardian.explorer.client import ExplorerClient, ExplorerError

    cfg = load_config(None)
    selected_provider = (provider or cfg.explorer.provider).strip().lower()
    selected_network = (network or cfg.explorer.network).strip().lower()
    selected_api_key = api_key or cfg.explorer.api_key

    if provider is None and selected_provider == "etherscan":
        selected_provider = "etherscan,blockscout,sourcify"
        console.print(
            f"[{WARN}]Explorer provider defaulted to fallback chain:[/{WARN}] "
            "etherscan,blockscout,sourcify"
        )

    try:
        info = ExplorerClient(
            provider=selected_provider,
            network=selected_network,
            api_key=selected_api_key,
        ).fetch_contract(address)
    except ExplorerError as exc:
        console.print(f"[{ERR}]Explorer lookup failed:[/{ERR}] {exc}")
        console.print(
            f"[{DIM}]Try:[/{DIM}]\n"
            "  • Use a verified contract address\n"
            "  • Override provider chain: --provider etherscan,blockscout,sourcify\n"
            "  • Specify network explicitly: --network ethereum\n"
            "  • Configure key when needed: vyper-guard explorer config set api-key <key>"
        )
        raise typer.Exit(code=2) from exc

    if not info.source_code:
        console.print(f"[{ERR}]No verified source code available for address:[/{ERR}] {address}")
        raise typer.Exit(code=2)

    if save_source:
        save_source.parent.mkdir(parents=True, exist_ok=True)
        save_source.write_text(info.source_code, encoding="utf-8")

    enabled = ["all"]
    if detectors:
        enabled = [d.strip() for d in detectors.split(",")]
    elif cfg.analysis.enabled_detectors != ["all"]:
        enabled = cfg.analysis.enabled_detectors

    threshold_name = (severity_threshold or cfg.analysis.severity_threshold).upper()
    try:
        threshold = Severity(threshold_name)
    except ValueError:
        console.print(f"[{ERR}]Invalid severity threshold: {threshold_name}[/{ERR}]")
        raise typer.Exit(code=2) from None

    analyzer = StaticAnalyzer(
        enabled_detectors=enabled,
        disabled_detectors=cfg.analysis.disabled_detectors,
        severity_threshold=threshold,
    )

    fmt = (format or cfg.reporting.default_format).lower()
    if fmt not in {"cli", "json", "markdown"}:
        console.print(f"[{ERR}]Invalid format: {fmt}. Use one of: cli, json, markdown.[/{ERR}]")
        raise typer.Exit(code=2)

    t0 = _time.perf_counter()
    report = analyzer.analyze_source(
        info.source_code,
        file_path=f"explorer://{selected_network}/{address}",
    )
    report.vyper_version = report.vyper_version or info.compiler_version
    elapsed_ms = (_time.perf_counter() - t0) * 1000

    triage_enabled, triage_min, triage_max_items, triage_mode, fallback_allowed = (
        _resolve_ai_triage_settings(
            cfg=cfg,
            ai=ai,
            ai_triage=ai_triage,
            ai_triage_min_severity=ai_triage_min_severity,
            ai_triage_max_items=ai_triage_max_items,
            ai_triage_mode=ai_triage_mode,
            ai_allow_fallback=ai_allow_fallback,
        )
    )
    if triage_enabled:
        if triage_mode == "llm":
            from guardian.agents.llm_triage import LLMTriageError, apply_llm_triage

            llm_model = ai_llm_model or cfg.llm.model
            llm_key = cfg.llm.api_key or ""
            try:
                apply_llm_triage(
                    report,
                    info.source_code,
                    api_key=llm_key,
                    model=llm_model,
                    provider=cfg.llm.provider,
                    base_url=cfg.llm.base_url,
                    min_severity=triage_min,
                    max_items=triage_max_items,
                    temperature=cfg.llm.temperature,
                )
            except LLMTriageError as exc:
                if not fallback_allowed:
                    console.print(
                        f"[{ERR}]LLM triage failed:[/{ERR}] {exc}. "
                        "Re-run with --allow-ai-fallback to enable deterministic fallback."
                    )
                    raise typer.Exit(code=2) from exc
                console.print(
                    f"[{WARN}]LLM triage unavailable:[/{WARN}] {exc} — falling back to deterministic triage (--allow-ai-fallback)."
                )
                _apply_deterministic_triage(
                    report,
                    cfg=cfg,
                    triage_min=triage_min,
                    triage_max_items=triage_max_items,
                )
                _annotate_llm_fallback(report, str(exc))
        else:
            _apply_deterministic_triage(
                report,
                cfg=cfg,
                triage_min=triage_min,
                triage_max_items=triage_max_items,
            )

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

    if ci and report.findings:
        raise typer.Exit(code=1)


def _mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "..." + secret[-4:]


@app.command(name="explorer")
def explorer_lookup(
    address: str = typer.Argument(
        ...,
        help=(
            "Contract address to inspect, OR 'config' for config mode.\n"
            "Examples:\n"
            "  vyper-guard explorer 0xA0b8...6eb48 --provider auto --format json\n"
            "  vyper-guard explorer config show\n"
            "  vyper-guard explorer config set provider auto"
        ),
    ),
    subcommand: str | None = typer.Argument(
        None,
        help="Only for config mode: set | show.",
    ),
    key: str | None = typer.Argument(
        None,
        help="Only for config set: provider | network | api-key.",
    ),
    value: str | None = typer.Argument(None, help="Only for config set: value to persist."),
    provider: str | None = typer.Option(
        None, "--provider", help="Explorer provider (default from config)."
    ),
    network: str | None = typer.Option(
        None, "--network", help="Network name (default from config)."
    ),
    api_key: str | None = typer.Option(
        None, "--api-key", help="Explorer API key (or GUARDIAN_EXPLORER_API_KEY)."
    ),
    private_key: str | None = typer.Option(
        None, "--private-key", help="Optional wallet private key (not stored)."
    ),
    format: str = typer.Option("cli", "--format", "-f", help="Output format: cli | json."),
    save_json: Path | None = typer.Option(
        None, "--save-json", help="Save explorer metadata JSON to file."
    ),
    save_source: Path | None = typer.Option(
        None, "--save-source", help="Save verified source code to file."
    ),
    save_abi: Path | None = typer.Option(None, "--save-abi", help="Save ABI JSON to file."),
) -> None:
    """Fetch contract metadata (source/ABI/functions), or manage explorer config.

    Quick examples:
    - Lookup address: vyper-guard explorer 0xA0b8...6eb48 --provider auto --network ethereum
    - Lookup JSON:    vyper-guard explorer 0xA0b8...6eb48 -f json
    - Show config:    vyper-guard explorer config show
    - Set config:     vyper-guard explorer config set provider auto
    """
    if address.strip().lower() == "config":
        action = (subcommand or "").strip().lower()
        if not action:
            console.print(
                f"[{WARN}]Explorer config usage:[/{WARN}]\n"
                "  vyper-guard explorer config show\n"
                "  vyper-guard explorer config set provider auto\n"
                "  vyper-guard explorer config set network ethereum\n"
                "  vyper-guard explorer config set api-key <key>"
            )
            raise typer.Exit(code=2)
        if action == "show":
            cfg = load_config()
            current_key = cfg.explorer.api_key or ""
            redacted = ""
            if current_key:
                redacted = (
                    (current_key[:4] + "..." + current_key[-4:]) if len(current_key) > 8 else "***"
                )

            payload = {
                "provider": cfg.explorer.provider,
                "network": cfg.explorer.network,
                "api_key_set": bool(current_key),
                "api_key": redacted,
                "user_config_path": str(_user_config_path()),
            }
            typer.echo(_json.dumps(payload, indent=2, ensure_ascii=False))
            return

        if action == "set":
            normalized_key = (key or "").strip().lower()
            key_map = {
                "provider": "provider",
                "network": "network",
                "api-key": "api_key",
            }
            if normalized_key not in key_map:
                console.print(
                    f"[{ERR}]Unsupported explorer config key:[/{ERR}] {key}. "
                    "Use provider, network, or api-key."
                )
                raise typer.Exit(code=2)

            target_key = key_map[normalized_key]
            if normalized_key == "api-key":
                if value is None:
                    value = typer.prompt(
                        "Enter explorer API key", hide_input=True, confirmation_prompt=True
                    )
                resolved: object = value.strip()
                if not resolved:
                    console.print(f"[{ERR}]API key cannot be empty.[/{ERR}]")
                    raise typer.Exit(code=2)
            else:
                if value is None or not value.strip():
                    console.print(f"[{ERR}]Missing value for key:[/{ERR}] {key}")
                    raise typer.Exit(code=2)
                resolved = value.strip().lower()

            _set_user_config_value("explorer", target_key, resolved)
            if normalized_key == "api-key":
                console.print(
                    f"[{OK}]Explorer API key saved to user config:[/{OK}] [bold]{_user_config_path()}[/bold] "
                    f"[{WARN}](consider env/keyring for stronger secret hygiene)[/{WARN}]"
                )
            else:
                console.print(
                    f"[{OK}]Explorer config updated:[/{OK}] explorer.{target_key} = {resolved} "
                    f"([bold]{_user_config_path()}[/bold])"
                )
            return

        console.print(
            f"[{ERR}]Invalid explorer config command.[/{ERR}] "
            "Use: explorer config show OR explorer config set <provider|network|api-key> [value]"
        )
        raise typer.Exit(code=2)

    if subcommand is not None or key is not None or value is not None:
        console.print(f"[{ERR}]Unexpected extra positional arguments for explorer lookup.[/{ERR}]")
        raise typer.Exit(code=2)

    cfg = load_config(None)
    from guardian.explorer.client import ExplorerClient, ExplorerError

    selected_provider = (provider or cfg.explorer.provider).strip().lower()
    selected_network = (network or cfg.explorer.network).strip().lower()
    selected_key = api_key or cfg.explorer.api_key

    # UX guardrail: if user relies on default etherscan config, transparently
    # use fallback chain so explorer still works even with Etherscan V1 deprecation.
    if provider is None and selected_provider == "etherscan":
        selected_provider = "etherscan,blockscout,sourcify"
        console.print(
            f"[{WARN}]Explorer provider defaulted to fallback chain:[/{WARN}] "
            "etherscan,blockscout,sourcify"
        )

    if private_key:
        pk = private_key.strip().lower()
        if pk.startswith("0x"):
            pk = pk[2:]
        if len(pk) != 64 or any(ch not in "0123456789abcdef" for ch in pk):
            console.print(f"[{ERR}]Invalid private key format.[/{ERR}]")
            raise typer.Exit(code=2)
        console.print(
            f"[{WARN}]Private key supplied ([/{WARN}]{_mask_secret(private_key)}[{WARN}]); not persisted.[/{WARN}]"
        )

    try:
        client = ExplorerClient(
            provider=selected_provider,
            network=selected_network,
            api_key=selected_key,
        )
        info = client.fetch_contract(address)
    except ExplorerError as exc:
        console.print(f"[{ERR}]Explorer lookup failed:[/{ERR}] {exc}")
        console.print(
            f"[{DIM}]Try:[/{DIM}]\n"
            "  • Use a verified contract address\n"
            "  • Override provider chain: --provider etherscan,blockscout,sourcify\n"
            "  • Specify network explicitly: --network ethereum\n"
            "  • Configure key when needed: vyper-guard explorer config set api-key <key>"
        )
        raise typer.Exit(code=2) from exc

    payload = {
        "address": info.address,
        "network": info.network,
        "provider": info.provider,
        "contract_name": info.contract_name,
        "compiler_version": info.compiler_version,
        "optimization_used": info.optimization_used,
        "runs": info.runs,
        "is_proxy": info.is_proxy,
        "implementation": info.implementation,
        "function_names": info.function_names,
        "has_source_code": bool(info.source_code),
        "abi_entries": len(info.abi or []),
    }

    if format.lower() == "json":
        typer.echo(_json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        table = Table(title="Explorer Contract Metadata", box=box.SIMPLE_HEAVY)
        table.add_column("Field", style="bold")
        table.add_column("Value")
        for k, v in payload.items():
            table.add_row(str(k), str(v))
        console.print(table)

    if save_json:
        save_json.parent.mkdir(parents=True, exist_ok=True)
        save_json.write_text(_json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if save_source and info.source_code:
        save_source.parent.mkdir(parents=True, exist_ok=True)
        save_source.write_text(info.source_code, encoding="utf-8")
    if save_abi and info.abi is not None:
        save_abi.parent.mkdir(parents=True, exist_ok=True)
        save_abi.write_text(_json.dumps(info.abi, indent=2, ensure_ascii=False), encoding="utf-8")


@app.command(name="agent")
def agent_run(
    prompt: str | None = typer.Argument(None, help="Agent prompt/question."),
    file_path: Path | None = typer.Option(None, "--file", help="Optional local .vy file context."),
    address: str | None = typer.Option(
        None, "--address", help="Optional contract address context via explorer."
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="LLM provider override (e.g., gemini, openai_compatible)."
    ),
    model: str | None = typer.Option(None, "--model", help="LLM model (default from config)."),
    base_url: str | None = typer.Option(None, "--base-url", help="LLM API base URL."),
    api_key: str | None = typer.Option(
        None, "--api-key", help="LLM API key (or GUARDIAN_LLM_API_KEY)."
    ),
    explorer_provider: str | None = typer.Option(
        None, "--explorer-provider", help="Explorer provider override for --address context."
    ),
    explorer_network: str | None = typer.Option(
        None, "--explorer-network", help="Explorer network override for --address context."
    ),
    explorer_api_key: str | None = typer.Option(
        None, "--explorer-api-key", help="Explorer API key override for --address context."
    ),
    allow_fallback: bool = typer.Option(
        False,
        "--allow-fallback",
        help="Allow deterministic fallback response when explorer/LLM calls fail.",
    ),
    memory_file: Path | None = typer.Option(None, "--memory-file", help="JSONL memory file path."),
    memory_max_entries: int | None = typer.Option(
        None,
        "--memory-max-entries",
        min=1,
        help="Maximum number of memory entries to retain in JSONL store.",
    ),
    sandbox_script: Path | None = typer.Option(
        None, "--sandbox-script", help="Optional python script to run in sandbox."
    ),
    save_context: Path | None = typer.Option(
        None, "--save-context", help="Save assembled agent context as JSON before LLM call."
    ),
    save_output: Path | None = typer.Option(
        None, "--save-output", help="Save agent answer to file."
    ),
) -> None:
    """Run LLM-backed security agent with memory and optional sandbox tool."""
    from guardian.agents.adk import AgentError, AgentMemory, SecurityAgent
    from guardian.explorer.client import ExplorerClient, ExplorerError

    if not prompt or not prompt.strip():
        console.print(
            f"[{WARN}]Missing prompt.[/{WARN}] Example usage:\n"
            '  vyper-guard agent "Summarize critical risks" --file contract.vy\n'
            '  vyper-guard agent "Review upgrade safety" --address 0xA0b8...6eb48\n'
            '  vyper-guard agent "Prioritize fixes" --file contract.vy --save-output agent.txt'
        )
        raise typer.Exit(code=2)

    cfg = load_config(None)
    resolved_provider = (provider or cfg.llm.provider).strip().lower()
    resolved_model = model or cfg.llm.model
    resolved_base = base_url or cfg.llm.base_url
    resolved_key = api_key or cfg.llm.api_key or ""
    resolved_memory = memory_file or Path(cfg.llm.memory_file)
    resolved_memory_max_entries = memory_max_entries or cfg.llm.memory_max_entries
    resolved_explorer_provider = (explorer_provider or cfg.explorer.provider).strip().lower()
    resolved_explorer_network = (explorer_network or cfg.explorer.network).strip().lower()
    resolved_explorer_key = explorer_api_key or cfg.explorer.api_key

    if address and explorer_provider is None and resolved_explorer_provider == "etherscan":
        resolved_explorer_provider = "etherscan,blockscout,sourcify"
        console.print(
            f"[{WARN}]Explorer provider defaulted to fallback chain:[/{WARN}] "
            "etherscan,blockscout,sourcify"
        )

    context: dict[str, object] = {}
    context["available_tools"] = [
        "local_static_analysis",
        "explorer_contract_metadata",
        "python_sandbox",
        "memory_tail",
    ]

    if file_path:
        if not file_path.exists() or file_path.suffix != ".vy":
            console.print(f"[{ERR}]--file must point to an existing .vy file.[/{ERR}]")
            raise typer.Exit(code=2)
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_file(file_path)
        context["local_analysis"] = {
            "file_path": str(file_path),
            "security_score": report.security_score,
            "findings": [
                {
                    "detector": f.detector_name,
                    "severity": f.severity.value,
                    "title": f.title,
                    "line": f.line_number,
                }
                for f in report.findings
            ],
        }

    if address:
        try:
            info = ExplorerClient(
                provider=resolved_explorer_provider,
                network=resolved_explorer_network,
                api_key=resolved_explorer_key,
            ).fetch_contract(address)
            context["explorer"] = {
                "address": info.address,
                "network": info.network,
                "contract_name": info.contract_name,
                "compiler_version": info.compiler_version,
                "function_names": info.function_names,
                "abi_entries": len(info.abi or []),
            }
        except ExplorerError as exc:
            if not allow_fallback:
                console.print(
                    f"[{ERR}]Explorer lookup failed:[/{ERR}] {exc}. "
                    "Re-run with --allow-fallback to continue with deterministic fallback output."
                )
                raise typer.Exit(code=2) from exc
            context["explorer_error"] = str(exc)

    if sandbox_script:
        if not sandbox_script.exists():
            console.print(f"[{ERR}]Sandbox script not found: {sandbox_script}[/{ERR}]")
            raise typer.Exit(code=2)
        script = sandbox_script.read_text(encoding="utf-8")
        context["sandbox"] = SecurityAgent.run_python_sandbox(script)

    if save_context:
        save_context.parent.mkdir(parents=True, exist_ok=True)
        save_context.write_text(
            _json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _build_agent_fallback_answer(prompt_text: str, ctx: dict[str, object], reason: str) -> str:
        findings = []
        local = ctx.get("local_analysis")
        if isinstance(local, dict):
            raw_findings = local.get("findings")
            if isinstance(raw_findings, list):
                findings = [f for f in raw_findings if isinstance(f, dict)]

        def _sev_rank(name: str) -> int:
            return {
                "CRITICAL": 5,
                "HIGH": 4,
                "MEDIUM": 3,
                "LOW": 2,
                "INFO": 1,
            }.get(name.upper(), 0)

        findings_sorted = sorted(
            findings,
            key=lambda f: (
                -_sev_rank(str(f.get("severity", ""))),
                str(f.get("line") or ""),
            ),
        )

        risk_lines: list[str] = []
        for item in findings_sorted[:5]:
            risk_lines.append(
                "- "
                + f"[{item.get('severity', 'UNKNOWN')}] {item.get('detector', 'detector')}"
                + f" at line {item.get('line', '?')}: {item.get('title', '')}"
            )
        if not risk_lines:
            risk_lines.append("- No local findings were available in context.")

        action_lines = [
            "1. Address all CRITICAL/HIGH findings first (especially reentrancy/CEI violations).",
            "2. Re-run: `vyper-guard analyze <file> --ai --format json` after each patch.",
            "3. Use `--fix --fix-dry-run` to preview deterministic remediation candidates.",
            "4. Validate with tests and deployment simulation before production rollout.",
        ]

        validation_lines = [
            "- Run static scan with threshold gates (CI mode).",
            "- Re-check graph metrics: `vyper-guard stats <file> --graph`.",
            "- Confirm no new HIGH/CRITICAL findings in final report.",
        ]

        return "\n".join(
            [
                "Agent Fallback Response",
                "",
                f"Prompt: {prompt_text}",
                "",
                f"AI request was unavailable: {reason}",
                "A deterministic fallback summary is provided below.",
                "",
                "risk_summary",
                *risk_lines,
                "",
                "prioritized_actions",
                *action_lines,
                "",
                "validation_steps",
                *validation_lines,
            ]
        )

    def _normalize_agent_answer_plain_text(text: str) -> str:
        """Normalize markdown-heavy model output into plain terminal text."""
        out = text.replace("**", "").replace("`", "")
        out = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", out)
        out = re.sub(r"(?m)^\s*[-*]\s+", "- ", out)
        out = re.sub(r"\n{3,}", "\n\n", out).strip()
        return out

    try:
        answer = SecurityAgent(
            api_key=resolved_key,
            model=resolved_model,
            base_url=resolved_base,
            provider=resolved_provider,
            memory=AgentMemory(resolved_memory, max_entries=resolved_memory_max_entries),
        ).ask(prompt, context=context)
    except AgentError as exc:
        if not allow_fallback:
            console.print(
                f"[{ERR}]Agent LLM request failed:[/{ERR}] {exc}. "
                "Re-run with --allow-fallback to return deterministic fallback output."
            )
            raise typer.Exit(code=2) from exc
        console.print(
            f"[{WARN}]Agent LLM unavailable:[/{WARN}] {exc} — returning deterministic fallback response (--allow-fallback)."
        )
        answer = _build_agent_fallback_answer(prompt, context, str(exc))

    answer = _normalize_agent_answer_plain_text(answer)

    if save_output:
        save_output.parent.mkdir(parents=True, exist_ok=True)
        save_output.write_text(answer, encoding="utf-8")

    typer.echo(answer)


@app.command(name="agent-memory")
def agent_memory(
    action: str = typer.Argument(..., help="Action: tail | clear | stats"),
    memory_file: Path | None = typer.Option(None, "--memory-file", help="JSONL memory file path."),
    limit: int = typer.Option(10, "--limit", min=1, help="Rows to show for tail action."),
) -> None:
    """Inspect or clear persistent agent memory."""
    from guardian.agents.adk import AgentMemory

    cfg = load_config(None)
    path = memory_file or Path(cfg.llm.memory_file)
    mem = AgentMemory(path, max_entries=cfg.llm.memory_max_entries)

    op = action.strip().lower()
    if op == "tail":
        rows = mem.tail(limit)
        typer.echo(_json.dumps(rows, indent=2, ensure_ascii=False))
        return

    if op == "stats":
        if not path.exists():
            typer.echo(_json.dumps({"file": str(path), "entries": 0, "size_bytes": 0}, indent=2))
            return
        entries = len(path.read_text(encoding="utf-8").splitlines())
        payload = {
            "file": str(path),
            "entries": entries,
            "size_bytes": path.stat().st_size,
        }
        typer.echo(_json.dumps(payload, indent=2, ensure_ascii=False))
        return

    if op == "clear":
        if path.exists():
            path.unlink()
        typer.echo(_json.dumps({"file": str(path), "cleared": True}, indent=2, ensure_ascii=False))
        return

    console.print(f"[{ERR}]Invalid action:[/{ERR}] {action}. Use tail, clear, or stats.")
    raise typer.Exit(code=2)


@app.command()
def benchmark(
    corpus_dir: Path = typer.Argument(
        Path("test_contracts"),
        help="Directory containing .vy contracts for quality benchmarking.",
    ),
    format: str = typer.Option("cli", "--format", "-f", help="Output format: cli or json."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    labels_file: Path | None = typer.Option(
        None,
        "--labels-file",
        help="Optional JSON labels file for expected vulnerable files/detectors.",
    ),
    min_precision: float | None = typer.Option(
        None,
        "--min-precision",
        help="Optional overall precision quality gate (0.0-1.0).",
    ),
    min_recall: float | None = typer.Option(
        None,
        "--min-recall",
        help="Optional overall recall quality gate (0.0-1.0).",
    ),
    min_f1: float | None = typer.Option(
        None,
        "--min-f1",
        help="Optional overall F1 quality gate (0.0-1.0).",
    ),
    min_detector_f1: float | None = typer.Option(
        None,
        "--min-detector-f1",
        help="Optional per-detector F1 gate applied to detectors with support.",
    ),
    min_detector_support: int = typer.Option(
        1,
        "--min-detector-support",
        help="Minimum detector support before per-detector gate is enforced.",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="Exit 1 when configured quality gates are not met.",
    ),
) -> None:
    """Run a lightweight detector quality benchmark over a corpus directory."""
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        console.print(f"[{ERR}]Invalid corpus directory:[/{ERR}] {corpus_dir}")
        raise typer.Exit(code=2)

    fmt = format.lower()
    if fmt not in {"cli", "json"}:
        console.print(f"[{ERR}]Invalid format: {fmt}. Use one of: cli, json.[/{ERR}]")
        raise typer.Exit(code=2)

    for gate_name, gate_value in (
        ("min_precision", min_precision),
        ("min_recall", min_recall),
        ("min_f1", min_f1),
        ("min_detector_f1", min_detector_f1),
    ):
        if gate_value is not None and not (0.0 <= gate_value <= 1.0):
            console.print(
                f"[{ERR}]Invalid {gate_name}: {gate_value}. Must be between 0.0 and 1.0.[/{ERR}]"
            )
            raise typer.Exit(code=2)

    if min_detector_support < 1:
        console.print(
            f"[{ERR}]Invalid min_detector_support: {min_detector_support}. Must be >= 1.[/{ERR}]"
        )
        raise typer.Exit(code=2)

    if labels_file and (not labels_file.exists() or not labels_file.is_file()):
        console.print(f"[{ERR}]Invalid labels file:[/{ERR}] {labels_file}")
        raise typer.Exit(code=2)

    result = run_corpus_benchmark(corpus_dir, labels_file=labels_file)
    failures: list[str] = []
    if min_precision is not None and result.precision < min_precision:
        failures.append(f"overall precision {result.precision:.4f} < {min_precision:.4f}")
    if min_recall is not None and result.recall < min_recall:
        failures.append(f"overall recall {result.recall:.4f} < {min_recall:.4f}")
    if min_f1 is not None and result.f1 < min_f1:
        failures.append(f"overall f1 {result.f1:.4f} < {min_f1:.4f}")
    if min_detector_f1 is not None:
        for detector_name, stats in result.by_detector.items():
            if stats.support < min_detector_support:
                continue
            if stats.f1 < min_detector_f1:
                failures.append(
                    f"{detector_name} f1 {stats.f1:.4f} < {min_detector_f1:.4f} "
                    f"(support={stats.support})"
                )

    gates_configured = any(
        gate is not None for gate in (min_precision, min_recall, min_f1, min_detector_f1)
    )

    payload = {
        "corpus_dir": str(corpus_dir),
        "labels_file": str(labels_file) if labels_file else None,
        "files_total": result.files_total,
        "expected": {
            "vulnerable": result.vulnerable_expected,
            "safe": result.safe_expected,
        },
        "predicted_vulnerable": result.predicted_vulnerable,
        "confusion_matrix": {
            "tp": result.true_positive,
            "fp": result.false_positive,
            "tn": result.true_negative,
            "fn": result.false_negative,
        },
        "metrics": {
            "precision": round(result.precision, 4),
            "recall": round(result.recall, 4),
            "f1": round(result.f1, 4),
        },
        "by_detector": {
            name: {
                "tp": stats.tp,
                "fp": stats.fp,
                "fn": stats.fn,
                "support": stats.support,
                "precision": round(stats.precision, 4),
                "recall": round(stats.recall, 4),
                "f1": round(stats.f1, 4),
            }
            for name, stats in result.by_detector.items()
        },
        "quality_gates": {
            "configured": gates_configured,
            "thresholds": {
                "min_precision": min_precision,
                "min_recall": min_recall,
                "min_f1": min_f1,
                "min_detector_f1": min_detector_f1,
                "min_detector_support": min_detector_support,
            },
            "passed": len(failures) == 0,
            "failures": failures,
        },
    }

    if fmt == "json":
        text = _json.dumps(payload, indent=2)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text + "\n", encoding="utf-8")
        else:
            typer.echo(text)
    else:
        table = Table(title="Detector Benchmark", box=box.ROUNDED, show_header=True)
        table.add_column("Metric", style=f"bold {ACCENT}")
        table.add_column("Value", justify="right")

        table.add_row("Corpus", str(corpus_dir))
        if labels_file:
            table.add_row("Labels file", str(labels_file))
        table.add_row("Files", str(result.files_total))
        table.add_row("Expected vulnerable", str(result.vulnerable_expected))
        table.add_row("Expected safe", str(result.safe_expected))
        table.add_row("Predicted vulnerable", str(result.predicted_vulnerable))
        table.add_row(
            "TP / FP / TN / FN",
            f"{result.true_positive} / {result.false_positive} / {result.true_negative} / {result.false_negative}",
        )
        table.add_row("Precision", f"{result.precision:.3f}")
        table.add_row("Recall", f"{result.recall:.3f}")
        table.add_row("F1", f"{result.f1:.3f}")
        console.print(table)

        det_table = Table(
            title="Per-Detector Quality",
            box=box.ROUNDED,
            show_header=True,
        )
        det_table.add_column("Detector", style=f"bold {ACCENT}")
        det_table.add_column("Support", justify="right")
        det_table.add_column("TP/FP/FN", justify="right")
        det_table.add_column("Precision", justify="right")
        det_table.add_column("Recall", justify="right")
        det_table.add_column("F1", justify="right")

        for name, stats in result.by_detector.items():
            if stats.support == 0 and stats.fp == 0:
                continue
            det_table.add_row(
                name,
                str(stats.support),
                f"{stats.tp}/{stats.fp}/{stats.fn}",
                f"{stats.precision:.3f}",
                f"{stats.recall:.3f}",
                f"{stats.f1:.3f}",
            )

        if det_table.row_count > 0:
            console.print(det_table)

        if gates_configured:
            gate_table = Table(title="Quality Gates", box=box.ROUNDED, show_header=True)
            gate_table.add_column("Gate", style=f"bold {ACCENT}")
            gate_table.add_column("Value", justify="right")
            gate_table.add_row("Configured", "yes")
            gate_table.add_row("Passed", "yes" if not failures else "no")
            gate_table.add_row("Failures", str(len(failures)))
            console.print(gate_table)

            if failures:
                console.print(f"[{WARN}]Quality gate failures:[/{WARN}]")
                for failure in failures:
                    console.print(f"  - {failure}")

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if failures and (gates_configured or ci):
        raise typer.Exit(code=1)


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

    # Avoid re-reading/parsing from disk during render to prevent TOCTOU mismatch.
    meta_table.add_row("📏 Lines of Code", "n/a")

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

    if report.ai_triage:
        _print_ai_triage_section(report)

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


def _print_ai_triage_section(report: AnalysisReport) -> None:
    """Render optional AI-assisted triage metadata."""
    console.print(Rule("[bold]🤖 AI-Assisted Triage[/bold]", style=ACCENT))
    console.print()

    policy_version = report.ai_triage_policy.get("policy_version", "unknown")
    policy_status = report.ai_triage_policy.get("status", "unknown")
    deterministic_mode = bool(report.ai_triage_policy.get("deterministic", True))
    mode_label = "deterministic" if deterministic_mode else "llm-assisted"
    console.print(
        f"[dim]Policy: v{policy_version} ({policy_status}) • {mode_label} advisory metadata[/dim]"
    )
    scoring_versions = {
        str(item.get("scoring_rationale", {}).get("version", "")).strip()
        for item in report.ai_triage
    }
    scoring_versions = {v for v in scoring_versions if v}
    if scoring_versions:
        ordered_versions = ", ".join(sorted(scoring_versions))
        console.print(f"[dim]Scoring profile: {ordered_versions}[/dim]")
    policy_warnings = report.ai_triage_policy.get("warnings", [])
    if isinstance(policy_warnings, list):
        for w in policy_warnings:
            console.print(f"[{WARN}]Policy warning:[/{WARN}] {w}")
    console.print()

    console.print("[bold]LLM Summary[/bold]")
    top_items = sorted(
        report.ai_triage,
        key=lambda item: int(item.get("priority_rank", 9999) or 9999),
    )[:3]
    if top_items:
        for item in top_items:
            rank = item.get("priority_rank", "—")
            detector = item.get("detector", "—")
            bucket = item.get("triage_bucket", "—")
            conf = item.get("confidence", "—")
            reasoning = str(item.get("reasoning", "")).strip()
            next_step = str(item.get("suggested_next_step", "")).strip()
            line = f"{rank}. {detector} ({bucket}) confidence={conf}."
            if reasoning:
                line += f" {reasoning}"
            if next_step:
                line += f" Next: {next_step}"
            console.print(f"  {line}")
    else:
        console.print("  No triage items available.")
    console.print()

    triage_table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=True,
    )
    triage_table.add_column("Rank", width=6, justify="right")
    triage_table.add_column("Bucket", width=14)
    triage_table.add_column("Detector", width=28, style=f"bold {ACCENT}")
    triage_table.add_column("Confidence", width=10, justify="right")
    triage_table.add_column("Scoring", width=22)
    triage_table.add_column("Next Step", ratio=1)

    for item in report.ai_triage:
        scoring = item.get("scoring_rationale", {})
        scoring_text = (
            f"{scoring.get('version', '—')} "
            f"(b={scoring.get('severity_base', '—')}+e={scoring.get('evidence_bonus', '—')})"
        )
        triage_table.add_row(
            str(item.get("priority_rank", "—")),
            str(item.get("triage_bucket", "—")),
            str(item.get("detector", "—")),
            str(item.get("confidence", "—")),
            scoring_text,
            str(item.get("suggested_next_step", "—")),
        )

    console.print(triage_table)
    console.print(
        "[dim]Guardrail: triage is advisory only and cannot override deterministic detector verdicts.[/dim]"
    )
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  --fix mode
# ═══════════════════════════════════════════════════════════════════


def _run_fix_mode(
    file_path: Path,
    report: AnalysisReport,
    con: Console,
    *,
    max_auto_fix_tier: str = "C",
    dry_run: bool = False,
) -> dict[str, object]:
    """Auto-remediation flow: generate fixes, show diffs, prompt, apply."""
    from rich.syntax import Syntax

    from guardian.analyzer.ast_parser import parse_vyper_source
    from guardian.remediation.fix_generator import (
        FixGenerator,
        remediation_planning_contract,
        risk_tier_for_detector,
    )

    source = file_path.read_text(encoding="utf-8")
    contract = parse_vyper_source(source, str(file_path))
    source_lines = source.splitlines()

    max_rank = _RISK_TIER_ORDER.get(max_auto_fix_tier, _RISK_TIER_ORDER["C"])
    eligible_findings = [
        f
        for f in report.findings
        if _RISK_TIER_ORDER.get(risk_tier_for_detector(f.detector_name), 99) <= max_rank
    ]
    skipped_by_tier = [
        f
        for f in report.findings
        if _RISK_TIER_ORDER.get(risk_tier_for_detector(f.detector_name), 99) > max_rank
    ]

    plan = remediation_planning_contract(report.findings, max_auto_fix_tier=max_auto_fix_tier)

    gen = FixGenerator(source_lines, contract)
    results = gen.generate_all(eligible_findings)

    applied = [r for r in results if r.applied]
    skipped = [r for r in results if not r.applied]

    remediation_report: dict[str, object] = {
        "policy_version": "1.0.0",
        "file_path": str(file_path),
        "max_auto_fix_tier": max_auto_fix_tier,
        "dry_run": dry_run,
        "plan": plan,
        "summary": {
            "generated": len(results),
            "applied": 0,
            "not_applied": 0,
            "skipped_by_tier": len(skipped_by_tier),
        },
        "generated_fixes": [],
        "not_applied_fixes": [],
        "skipped_by_tier": [
            {
                "detector": s.detector_name,
                "tier": risk_tier_for_detector(s.detector_name),
                "title": s.title,
                "line_number": s.line_number,
            }
            for s in skipped_by_tier
        ],
    }

    if not applied:
        if skipped_by_tier:
            con.print(
                f"  [{DIM}]{len(skipped_by_tier)} fix(es) skipped by risk-tier policy"
                f" (>{max_auto_fix_tier}).[/{DIM}]"
            )
            for s in skipped_by_tier:
                tier = risk_tier_for_detector(s.detector_name)
                con.print(f"    [{DIM}]• {s.detector_name}: tier {tier} ({s.title})[/{DIM}]")
            con.print()
        if skipped:
            con.print(
                f"  [{WARN}]Manual remediation required for {len(skipped)} finding(s):[/{WARN}]"
            )
            for s in skipped:
                con.print(f"    [{DIM}]• {s.finding.detector_name}: {s.description}[/{DIM}]")
            con.print()
        con.print(
            f"\n  [{WARN}]⚠  No auto-fixes available within risk tier ≤ {max_auto_fix_tier}.[/{WARN}]\n"
        )
        remediation_report["summary"] = {
            "generated": len(results),
            "applied": 0,
            "not_applied": len(results),
            "skipped_by_tier": len(skipped_by_tier),
        }
        remediation_report["not_applied_fixes"] = [
            {
                "detector": r.finding.detector_name,
                "severity": r.finding.severity.value,
                "risk_tier": r.risk_tier,
                "line_number": r.finding.line_number,
                "title": r.finding.title,
                "description": r.description,
            }
            for r in skipped
        ]
        return remediation_report

    # Header
    con.print()
    con.print(
        Panel(
            f"[{OK}]🔧  Auto-Remediation  —  {len(applied)} fix(es) generated[/{OK}]",
            expand=False,
            border_style="green",
        )
    )
    con.print(
        f"  [{DIM}]Plan (tier cap ≤ {plan['max_auto_fix_tier']}): "
        f"eligible={plan['eligible_total']} skipped={plan['skipped_total']}"
        f" | A:{plan['eligible_by_tier']['A']}"
        f" B:{plan['eligible_by_tier']['B']}"
        f" C:{plan['eligible_by_tier']['C']}[/{DIM}]"
    )
    advisory_applied = [r for r in applied if r.risk_tier == "C"]
    if advisory_applied:
        con.print(
            f"  [{WARN}]Note:[/{WARN}] {len(advisory_applied)} tier-C remediation item(s) are "
            "advisory annotations and may [bold]not[/bold] clear the underlying detector finding."
        )
        con.print(f"  [{DIM}]Re-run analyze after manual refactor to confirm closure.[/{DIM}]")
    con.print()

    for i, result in enumerate(applied, 1):
        sev = result.finding.severity.value
        con.print(f"  [bold]Fix {i}/{len(applied)}:[/bold] {result.description}")
        if result.risk_tier == "C":
            con.print(
                f"    [{WARN}]Advisory annotation only:[/{WARN}] manual code changes are still required."
            )
        con.print(
            f"    Severity: [bold]{sev}[/bold]  |  Detector: {result.finding.detector_name}"
            f"  |  Risk Tier: {result.risk_tier}"
        )
        if result.diff:
            con.print()
            con.print(Syntax(result.diff, "diff", theme="monokai", line_numbers=False))
        if result.warnings:
            for w in result.warnings:
                con.print(f"    [{WARN}]⚠ {w}[/{WARN}]")
        con.print()

        remediation_report["generated_fixes"].append(
            {
                "detector": result.finding.detector_name,
                "severity": result.finding.severity.value,
                "risk_tier": result.risk_tier,
                "line_number": result.finding.line_number,
                "title": result.finding.title,
                "description": result.description,
                "warnings": list(result.warnings),
            }
        )

    if skipped:
        con.print(
            f"  [{DIM}]{len(skipped)} finding(s) have no auto-fix (manual review needed).[/{DIM}]"
        )
        for s in skipped:
            con.print(f"    [{DIM}]• {s.finding.detector_name}: {s.description}[/{DIM}]")
        con.print()

    remediation_report["not_applied_fixes"] = [
        {
            "detector": r.finding.detector_name,
            "severity": r.finding.severity.value,
            "risk_tier": r.risk_tier,
            "line_number": r.finding.line_number,
            "title": r.finding.title,
            "description": r.description,
        }
        for r in skipped
    ]

    if skipped_by_tier:
        con.print(
            f"  [{DIM}]{len(skipped_by_tier)} fix(es) skipped by risk-tier policy"
            f" (>{max_auto_fix_tier}).[/{DIM}]"
        )
        for s in skipped_by_tier:
            tier = risk_tier_for_detector(s.detector_name)
            con.print(f"    [{DIM}]• {s.detector_name}: tier {tier} ({s.title})[/{DIM}]")
        con.print()

    # Build patched source once so we can provide post-fix analysis clarity
    # even in dry-run mode.
    patched = gen.patched_source()

    post_fix_payload: dict[str, object] | None = None
    try:
        post_enabled = [d for d in report.detectors_run if d != "compiler_version_check"]
        post_analyzer = StaticAnalyzer(enabled_detectors=post_enabled or ["all"])
        post_report = post_analyzer.analyze_source(patched, file_path=str(file_path))

        before_total = len(report.findings)
        after_total = len(post_report.findings)
        before_by_detector = Counter(f.detector_name for f in report.findings)
        after_by_detector = Counter(f.detector_name for f in post_report.findings)

        still_open = {det: count for det, count in after_by_detector.items() if count > 0}

        post_fix_payload = {
            "before_findings": before_total,
            "after_findings": after_total,
            "delta": before_total - after_total,
            "remaining_by_detector": dict(still_open),
            "before_by_detector": dict(before_by_detector),
            "after_by_detector": dict(after_by_detector),
        }

        title_style = (
            OK if after_total < before_total else WARN if after_total == before_total else ERR
        )
        con.print(
            Panel(
                f"[bold]Post-fix verification[/bold]\n"
                f"Before findings: [bold]{before_total}[/bold]\n"
                f"After findings: [bold]{after_total}[/bold]\n"
                f"Delta: [bold]{before_total - after_total:+d}[/bold]",
                border_style="green"
                if after_total < before_total
                else "yellow"
                if after_total == before_total
                else "red",
                title=f"[{title_style}]Verification Summary[/{title_style}]",
                expand=False,
            )
        )
        if still_open:
            con.print(f"  [{WARN}]Remaining detector(s):[/{WARN}]")
            for det, count in sorted(still_open.items()):
                con.print(f"    [{DIM}]• {det}: {count}[/{DIM}]")
        else:
            con.print(f"  [{OK}]No findings remain after patching.[/{OK}]")
        con.print()
    except Exception:
        # Best-effort enhancement: never block remediation flow.
        post_fix_payload = None

    if dry_run:
        con.print(f"  [{WARN}]Dry-run mode:[/{WARN}] no files were written.")
        con.print()
        remediation_report["summary"] = {
            "generated": len(results),
            "applied": len(applied),
            "not_applied": len(skipped),
            "skipped_by_tier": len(skipped_by_tier),
        }
        if post_fix_payload is not None:
            remediation_report["post_fix_analysis"] = post_fix_payload
        return remediation_report

    fixed_path = file_path.with_suffix(".fixed.vy")
    try:
        write_fixed = typer.confirm(
            f"\n  Write patched artifact ({fixed_path.name})?",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        write_fixed = False

    if not write_fixed:
        con.print(f"  [{WARN}]Skipped:[/{WARN}] no patched file was written.")
        con.print()
        remediation_report["summary"] = {
            "generated": len(results),
            "applied": len(applied),
            "not_applied": len(skipped),
            "skipped_by_tier": len(skipped_by_tier),
        }
        remediation_report["artifact"] = {
            "fixed_file": None,
            "original_overwritten": False,
            "backup_file": None,
            "write_declined": True,
        }
        if post_fix_payload is not None:
            remediation_report["post_fix_analysis"] = post_fix_payload
        return remediation_report

    # Write to .fixed.vy file
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

    backup_path: Path | None = None
    if overwrite:
        backup_candidate = file_path.with_suffix(file_path.suffix + ".bak")
        if backup_candidate.exists():
            i = 1
            while True:
                alt = file_path.with_suffix(file_path.suffix + f".bak.{i}")
                if not alt.exists():
                    backup_candidate = alt
                    break
                i += 1
        backup_candidate.write_text(source, encoding="utf-8")
        backup_path = backup_candidate
        con.print(f"  [{OK}]Backup created:[/{OK}] [bold]{backup_path}[/bold]")

        file_path.write_text(patched, encoding="utf-8")
        con.print(f"  [{OK}]✅  Original file updated:[/{OK}] [bold]{file_path}[/bold]")
        if fixed_path.exists():
            fixed_path.unlink()
    else:
        con.print(
            f"  [{DIM}]Original unchanged. Review {fixed_path.name} and apply manually.[/{DIM}]"
        )

    con.print()
    remediation_report["summary"] = {
        "generated": len(results),
        "applied": len(applied),
        "not_applied": len(skipped),
        "skipped_by_tier": len(skipped_by_tier),
    }
    remediation_report["artifact"] = {
        "fixed_file": str(fixed_path) if fixed_path.exists() else None,
        "original_overwritten": overwrite,
        "backup_file": str(backup_path) if backup_path else None,
        "write_declined": False,
    }
    if post_fix_payload is not None:
        remediation_report["post_fix_analysis"] = post_fix_payload
    return remediation_report


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

    sev_counts = Counter(d["severity"] for d in dets)
    cat_counts = Counter(d["vulnerability_type"] for d in dets)

    sev_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev_counts.get(sev, 0):
            sev_table.add_row(f"{_SEV_ICONS.get(sev, '')} {sev}", str(sev_counts[sev]))

    cat_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    cat_table.add_column("Category", style="bold")
    cat_table.add_column("Count", justify="right")
    for cat, count in sorted(cat_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        cat_table.add_row(cat, str(count))

    console.print(
        Columns(
            [
                Panel(
                    sev_table,
                    title="[bold]By Severity[/bold]",
                    border_style=ACCENT,
                    box=box.ROUNDED,
                ),
                Panel(
                    cat_table,
                    title="[bold]By Category[/bold]",
                    border_style=ACCENT,
                    box=box.ROUNDED,
                ),
            ],
            equal=True,
            expand=True,
        )
    )
    console.print()

    table = Table(
        title="[bold]Security Detectors[/bold]",
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=True,
        padding=(0, 1),
        show_lines=False,
        row_styles=["", "dim"],
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Detector", style=f"bold {ACCENT}", min_width=30, no_wrap=True)
    table.add_column("Severity", width=12, justify="center")
    table.add_column("Category", width=24, no_wrap=True)
    table.add_column("Description", ratio=1, overflow="fold")

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


def _write_stats_graph_artifacts(
    payload: dict[str, object],
    *,
    json_path: Path,
    html_path: Path,
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(_json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    line_breakdown = (
        payload.get("line_breakdown", {}) if isinstance(payload.get("line_breakdown"), dict) else {}
    )

    total_lines = int(metrics.get("total_lines", 0) or 0)
    code_lines = int(metrics.get("code_lines", 0) or 0)
    comment_lines = int(metrics.get("comment_lines", 0) or 0)
    blank_lines = int(metrics.get("blank_lines", 0) or 0)
    functions = int(metrics.get("functions", 0) or 0)
    state_vars = int(metrics.get("state_variables", 0) or 0)
    events = int(metrics.get("events", 0) or 0)
    imports = int(metrics.get("imports", 0) or 0)

    code_pct = float(line_breakdown.get("code_pct", 0.0) or 0.0)
    comment_pct = float(line_breakdown.get("comment_pct", 0.0) or 0.0)
    blank_pct = float(line_breakdown.get("blank_pct", 0.0) or 0.0)

    functions_payload = payload.get("functions", [])
    fn_lengths: list[int] = []
    if isinstance(functions_payload, list):
        for item in functions_payload:
            if isinstance(item, dict):
                s = int(item.get("start_line", 0) or 0)
                e = int(item.get("end_line", 0) or 0)
                if s > 0 and e >= s:
                    fn_lengths.append(e - s + 1)

    avg_fn_len = (sum(fn_lengths) / len(fn_lengths)) if fn_lengths else 0.0
    state_per_fn = (state_vars / functions) if functions else 0.0
    event_per_fn = (events / functions) if functions else 0.0
    complexity_index = min(
        100.0,
        (functions * 2.2)
        + (state_vars * 1.4)
        + (imports * 6.0)
        + (events * 0.8)
        + (avg_fn_len * 0.9),
    )
    complexity_band = (
        "Low" if complexity_index < 35 else "Moderate" if complexity_index < 65 else "High"
    )

    file_label = str(payload.get("file", "contract.vy"))
    control_flow = (
        payload.get("control_flow", {}) if isinstance(payload.get("control_flow"), dict) else {}
    )
    call_activity = (
        payload.get("call_activity", {}) if isinstance(payload.get("call_activity"), dict) else {}
    )
    call_edges = (
        payload.get("call_edges", []) if isinstance(payload.get("call_edges"), list) else []
    )
    functions_detailed = (
        payload.get("functions_detailed", [])
        if isinstance(payload.get("functions_detailed"), list)
        else []
    )

    def _clamp_pct(value: float) -> float:
        return max(0.0, min(100.0, value))

    def _polar(cx: float, cy: float, r: float, angle_deg: float) -> tuple[float, float]:
        rad = math.radians(angle_deg - 90)
        return (cx + r * math.cos(rad), cy + r * math.sin(rad))

    def _arc_path(cx: float, cy: float, r: float, start_deg: float, end_deg: float) -> str:
        sx, sy = _polar(cx, cy, r, start_deg)
        ex, ey = _polar(cx, cy, r, end_deg)
        large_arc = 1 if (end_deg - start_deg) > 180 else 0
        return f"M {sx:.2f} {sy:.2f} A {r:.2f} {r:.2f} 0 {large_arc} 1 {ex:.2f} {ey:.2f}"

    line_segments = [
        ("Code", _clamp_pct(code_pct), "#7f56d9"),
        ("Comments", _clamp_pct(comment_pct), "#a78bfa"),
        ("Blank", _clamp_pct(blank_pct), "#d6bcfa"),
    ]

    donut_paths: list[str] = []
    angle = 0.0
    for _, pct, color in line_segments:
        if pct <= 0:
            continue
        sweep = 360.0 * pct / 100.0
        end_angle = angle + sweep
        donut_paths.append(
            f'<path d="{_arc_path(180, 180, 118, angle, end_angle)}" '
            f'stroke="{color}" stroke-width="44" fill="none" stroke-linecap="butt" />'
        )
        angle = end_angle

    donut_svg = (
        '<svg viewBox="0 0 360 360" aria-label="Line composition donut chart">'
        '<circle cx="180" cy="180" r="118" stroke="#e8e4f7" stroke-width="44" fill="none" />'
        + "".join(donut_paths)
        + '<circle cx="180" cy="180" r="80" fill="#ffffff" stroke="#e5e7eb" stroke-width="1" />'
        + f'<text x="180" y="175" text-anchor="middle" fill="#3f2a80" font-size="42" font-weight="700">{total_lines}</text>'
        + '<text x="180" y="198" text-anchor="middle" fill="#6b7280" font-size="13">total lines</text>'
        + "</svg>"
    )

    structure_labels = ["Functions", "State Vars", "Events", "Imports"]
    structure_values = [functions, state_vars, events, imports]
    structure_max = max(1, *structure_values)
    structure_parts: list[str] = [
        '<svg viewBox="0 0 560 300" aria-label="Structure counts bar chart">',
        '<rect x="0" y="0" width="560" height="300" fill="#ffffff" />',
    ]
    for i in range(5):
        y = 24 + i * 50
        structure_parts.append(
            f'<line x1="54" y1="{y}" x2="534" y2="{y}" stroke="#eceff3" stroke-width="1" />'
        )
    slot_w = 480 / max(1, len(structure_values))
    bar_w = 56
    for idx, (label, value) in enumerate(zip(structure_labels, structure_values, strict=True)):
        h = (value / structure_max) * 200 if structure_max else 0
        x = 54 + idx * slot_w + ((slot_w - bar_w) / 2)
        y = 224 - h
        structure_parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w}" height="{h:.1f}" fill="#7f56d9" rx="6" />'
        )
        structure_parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{y - 8:.1f}" text-anchor="middle" fill="#3f2a80" font-size="12" font-weight="700">{value}</text>'
        )
        structure_parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="256" text-anchor="middle" fill="#4b5563" font-size="12">{_html.escape(label)}</text>'
        )
    structure_parts.append("</svg>")
    structure_svg = "".join(structure_parts)

    fn_items: list[tuple[str, int]] = []
    if isinstance(functions_payload, list):
        for item in functions_payload[:12]:
            if isinstance(item, dict):
                name = str(item.get("name", "fn"))
                s = int(item.get("start_line", 0) or 0)
                e = int(item.get("end_line", 0) or 0)
                length = (e - s + 1) if (s > 0 and e >= s) else 0
                fn_items.append((name, max(0, length)))
    if not fn_items:
        fn_items = [("No functions", 0)]

    fn_max = max(1, *(v for _, v in fn_items))
    fn_height = max(220, 48 + len(fn_items) * 28)
    fn_parts: list[str] = [
        f'<svg viewBox="0 0 640 {fn_height}" aria-label="Function length distribution chart">',
        f'<rect x="0" y="0" width="640" height="{fn_height}" fill="#ffffff" />',
    ]
    for idx, (name, value) in enumerate(fn_items):
        y = 24 + idx * 28
        w = (value / fn_max) * 430 if fn_max else 0
        fn_parts.append(f'<rect x="170" y="{y}" width="430" height="18" fill="#eef0f4" rx="4" />')
        fn_parts.append(
            f'<rect x="170" y="{y}" width="{w:.1f}" height="18" fill="#a78bfa" rx="4" />'
        )
        fn_parts.append(
            f'<text x="162" y="{y + 13}" text-anchor="end" fill="#4b5563" font-size="12">{_html.escape(name)}</text>'
        )
        fn_parts.append(
            f'<text x="{170 + w + 8:.1f}" y="{y + 13}" fill="#3f2a80" font-size="12" font-weight="700">{value} lines</text>'
        )
    fn_parts.append("</svg>")
    fn_svg = "".join(fn_parts)

    gauge_color = (
        "#22c55e" if complexity_index < 35 else "#f59e0b" if complexity_index < 65 else "#ef4444"
    )
    gauge_r = 82.0
    gauge_c = 2 * math.pi * gauge_r
    gauge_progress = gauge_c * (_clamp_pct(complexity_index) / 100.0)
    gauge_svg = (
        '<svg viewBox="0 0 220 220" aria-label="Complexity index gauge">'
        '<circle cx="110" cy="110" r="82" fill="#ffffff" stroke="#e5e7eb" stroke-width="1" />'
        '<circle cx="110" cy="110" r="82" fill="none" stroke="#eceff3" stroke-width="18" />'
        + f'<circle cx="110" cy="110" r="82" fill="none" stroke="{gauge_color}" stroke-width="18" stroke-dasharray="{gauge_progress:.2f} {gauge_c:.2f}" transform="rotate(-90 110 110)" />'
        + f'<text x="110" y="112" text-anchor="middle" fill="#3f2a80" font-size="34" font-weight="800">{complexity_index:.1f}</text>'
        + f'<text x="110" y="134" text-anchor="middle" fill="#6b7280" font-size="12">{_html.escape(complexity_band)} complexity</text>'
        + "</svg>"
    )

    flow_labels = [
        "Branches",
        "Loops",
        "Asserts",
        "External Calls",
        "Internal Calls",
        "Delegatecalls",
        "Event Emits",
    ]
    flow_values = [
        int(control_flow.get("branches", 0) or 0),
        int(control_flow.get("loops", 0) or 0),
        int(control_flow.get("asserts", 0) or 0),
        int(call_activity.get("external_calls", 0) or 0),
        int(call_activity.get("internal_calls", 0) or 0),
        int(call_activity.get("delegatecall_sites", 0) or 0),
        int(call_activity.get("event_emits", 0) or 0),
    ]
    flow_max = max(1, *flow_values)
    flow_svg_parts: list[str] = [
        '<svg viewBox="0 0 720 280" aria-label="Control and call activity chart">',
        '<rect x="0" y="0" width="720" height="280" fill="#ffffff" />',
    ]
    slot = 620 / max(1, len(flow_values))
    width = 52
    for i in range(5):
        y = 24 + i * 44
        flow_svg_parts.append(
            f'<line x1="72" y1="{y}" x2="690" y2="{y}" stroke="#eceff3" stroke-width="1" />'
        )
    for idx, (label, value) in enumerate(zip(flow_labels, flow_values, strict=True)):
        h = (value / flow_max) * 170 if flow_max else 0
        x = 72 + idx * slot + (slot - width) / 2
        y = 200 - h
        color = "#7f56d9" if idx < 3 else "#6d28d9"
        flow_svg_parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{width}" height="{h:.1f}" fill="{color}" rx="5" />'
        )
        flow_svg_parts.append(
            f'<text x="{x + width / 2:.1f}" y="{y - 8:.1f}" text-anchor="middle" fill="#3f2a80" font-size="12" font-weight="700">{value}</text>'
        )
        flow_svg_parts.append(
            f'<text x="{x + width / 2:.1f}" y="234" text-anchor="middle" fill="#4b5563" font-size="10">{_html.escape(label)}</text>'
        )
    flow_svg_parts.append("</svg>")
    flow_svg = "".join(flow_svg_parts)

    edges: list[tuple[str, str]] = []
    for edge in call_edges:
        if isinstance(edge, dict):
            a = str(edge.get("from", "")).strip()
            b = str(edge.get("to", "")).strip()
            if a and b:
                edges.append((a, b))

    fn_detail_map: dict[str, dict[str, object]] = {}
    for item in functions_detailed:
        if isinstance(item, dict):
            fn_name = str(item.get("name", "")).strip()
            if fn_name:
                fn_detail_map[fn_name] = item

    fn_meta_map: dict[str, dict[str, object]] = {}
    for item in functions_payload:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            if name:
                fn_meta_map[name] = item

    nodes = [str(item.get("name", "fn")) for item in functions_payload if isinstance(item, dict)]
    if not nodes and edges:
        nodes = sorted({a for a, _ in edges} | {b for _, b in edges})
    nodes = nodes[:24]

    seen_edges: set[tuple[str, str]] = set()
    unique_edges: list[tuple[str, str]] = []
    for a, b in edges:
        tup = (a, b)
        if tup not in seen_edges:
            seen_edges.add(tup)
            unique_edges.append(tup)
    edges = unique_edges

    def _var_preview(values: object) -> str:
        if not isinstance(values, list):
            return "—"
        vals = [str(v) for v in values if str(v).strip()]
        if not vals:
            return "—"
        if len(vals) == 1:
            return vals[0]
        return f"{vals[0]} +{len(vals) - 1}"

    node_w = 250.0
    node_h = 74.0
    top_y = 72.0
    row_gap = 16.0
    col_gap = 42.0
    left_margin = 24.0

    node_set = set(nodes)
    edges = [(a, b) for a, b in edges if a in node_set and b in node_set]

    adjacency: dict[str, list[str]] = {n: [] for n in nodes}
    indegree: dict[str, int] = {n: 0 for n in nodes}
    for a, b in edges:
        adjacency.setdefault(a, []).append(b)
        indegree[b] = indegree.get(b, 0) + 1

    def _is_external_fn(name: str) -> bool:
        meta = fn_meta_map.get(name, {})
        visibility = str(meta.get("visibility", "")).lower()
        if "external" in visibility:
            return True
        decorators = meta.get("decorators", [])
        if isinstance(decorators, list):
            for dec in decorators:
                if "external" in str(dec).lower():
                    return True
        return False

    roots = [n for n in nodes if _is_external_fn(n) and indegree.get(n, 0) == 0]
    roots.extend(n for n in nodes if indegree.get(n, 0) == 0 and n not in roots)
    if not roots and nodes:
        roots = [nodes[0]]

    depth: dict[str, int] = {n: 0 for n in nodes}
    frontier = list(roots)
    visited: set[str] = set()
    while frontier:
        current = frontier.pop(0)
        visited.add(current)
        base = depth.get(current, 0)
        for nxt in adjacency.get(current, []):
            if depth.get(nxt, 0) < base + 1:
                depth[nxt] = base + 1
            if nxt not in visited and nxt not in frontier:
                frontier.append(nxt)
    for _ in range(len(nodes)):
        changed = False
        for a, b in edges:
            candidate = depth.get(a, 0) + 1
            if depth.get(b, 0) < candidate:
                depth[b] = candidate
                changed = True
        if not changed:
            break

    depth_keys = sorted(set(depth.values()) or {0})
    columns: dict[int, list[str]] = {d: [] for d in depth_keys}
    for n in nodes:
        columns.setdefault(depth.get(n, 0), []).append(n)

    col_count = max(1, len(columns))
    diagram_w = left_margin * 2 + col_count * node_w + (col_count - 1) * col_gap
    sink_x = diagram_w + 22.0
    total_w = sink_x + 300.0 + 20.0
    max_rows = max((len(v) for v in columns.values()), default=1)
    graph_h = max(300.0, top_y + max_rows * (node_h + row_gap) + 34.0)

    node_pos: dict[str, tuple[float, float, float, float]] = {}
    for col_index, d in enumerate(depth_keys):
        names = columns.get(d, [])
        for row_index, name in enumerate(names):
            x = left_margin + col_index * (node_w + col_gap)
            y = top_y + row_index * (node_h + row_gap)
            node_pos[name] = (x, y, node_w, node_h)

    external_box = (sink_x, 64.0, 300.0, 72.0)
    storage_box = (sink_x, 166.0, 300.0, 72.0)

    graph_parts: list[str] = [
        f'<svg viewBox="0 0 {total_w:.0f} {graph_h:.0f}" aria-label="Function control flow and interaction block diagram">',
        "<defs>"
        '<marker id="arrow-int-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#7f56d9"/></marker>'
        '<marker id="arrow-int-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#0ea5e9"/></marker>'
        '<marker id="arrow-int-teal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#14b8a6"/></marker>'
        '<marker id="arrow-int-orange" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b"/></marker>'
        '<marker id="arrow-int-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626"/></marker>'
        '<marker id="arrow-ext" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#16a34a"/></marker>'
        '<marker id="arrow-read" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#2563eb"/></marker>'
        '<marker id="arrow-write" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#f97316"/></marker>'
        "</defs>",
        f'<rect x="0" y="0" width="{total_w:.0f}" height="{graph_h:.0f}" fill="#ffffff" />',
        '<text x="24" y="26" fill="#4b5563" font-size="12">solid: internal control flow (multi-color by path)</text>',
        '<text x="390" y="26" fill="#6b7280" font-size="12">dashed: external/state interactions</text>',
        f'<rect x="{external_box[0]}" y="{external_box[1]}" width="{external_box[2]}" height="{external_box[3]}" rx="10" fill="#f5f3ff" stroke="#c4b5fd" />',
        f'<text x="{external_box[0] + 12}" y="{external_box[1] + 24}" fill="#5b3da5" font-size="13" font-weight="700">External Surface</text>',
        f'<text x="{external_box[0] + 12}" y="{external_box[1] + 44}" fill="#6b7280" font-size="12">send/raw_call/create_*</text>',
        f'<rect x="{storage_box[0]}" y="{storage_box[1]}" width="{storage_box[2]}" height="{storage_box[3]}" rx="10" fill="#f9fafb" stroke="#d1d5db" />',
        f'<text x="{storage_box[0] + 12}" y="{storage_box[1] + 24}" fill="#374151" font-size="13" font-weight="700">State Surface</text>',
        f'<text x="{storage_box[0] + 12}" y="{storage_box[1] + 44}" fill="#6b7280" font-size="12">self.* reads / writes</text>',
    ]

    for col_index, _d in enumerate(depth_keys):
        col_x = left_margin + col_index * (node_w + col_gap)
        graph_parts.append(
            f'<text x="{col_x}" y="44" fill="#6b7280" font-size="11" font-weight="600">L{col_index} flow stage</text>'
        )

    connector_parts: list[str] = []
    node_parts: list[str] = []

    for idx, name in enumerate(nodes):
        x, y, w, h = node_pos[name]
        item = fn_detail_map.get(name, {})
        ext = int(item.get("external_calls", 0) or 0)
        ints = item.get("internal_calls", [])
        int_count = len(ints) if isinstance(ints, list) else 0
        branches = int(item.get("branch_count", 0) or 0)
        loops = int(item.get("loop_count", 0) or 0)
        asserts = int(item.get("assert_count", 0) or 0)
        reads = item.get("state_reads", [])
        writes = item.get("state_writes", [])

        cf_score = branches + loops + asserts
        if cf_score > 3:
            fill = "#fff7ed"
            stroke = "#fdba74"
        elif cf_score > 0:
            fill = "#faf8ff"
            stroke = "#d8cdf8"
        else:
            fill = "#f8fafc"
            stroke = "#d1d5db"

        node_parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" />'
        )
        node_parts.append(
            f'<text x="{x + 12}" y="{y + 22}" fill="#3f2a80" font-size="13" font-weight="700">{_html.escape(name)}</text>'
        )
        node_parts.append(
            f'<text x="{x + 12}" y="{y + 42}" fill="#4b5563" font-size="11">'
            f"int:{int_count} ext:{ext} cf:{branches}/{loops}/{asserts}</text>"
        )
        node_parts.append(
            f'<text x="{x + 12}" y="{y + 60}" fill="#6b7280" font-size="11">'
            f"r:{_html.escape(_var_preview(reads))}  w:{_html.escape(_var_preview(writes))}</text>"
        )

        if ext > 0:
            sx = x + w
            sy = y + 24
            tx = external_box[0]
            ty = external_box[1] + 22 + (idx % 4) * 10
            path = f"M {sx:.1f} {sy:.1f} C {sx + 32:.1f} {sy:.1f}, {tx - 26:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"
            connector_parts.append(
                f'<path d="{path}" fill="none" stroke="#16a34a" stroke-width="1.4" stroke-dasharray="4 3" marker-end="url(#arrow-ext)" opacity="0.85" />'
            )
        read_count = len(reads) if isinstance(reads, list) else 0
        if read_count > 0:
            sx = storage_box[0]
            sy = storage_box[1] + 20 + (idx % 4) * 10
            tx = x + w
            ty = y + 46
            path = f"M {sx:.1f} {sy:.1f} C {sx - 24:.1f} {sy:.1f}, {tx + 20:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"
            connector_parts.append(
                f'<path d="{path}" fill="none" stroke="#2563eb" stroke-width="1.2" stroke-dasharray="2 3" marker-end="url(#arrow-read)" opacity="0.85" />'
            )
        write_count = len(writes) if isinstance(writes, list) else 0
        if write_count > 0:
            sx = x + w
            sy = y + 60
            tx = storage_box[0]
            ty = storage_box[1] + 34 + (idx % 4) * 8
            path = f"M {sx:.1f} {sy:.1f} C {sx + 22:.1f} {sy:.1f}, {tx - 22:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"
            connector_parts.append(
                f'<path d="{path}" fill="none" stroke="#f97316" stroke-width="1.3" stroke-dasharray="3 3" marker-end="url(#arrow-write)" opacity="0.85" />'
            )

    drawn_edges = 0
    internal_palette = [
        ("#7f56d9", "url(#arrow-int-purple)"),
        ("#0ea5e9", "url(#arrow-int-blue)"),
        ("#14b8a6", "url(#arrow-int-teal)"),
        ("#f59e0b", "url(#arrow-int-orange)"),
    ]

    for edge_idx, (a, b) in enumerate(edges):
        if drawn_edges >= 180:
            break
        pa = node_pos.get(a)
        pb = node_pos.get(b)
        if pa is None or pb is None:
            continue
        ax, ay, aw, ah = pa
        bx, by, bw, bh = pb

        sx = ax + aw
        sy = ay + ah / 2
        tx = bx
        ty = by + bh / 2
        if tx < sx:
            sx = ax
            tx = bx + bw

        forward = depth.get(b, 0) >= depth.get(a, 0)
        if forward:
            color, marker = internal_palette[edge_idx % len(internal_palette)]
            mid_x = (sx + tx) / 2
            path = f"M {sx:.1f} {sy:.1f} C {mid_x:.1f} {sy:.1f}, {mid_x:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"
            connector_parts.append(
                f'<path d="{path}" fill="none" stroke="{color}" stroke-width="1.7" marker-end="{marker}" opacity="0.88" />'
            )
        else:
            bend = 36.0
            path = f"M {sx:.1f} {sy:.1f} C {sx + bend:.1f} {sy - bend:.1f}, {tx - bend:.1f} {ty - bend:.1f}, {tx:.1f} {ty:.1f}"
            connector_parts.append(
                f'<path d="{path}" fill="none" stroke="#dc2626" stroke-width="1.6" stroke-dasharray="5 3" marker-end="url(#arrow-int-red)" opacity="0.85" />'
            )
        drawn_edges += 1

    graph_parts.extend(connector_parts)
    graph_parts.extend(node_parts)

    if not edges:
        graph_parts.append(
            '<text x="24" y="270" fill="#6b7280" font-size="13">No internal function-to-function call edges detected.</text>'
        )

    graph_parts.append("</svg>")
    call_graph_svg = "".join(graph_parts)

    detail_rows = []
    for item in functions_detailed[:80]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "fn"))
        ext = int(item.get("external_calls", 0) or 0)
        ints = item.get("internal_calls", [])
        int_count = len(ints) if isinstance(ints, list) else 0
        branches = int(item.get("branch_count", 0) or 0)
        loops = int(item.get("loop_count", 0) or 0)
        asserts = int(item.get("assert_count", 0) or 0)
        reads = item.get("state_reads", [])
        writes = item.get("state_writes", [])
        reads_count = len(reads) if isinstance(reads, list) else 0
        writes_count = len(writes) if isinstance(writes, list) else 0
        detail_rows.append(
            f'<tr><td>{_html.escape(name)}</td><td class="val">{ext}</td><td class="val">{int_count}</td>'
            f'<td class="val">{branches}/{loops}/{asserts}</td><td class="val">{reads_count}/{writes_count}</td></tr>'
        )
    if not detail_rows:
        detail_rows.append(
            '<tr><td colspan="5">No function-level behavioral data available.</td></tr>'
        )
    function_behavior_html = "".join(detail_rows)

    kpi_cards = [
        ("Total Lines", total_lines),
        ("Code Lines", code_lines),
        ("Comment Lines", comment_lines),
        ("Blank Lines", blank_lines),
        ("Functions", functions),
        ("State Variables", state_vars),
        ("Events", events),
        ("Imports", imports),
    ]
    kpi_html = "".join(
        '<div class="kpi">'
        + f'<div class="label">{_html.escape(label)}</div>'
        + f'<div class="value">{value}</div>'
        + "</div>"
        for label, value in kpi_cards
    )

    legend_html = "".join(
        '<div class="row">'
        + f'<span class="dot" style="background:{color}"></span>'
        + f"<span>{_html.escape(label)}</span>"
        + f"<strong>{pct:.1f}%</strong>"
        + "</div>"
        for label, pct, color in line_segments
    )

    insights_html = "".join(
        [
            f'<tr><td>Avg Function Length</td><td class="val">{avg_fn_len:.1f} lines</td><td>Longer functions can increase audit complexity.</td></tr>',
            f'<tr><td>State Variables per Function</td><td class="val">{state_per_fn:.2f}</td><td>Higher ratios indicate state-heavy behavior.</td></tr>',
            f'<tr><td>Events per Function</td><td class="val">{event_per_fn:.2f}</td><td>Low ratios can reduce observability.</td></tr>',
            f'<tr><td>Complexity Index</td><td class="val">{complexity_index:.1f} / 100 ({_html.escape(complexity_band)})</td><td>Composite heuristic from size, state, and function profile.</td></tr>',
        ]
    )

    payload_json = _json.dumps(payload, ensure_ascii=False, indent=2)

    html = f"""<!doctype html>
<html lang="en">
<head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Vyper Guard Stats Graph — {_html.escape(file_label)}</title>
        <style>
                :root {{
                        --bg: #ffffff;
                        --panel: #ffffff;
                        --panel-2: #f8f7fd;
                        --stroke: #e4e1ef;
                        --text: #2f215c;
                        --muted: #6b7280;
                }}
                * {{ box-sizing: border-box; }}
                body {{
                        margin: 0;
                        font-family: Inter, "Segoe UI", Roboto, Arial, sans-serif;
                        background: var(--bg);
                        color: var(--text);
                        padding: 24px;
                }}
                .wrap {{ max-width: 1260px; margin: 0 auto; }}
                .hero {{
                        background: linear-gradient(180deg, #fcfbff 0%, #f6f3ff 100%);
                        border: 1px solid var(--stroke);
                        border-radius: 16px;
                        padding: 18px 20px;
                        margin-bottom: 16px;
                }}
                .hero h1 {{ margin: 0; font-size: 22px; letter-spacing: 0.02em; }}
                .hero .file {{ color: var(--muted); margin-top: 6px; word-break: break-all; }}
                .chips {{ margin-top: 10px; display: flex; gap: 10px; flex-wrap: wrap; }}
                .chip {{
                    border: 1px solid #d9cff5;
                    background: #f4edff;
                        border-radius: 999px;
                        padding: 6px 12px;
                    color: #5b3da5;
                        font-size: 12px;
                }}
                .kpis {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
                        gap: 12px;
                        margin-bottom: 16px;
                }}
                .kpi {{
                        background: var(--panel);
                        border: 1px solid var(--stroke);
                        border-radius: 12px;
                        padding: 12px;
                }}
                .kpi .label {{
                        color: var(--muted);
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: .06em;
                }}
                .kpi .value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
                .grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
                        gap: 14px;
                }}
                .panel {{
                        background: var(--panel);
                        border: 1px solid var(--stroke);
                        border-radius: 14px;
                        padding: 14px;
                        min-height: 300px;
                }}
                .panel h2 {{
                        margin: 0 0 10px 0;
                        font-size: 14px;
                        text-transform: uppercase;
                        letter-spacing: .08em;
                    color: #5b3da5;
                }}
                .chart {{ width: 100%; }}
                .legend {{
                        margin-top: 8px;
                        display: grid;
                        grid-template-columns: 1fr;
                        gap: 6px;
                        font-size: 13px;
                }}
                .legend .row {{
                        display: grid;
                        grid-template-columns: 12px 1fr auto;
                        align-items: center;
                        gap: 8px;
                    color: #4b5563;
                }}
                .dot {{ width: 12px; height: 12px; border-radius: 3px; }}
                table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 8px;
                        font-size: 13px;
                }}
                th, td {{
                    border: 1px solid #e5e7eb;
                        padding: 8px 10px;
                        text-align: left;
                }}
                th {{ background: var(--panel-2); color: #4b5563; }}
                td {{ background: #ffffff; }}
                .val {{ font-weight: 700; color: #5b3da5; white-space: nowrap; }}
                .payload-json {{ display:none; }}
        </style>
</head>
<body>
        <div class="wrap">
                <section class="hero">
                        <h1>Vyper Guard Stats Graph — Contract Metrics Dashboard</h1>
                        <div class="file">{_html.escape(file_label)}</div>
                        <div class="chips">
                                <div class="chip">Static profile</div>
                                <div class="chip">Visualization-ready report</div>
                                <div class="chip">Security audit baseline</div>
                        </div>
                </section>

                <section class="kpis">{kpi_html}</section>

                <section class="grid">
                        <article class="panel">
                                <h2>Line Composition (Donut)</h2>
                                <div class="chart">{donut_svg}</div>
                                <div class="legend">{legend_html}</div>
                        </article>

                        <article class="panel">
                                <h2>Structure Counts</h2>
                                <div class="chart">{structure_svg}</div>
                        </article>

                        <article class="panel">
                                <h2>Function Length Distribution</h2>
                                <div class="chart">{fn_svg}</div>
                        </article>

                        <article class="panel">
                                <h2>Complexity Signal</h2>
                                <div class="chart">{gauge_svg}</div>
                                <table>
                                        <thead><tr><th>Metric</th><th>Value</th><th>Interpretation</th></tr></thead>
                                        <tbody>{insights_html}</tbody>
                                </table>
                        </article>

                            <article class="panel" style="grid-column: 1 / -1;">
                                <h2>Execution & Control Signals</h2>
                                <div class="chart">{flow_svg}</div>
                            </article>

                            <article class="panel" style="grid-column: 1 / -1;">
                                <h2>Function Call Graph (Internal)</h2>
                                <div class="chart">{call_graph_svg}</div>
                            </article>

                            <article class="panel" style="grid-column: 1 / -1;">
                                <h2>Function-Level Behavior</h2>
                                <table>
                                    <thead><tr><th>Function</th><th>External Calls</th><th>Internal Calls</th><th>Branches/Loops/Asserts</th><th>State Reads/Writes</th></tr></thead>
                                    <tbody>{function_behavior_html}</tbody>
                                </table>
                            </article>
                </section>
        </div>

        <pre id="payload-json" class="payload-json">{_html.escape(payload_json)}</pre>
</body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")


@app.command()
def stats(
    file_path: Path = typer.Argument(
        ...,
        help="Path to the .vy contract.",
        exists=True,
        readable=True,
    ),
    graph: bool = typer.Option(
        False,
        "--graph",
        help="Export JSON + HTML stats graph artifacts beside the contract.",
    ),
    graph_json: Path | None = typer.Option(
        None,
        "--graph-json",
        help="Custom path for stats graph JSON output.",
    ),
    graph_html: Path | None = typer.Option(
        None,
        "--graph-html",
        help="Custom path for stats graph HTML output.",
    ),
) -> None:
    """Show contract statistics, structure & complexity overview."""
    from guardian.analyzer.ast_parser import parse_vyper_source
    from guardian.analyzer.semantic import build_semantic_summary
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

    semantic = build_semantic_summary(contract)
    function_names = {func.name for func in contract.functions}

    control_flow = {
        "branches": 0,
        "loops": 0,
        "asserts": 0,
    }
    call_activity = {
        "external_calls": 0,
        "internal_calls": 0,
        "delegatecall_sites": 0,
        "event_emits": 0,
    }
    call_edges: list[dict[str, str]] = []
    functions_detailed: list[dict[str, object]] = []

    for func in sorted(contract.functions, key=lambda f: f.start_line):
        sem_fn = semantic.functions.get(func.name)
        body_text = func.body_text

        branch_count = len(re.findall(r"(?m)^\s*(if|elif)\b", body_text))
        loop_count = len(re.findall(r"(?m)^\s*for\b", body_text))
        assert_count = len(re.findall(r"(?m)^\s*assert\b", body_text))

        internal_callees = sorted(
            {
                name
                for name in re.findall(r"\bself\.(\w+)\s*\(", body_text)
                if name in function_names and name != func.name
            }
        )

        external_calls = sem_fn.external_calls if sem_fn else 0
        delegatecall_flag = sem_fn.uses_delegatecall if sem_fn else False
        emits_event = sem_fn.emits_event if sem_fn else False
        state_reads = sorted(sem_fn.state_reads) if sem_fn else []
        state_writes = sorted(sem_fn.state_writes) if sem_fn else []
        external_calls_in_loop = sem_fn.external_calls_in_loop if sem_fn else False

        control_flow["branches"] += branch_count
        control_flow["loops"] += loop_count
        control_flow["asserts"] += assert_count

        call_activity["external_calls"] += int(external_calls)
        call_activity["internal_calls"] += len(internal_callees)
        call_activity["delegatecall_sites"] += int(delegatecall_flag)
        call_activity["event_emits"] += int(emits_event)

        for callee in internal_callees:
            call_edges.append({"from": func.name, "to": callee})

        functions_detailed.append(
            {
                "name": func.name,
                "start_line": func.start_line,
                "end_line": func.end_line,
                "external_calls": external_calls,
                "internal_calls": internal_callees,
                "branch_count": branch_count,
                "loop_count": loop_count,
                "assert_count": assert_count,
                "state_reads": state_reads,
                "state_writes": state_writes,
                "emits_event": emits_event,
                "uses_delegatecall": delegatecall_flag,
                "external_calls_in_loop": external_calls_in_loop,
            }
        )

    stats_payload: dict[str, object] = {
        "file": str(file_path),
        "pragma_version": contract.pragma_version,
        "metrics": {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "comment_lines": comment_lines,
            "blank_lines": blank_lines,
            "functions": len(contract.functions),
            "state_variables": len(contract.state_variables),
            "events": len(contract.events),
            "imports": len(contract.imports),
        },
        "line_breakdown": {
            "code_pct": (code_lines / total_lines * 100) if total_lines else 0.0,
            "comment_pct": (comment_lines / total_lines * 100) if total_lines else 0.0,
            "blank_pct": (blank_lines / total_lines * 100) if total_lines else 0.0,
        },
        "functions": [
            {
                "name": func.name,
                "start_line": func.start_line,
                "end_line": func.end_line,
                "decorators": list(func.decorators),
            }
            for func in sorted(contract.functions, key=lambda f: f.start_line)
        ],
        "state_variables": [
            {
                "name": var.name,
                "type": var.type_annotation,
                "line_number": var.line_number,
                "public": var.is_public,
                "constant": var.is_constant,
                "immutable": var.is_immutable,
            }
            for var in contract.state_variables
        ],
        "events": [
            {
                "name": event.name,
                "line_number": event.line_number,
                "fields": list(event.fields),
            }
            for event in contract.events
        ],
        "imports": list(contract.imports),
        "control_flow": control_flow,
        "call_activity": call_activity,
        "call_edges": call_edges,
        "functions_detailed": functions_detailed,
    }

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
            f"[#7f56d9]{'█' * code_bar}[/#7f56d9]"
            f"[#a78bfa]{'█' * comment_bar}[/#a78bfa]"
            f"[#ddd6fe]{'░' * blank_bar}[/#ddd6fe]"
        )
        console.print(f"  {bar_str}")
        console.print(
            f"  [#7f56d9]■ Code {code_pct:.0f}%[/#7f56d9]  "
            f"[#a78bfa]■ Comments {comment_pct:.0f}%[/#a78bfa]  "
            f"[#ddd6fe]■ Blank {blank_pct:.0f}%[/#ddd6fe]"
        )
        console.print()

    # ── Analytical insights ──
    fn_lengths = [
        (func.end_line - func.start_line + 1)
        for func in contract.functions
        if func.end_line >= func.start_line
    ]
    avg_fn_len = (sum(fn_lengths) / len(fn_lengths)) if fn_lengths else 0.0
    state_per_fn = (
        (len(contract.state_variables) / len(contract.functions)) if contract.functions else 0.0
    )
    event_per_fn = (len(contract.events) / len(contract.functions)) if contract.functions else 0.0
    complexity_index = min(
        100.0,
        (len(contract.functions) * 2.2)
        + (len(contract.state_variables) * 1.4)
        + (len(contract.imports) * 6.0)
        + (len(contract.events) * 0.8)
        + (avg_fn_len * 0.9),
    )
    complexity_band = (
        "Low" if complexity_index < 35 else "Moderate" if complexity_index < 65 else "High"
    )

    insight_table = Table(
        title="[bold]🧠 Analytical Insights[/bold]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        expand=True,
    )
    insight_table.add_column("Metric", style=f"bold {ACCENT}", min_width=24)
    insight_table.add_column("Value", style="bold white", width=22)
    insight_table.add_column("Interpretation")
    insight_table.add_row(
        "Avg Function Length",
        f"{avg_fn_len:.1f} lines",
        "Longer functions can increase audit complexity.",
    )
    insight_table.add_row(
        "State Variables / Function",
        f"{state_per_fn:.2f}",
        "Higher ratio indicates state-heavy behavior.",
    )
    insight_table.add_row(
        "Events / Function", f"{event_per_fn:.2f}", "Lower ratio can reduce on-chain observability."
    )
    insight_table.add_row(
        "Complexity Index",
        f"{complexity_index:.1f} / 100 ({complexity_band})",
        "Composite heuristic from size, state, and function profile.",
    )
    console.print(insight_table)
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

    should_export_graph = graph or graph_json is not None or graph_html is not None
    if should_export_graph:
        default_base = file_path.with_suffix("")
        json_path = graph_json or default_base.with_suffix(".stats.json")
        html_path = graph_html or default_base.with_suffix(".stats.html")
        _write_stats_graph_artifacts(stats_payload, json_path=json_path, html_path=html_path)
        console.print(f"[{OK}]Stats graph JSON written:[/{OK}] {json_path}")
        console.print(f"[{OK}]Stats graph HTML written:[/{OK}] {html_path}")
        console.print()

    console.print(Rule(f"[dim]{__app_name__} v{__version__}[/dim]", style="dim"))
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  diff — compare two contracts' security
# ═══════════════════════════════════════════════════════════════════


@app.command()
def diff(
    file_a: Path = typer.Argument(
        ...,
        help="First .vy contract (baseline / old version).",
        exists=True,
        readable=True,
    ),
    file_b: Path = typer.Argument(
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

    # ── New / fixed findings ──
    # Use a content-based key instead of line number only to reduce
    # false churn from formatting-driven line shifts.
    def _diff_key(finding: DetectorResult) -> tuple[str, str, str, str]:
        return (
            finding.detector_name,
            finding.vulnerability_type.value,
            finding.severity.value,
            finding.title.strip().lower(),
        )

    keys_a = {_diff_key(f) for f in report_a.findings}
    new_in_b = [f for f in report_b.findings if _diff_key(f) not in keys_a]

    keys_b = {_diff_key(f) for f in report_b.findings}
    fixed_in_b = [f for f in report_a.findings if _diff_key(f) not in keys_b]

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

remediation:
    # Maximum auto-remediation risk tier to auto-apply: A, B, C
    max_auto_fix_tier: C

ai_triage:
    enabled: false
    # Minimum severity included in triage table
    min_severity: LOW
    # Cap triage rows for noisy contracts
    max_items: 50
    # Governance policy state (stable | experimental | deprecated)
    policy_status: stable
    # Deprecation lifecycle controls
    deprecation_announced: false
    deprecation_sunset_after: null

llm:
    # Enable LLM-backed triage/agent features
    enabled: false
    # Provider type (currently openai_compatible)
    provider: openai_compatible
    # Model name for API calls
    model: gpt-5
    # OpenAI-compatible API base URL
    base_url: https://api.openai.com/v1
    # Prefer setting via env: GUARDIAN_LLM_API_KEY
    api_key: null
    # Low temperature for stable security triage
    temperature: 0.1
    # Agent memory JSONL location
    memory_file: .guardian_agent_memory.jsonl
    # Max retained entries in agent memory JSONL file
    memory_max_entries: 2000

explorer:
    provider: etherscan
    network: ethereum
    # Prefer setting via env: GUARDIAN_EXPLORER_API_KEY
    api_key: null
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
    max_backfill_blocks: int = typer.Option(
        250,
        "--max-backfill-blocks",
        help="Maximum historical blocks processed per poll iteration.",
        min=1,
    ),
    max_history_records: int = typer.Option(
        50_000,
        "--max-history-records",
        help="Maximum in-memory transaction history records retained for analytics.",
        min=1,
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
    baseline_file: Path | None = typer.Option(
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
            f"\n  [{DIM}]Install monitoring dependencies:[/{DIM}]  pip install 'vyper-guard[[monitor]]'"
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
            max_backfill_blocks=max_backfill_blocks,
        )
    except Web3NotAvailableError as exc:
        console.print(f"[{ERR}]{exc}[/{ERR}]")
        console.print(
            f"\n  [{DIM}]Install monitoring dependencies:[/{DIM}]  pip install 'vyper-guard[[monitor]]'"
        )
        raise typer.Exit(code=2) from exc

    if not watcher.is_connected():
        console.print(f"[{ERR}]Cannot connect to RPC endpoint:[/{ERR}] {rpc}")
        raise typer.Exit(code=2)

    console.print(f"  [{OK}]Connected[/{OK}] to {rpc}  •  Block: {watcher.get_latest_block()}")

    tx_analyzer = TxAnalyzer(max_records=max_history_records)
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
    max_backfill_blocks: int = typer.Option(
        250,
        "--max-backfill-blocks",
        help="Maximum historical blocks processed per poll iteration.",
        min=1,
    ),
    max_history_records: int = typer.Option(
        50_000,
        "--max-history-records",
        help="Maximum in-memory transaction history records retained while profiling.",
        min=1,
    ),
    output: Path | None = typer.Option(
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
            f"\n  [{DIM}]Install monitoring dependencies:[/{DIM}]  pip install 'vyper-guard[[monitor]]'"
        )
        raise typer.Exit(code=2) from exc

    from guardian.monitor.baseline import BaselineProfiler

    try:
        watcher = ChainWatcher(
            contract_address=address,
            rpc_url=rpc,
            poll_interval=2.0,
            max_backfill_blocks=max_backfill_blocks,
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
        max_records=max_history_records,
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
