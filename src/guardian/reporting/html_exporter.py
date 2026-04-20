"""HTML report exporter.

Builds professional, analysis-dense HTML reports for single analysis runs.
"""

from __future__ import annotations

import html as _html
import json
import re
from pathlib import Path
from typing import Any

from guardian import __version__
from guardian.models import AnalysisReport, DetectorResult, Severity
from guardian.reporting.json_exporter import _prepare_output_path, report_to_dict

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#1d4ed8",
    Severity.INFO: "#0f766e",
}

_SEVERITY_SOFT_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#fee2e2",
    Severity.HIGH: "#ffedd5",
    Severity.MEDIUM: "#fef9c3",
    Severity.LOW: "#dbeafe",
    Severity.INFO: "#ccfbf1",
}


def _escape(value: object) -> str:
    return _html.escape(str(value))


def _finding_location(finding: DetectorResult) -> str:
    if finding.line_number is None:
        return "—"
    if finding.end_line_number is not None and finding.end_line_number != finding.line_number:
        return f"L{finding.line_number}-L{finding.end_line_number}"
    return f"L{finding.line_number}"


def _severity_counts(report: AnalysisReport) -> dict[Severity, int]:
    return {sev: sum(1 for f in report.findings if f.severity == sev) for sev in _SEVERITY_ORDER}


def _read_source_if_available(file_path: str) -> str:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _analyze_contract_source(source: str) -> dict[str, Any]:
    if not source.strip():
        return {
            "line_total": 0,
            "line_code": 0,
            "line_comment": 0,
            "line_blank": 0,
            "max_line_length": 0,
            "imports": [],
            "events": [],
            "state_variables": [],
            "functions": [],
            "internal_call_edges": [],
            "external_calls": 0,
            "send_calls": 0,
            "delegate_calls": 0,
            "create_calls": 0,
            "selfdestruct_calls": 0,
        }

    lines = source.splitlines()
    line_total = len(lines)
    line_blank = sum(1 for line in lines if not line.strip())
    line_comment = sum(1 for line in lines if line.strip().startswith("#"))
    line_code = line_total - line_blank - line_comment
    max_line_length = max((len(line) for line in lines), default=0)

    imports = sorted(
        {
            m.group(0).strip()
            for m in re.finditer(
                r"^\s*(import\s+[^\n]+|from\s+[^\n]+\s+import\s+[^\n]+)", source, flags=re.MULTILINE
            )
        }
    )

    events = sorted(
        {
            m.group(1)
            for m in re.finditer(
                r"^\s*event\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", source, flags=re.MULTILINE
            )
        }
    )

    top_level_lines = [line for line in lines if line and not line.startswith((" ", "\t"))]
    state_variables: list[str] = []
    for line in top_level_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("def ", "event ", "import ", "from ", "@")):
            continue
        if ":" in stripped and "(" not in stripped:
            state_variables.append(stripped)

    fn_matches = list(
        re.finditer(
            r"(?m)^(?P<header>(?:\s*@[^\n]+\n)*)\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^)]*)\)\s*(?:->\s*(?P<ret>[^:]+))?:",
            source,
        )
    )
    functions: list[dict[str, Any]] = []
    function_names = [m.group("name") for m in fn_matches]

    for idx, match in enumerate(fn_matches):
        start = match.start()
        end = fn_matches[idx + 1].start() if idx + 1 < len(fn_matches) else len(source)
        body = source[start:end]
        header = match.group("header") or ""
        decorators = [d.strip()[1:] for d in header.splitlines() if d.strip().startswith("@")]

        functions.append(
            {
                "name": match.group("name"),
                "args": (match.group("args") or "").strip(),
                "return_type": (match.group("ret") or "").strip() or "—",
                "decorators": decorators,
                "lines": len(body.splitlines()),
                "raw_call": bool(re.search(r"\braw_call\s*\(", body)),
                "send": bool(re.search(r"\bsend\s*\(", body)),
                "state_write": bool(
                    re.search(r"\bself\.[A-Za-z_][A-Za-z0-9_]*\s*[+\-*/%]?=", body)
                ),
            }
        )

    edges: list[tuple[str, str]] = []
    for idx, match in enumerate(fn_matches):
        caller = match.group("name")
        start = match.start()
        end = fn_matches[idx + 1].start() if idx + 1 < len(fn_matches) else len(source)
        body = source[start:end]
        for callee in function_names:
            if callee == caller:
                continue
            if re.search(rf"\b{re.escape(callee)}\s*\(", body):
                edges.append((caller, callee))

    return {
        "line_total": line_total,
        "line_code": line_code,
        "line_comment": line_comment,
        "line_blank": line_blank,
        "max_line_length": max_line_length,
        "imports": imports,
        "events": events,
        "state_variables": state_variables,
        "functions": functions,
        "internal_call_edges": sorted(set(edges)),
        "external_calls": len(re.findall(r"\braw_call\s*\(", source)),
        "send_calls": len(re.findall(r"\bsend\s*\(", source)),
        "delegate_calls": len(re.findall(r"is_delegate_call\s*=\s*True", source)),
        "create_calls": len(
            re.findall(r"\bcreate_(?:minimal_proxy_to|copy_of|from_blueprint)\s*\(", source)
        ),
        "selfdestruct_calls": len(re.findall(r"\bselfdestruct\s*\(", source)),
    }


def _severity_bar_html(report: AnalysisReport) -> str:
    counts = _severity_counts(report)
    total = max(1, len(report.findings))
    rows: list[str] = []
    for sev in _SEVERITY_ORDER:
        count = counts[sev]
        pct = (count / total) * 100
        rows.append(
            "<div class='sev-row'>"
            f"<div class='sev-label'><span class='dot' style='background:{_SEVERITY_COLORS[sev]}'></span>{_escape(sev.value)}</div>"
            f"<div class='sev-track'><div class='sev-fill' style='width:{pct:.2f}%; background:{_SEVERITY_COLORS[sev]}'></div></div>"
            f"<div class='sev-count'>{count}</div>"
            "</div>"
        )
    return "".join(rows)


def _line_composition_chart_html(stats: dict[str, Any]) -> str:
    total = max(1, int(stats["line_total"]))
    parts = [
        ("Code", int(stats["line_code"]), "#1d4ed8"),
        ("Comments", int(stats["line_comment"]), "#0f766e"),
        ("Blank", int(stats["line_blank"]), "#94a3b8"),
    ]
    rows: list[str] = []
    for label, value, color in parts:
        pct = value / total * 100
        rows.append(
            "<div class='hrow'>"
            f"<div class='hlabel'>{_escape(label)}</div>"
            f"<div class='htrack'><div class='hfill' style='width:{pct:.2f}%; background:{color}'></div></div>"
            f"<div class='hval'>{value} ({pct:.1f}%)</div>"
            "</div>"
        )
    return "".join(rows)


def _issue_map_html(report: AnalysisReport) -> str:
    categories = sorted({f.vulnerability_type.value for f in report.findings})
    if not categories:
        return "<div class='empty'>No findings available for mapping.</div>"

    matrix: dict[str, dict[Severity, int]] = {
        cat: {sev: 0 for sev in _SEVERITY_ORDER} for cat in categories
    }
    for finding in report.findings:
        matrix[finding.vulnerability_type.value][finding.severity] += 1

    header = "".join(f"<th>{_escape(sev.value)}</th>" for sev in _SEVERITY_ORDER)
    rows: list[str] = []
    for cat in categories:
        cols = []
        for sev in _SEVERITY_ORDER:
            value = matrix[cat][sev]
            cls = "cell-zero" if value == 0 else ""
            style = (
                ""
                if value == 0
                else f"background:{_SEVERITY_SOFT_COLORS[sev]}; color:{_SEVERITY_COLORS[sev]};"
            )
            cols.append(f"<td class='{cls}' style='{style}'>{value}</td>")
        rows.append(f"<tr><th>{_escape(cat)}</th>{''.join(cols)}</tr>")

    return (
        "<table class='table'>"
        "<thead><tr><th>Vulnerability Type</th>"
        f"{header}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _findings_overview_html(report: AnalysisReport) -> str:
    if not report.findings:
        return "<div class='empty'>No vulnerabilities detected.</div>"

    rows: list[str] = []
    for index, finding in enumerate(report.findings, start=1):
        sev_color = _SEVERITY_COLORS[finding.severity]
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td><span class='badge' style='background:{_SEVERITY_SOFT_COLORS[finding.severity]}; color:{sev_color};'>{_escape(finding.severity.value)}</span></td>"
            f"<td>{_escape(finding.confidence.value)}</td>"
            f"<td>{_escape(finding.detector_name)}</td>"
            f"<td>{_escape(finding.vulnerability_type.value)}</td>"
            f"<td>{_escape(_finding_location(finding))}</td>"
            f"<td>{_escape(finding.title)}</td>"
            "</tr>"
        )

    return (
        "<table class='table'>"
        "<thead><tr><th>#</th><th>Severity</th><th>Confidence</th><th>Detector</th><th>Type</th><th>Location</th><th>Title</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _function_inventory_html(stats: dict[str, Any]) -> str:
    functions = stats.get("functions", [])
    if not functions:
        return "<div class='empty'>No function inventory available.</div>"

    rows: list[str] = []
    for fn in sorted(functions, key=lambda item: str(item["name"])):
        decorators = ", ".join(str(item) for item in fn["decorators"]) or "—"
        rows.append(
            "<tr>"
            f"<td>{_escape(fn['name'])}</td>"
            f"<td>{_escape(fn['args'])}</td>"
            f"<td>{_escape(fn['return_type'])}</td>"
            f"<td>{_escape(decorators)}</td>"
            f"<td>{fn['lines']}</td>"
            f"<td>{'yes' if fn['raw_call'] else 'no'}</td>"
            f"<td>{'yes' if fn['send'] else 'no'}</td>"
            f"<td>{'yes' if fn['state_write'] else 'no'}</td>"
            "</tr>"
        )

    return (
        "<table class='table'>"
        "<thead><tr><th>Function</th><th>Arguments</th><th>Return</th><th>Decorators</th><th>Lines</th><th>raw_call</th><th>send</th><th>State Write</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _call_edges_html(stats: dict[str, Any]) -> str:
    edges = stats.get("internal_call_edges", [])
    if not edges:
        return "<div class='empty'>No internal call edges found.</div>"

    rows = "".join(f"<tr><td>{_escape(src)}</td><td>{_escape(dst)}</td></tr>" for src, dst in edges)
    return (
        "<table class='table'>"
        "<thead><tr><th>Caller</th><th>Callee</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
    )


def _remediation_plan_html(report: AnalysisReport) -> str:
    if not report.findings:
        return "<div class='empty'>No remediation actions required.</div>"

    priority = {
        Severity.CRITICAL: 1,
        Severity.HIGH: 2,
        Severity.MEDIUM: 3,
        Severity.LOW: 4,
        Severity.INFO: 5,
    }
    sorted_findings = sorted(
        report.findings, key=lambda f: (priority[f.severity], f.line_number or 10**9)
    )
    rows: list[str] = []
    for idx, finding in enumerate(sorted_findings, start=1):
        rows.append(
            "<tr>"
            f"<td>{idx}</td>"
            f"<td><span class='badge' style='background:{_SEVERITY_SOFT_COLORS[finding.severity]}; color:{_SEVERITY_COLORS[finding.severity]};'>{_escape(finding.severity.value)}</span></td>"
            f"<td>{_escape(finding.title)}</td>"
            f"<td>{_escape(_finding_location(finding))}</td>"
            f"<td>{_escape(finding.fix_suggestion or 'Manual review required')}</td>"
            "</tr>"
        )
    return (
        "<table class='table'>"
        "<thead><tr><th>Priority</th><th>Severity</th><th>Issue</th><th>Location</th><th>Recommended Action</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _finding_cards_html(report: AnalysisReport) -> str:
    if not report.findings:
        return ""

    cards: list[str] = []
    for index, finding in enumerate(report.findings, start=1):
        sev = finding.severity
        evidence = "".join(f"<li>{_escape(item)}</li>" for item in finding.evidence) or "<li>—</li>"
        source_block = (
            f"<pre>{_escape(finding.source_snippet)}</pre>"
            if finding.source_snippet
            else "<div class='muted'>No snippet available.</div>"
        )
        why_flagged = (
            _escape(finding.why_flagged)
            if finding.why_flagged
            else "No detector rationale text provided."
        )
        fix_suggestion = (
            _escape(finding.fix_suggestion)
            if finding.fix_suggestion
            else "No automatic remediation suggestion available."
        )

        cards.append(
            "<article class='finding-card'>"
            "<header class='finding-head'>"
            f"<h3>{index}. {_escape(finding.title)}</h3>"
            f"<span class='badge' style='background:{_SEVERITY_SOFT_COLORS[sev]}; color:{_SEVERITY_COLORS[sev]};'>{_escape(sev.value)}</span>"
            "</header>"
            "<div class='meta-grid'>"
            f"<div><strong>Detector</strong><span>{_escape(finding.detector_name)}</span></div>"
            f"<div><strong>Confidence</strong><span>{_escape(finding.confidence.value)}</span></div>"
            f"<div><strong>Type</strong><span>{_escape(finding.vulnerability_type.value)}</span></div>"
            f"<div><strong>Location</strong><span>{_escape(_finding_location(finding))}</span></div>"
            "</div>"
            "<section><h4>Description</h4>"
            f"<p>{_escape(finding.description)}</p></section>"
            "<section><h4>Detector rationale</h4>"
            f"<p>{why_flagged}</p></section>"
            "<section><h4>Evidence</h4>"
            f"<ul>{evidence}</ul></section>"
            "<section><h4>Remediation</h4>"
            f"<p>{fix_suggestion}</p></section>"
            "<section><h4>Source snippet</h4>"
            f"{source_block}</section>"
            "</article>"
        )

    return "".join(cards)


def export_html(report: AnalysisReport, output_path: str | Path | None = None) -> str:
    """Render a professional, analysis-focused HTML report for one analysis result."""
    counts = _severity_counts(report)
    source = _read_source_if_available(report.file_path)
    stats = _analyze_contract_source(source)
    payload = report_to_dict(report)
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)
    context_json = json.dumps(report.analysis_context or {}, indent=2, ensure_ascii=False)
    imports_text = "\n".join(stats["imports"]) or "None"
    events_text = "\n".join(stats["events"]) or "None"
    state_vars_text = "\n".join(stats["state_variables"]) or "None"

    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Vyper Guard Security Report — {_escape(report.file_path)}</title>
  <style>
    :root {{ --bg:#f6f7f9; --surface:#ffffff; --surface-soft:#fafbfc; --stroke:#d7dde6; --text:#0f172a; --muted:#64748b; --head:#0f172a; --link:#1d4ed8; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family:Inter,Segoe UI,Roboto,Arial,sans-serif; font-size:13px; }}
    .container {{ max-width:1280px; margin:0 auto; padding:18px; }}
    .hero {{ background:var(--head); color:#fff; border-radius:10px; padding:14px 16px; }}
    .hero h1 {{ margin:0; font-size:20px; font-weight:700; letter-spacing:.01em; }}
    .hero p {{ margin:6px 0 0 0; color:#cbd5e1; font-size:12px; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:8px; margin-top:10px; }}
    .card {{ background:var(--surface); border:1px solid var(--stroke); border-radius:8px; padding:9px 10px; min-height:0; }}
    .card .k {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }}
    .card .v {{ margin-top:4px; font-size:18px; font-weight:700; color:#111827; }}
    .grid {{ margin-top:10px; display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }}
    .panel {{ background:var(--surface); border:1px solid var(--stroke); border-radius:8px; padding:10px; overflow:hidden; }}
    .panel h2 {{ margin:0 0 8px 0; font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:#334155; }}
    .stack {{ margin-top:10px; }}
    .sev-row,.hrow {{ display:grid; grid-template-columns:170px 1fr 120px; gap:8px; align-items:center; margin:7px 0; }}
    .sev-label,.hlabel {{ font-size:13px; color:#334155; display:flex; align-items:center; gap:8px; font-weight:600; }}
    .dot {{ width:10px; height:10px; border-radius:999px; display:inline-block; }}
    .sev-track,.htrack {{ height:11px; background:#e2e8f0; border-radius:999px; overflow:hidden; }}
    .sev-fill,.hfill {{ height:100%; border-radius:999px; }}
    .sev-count,.hval {{ text-align:right; color:#334155; font-weight:600; font-size:12px; }}
    table {{ width:100%; border-collapse:collapse; table-layout:auto; }}
    .table th,.table td {{ border:1px solid #e2e8f0; padding:7px 8px; text-align:left; font-size:12px; word-break:break-word; overflow-wrap:anywhere; vertical-align:top; }}
    .table th {{ background:var(--surface-soft); color:#334155; font-weight:700; white-space:nowrap; }}
    .table tbody tr:nth-child(even) td {{ background:#fcfdff; }}
    .badge {{ font-size:10px; font-weight:800; padding:3px 7px; border-radius:999px; display:inline-block; }}
    .cell-zero {{ color:#94a3b8; }}
    .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:8px; margin-bottom:10px; }}
    .meta-grid div {{ background:var(--surface-soft); border:1px solid #e2e8f0; border-radius:8px; padding:8px; display:grid; gap:3px; }}
    .meta-grid strong {{ font-size:10px; text-transform:uppercase; letter-spacing:.08em; color:#64748b; }}
    .meta-grid span {{ font-size:12px; font-weight:600; color:#0f172a; word-break:break-word; overflow-wrap:anywhere; }}
    .finding-card {{ background:var(--surface); border:1px solid var(--stroke); border-radius:8px; padding:10px; margin-bottom:8px; }}
    .finding-head {{ display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:8px; }}
    .finding-head h3 {{ margin:0; font-size:14px; }}
    section h4 {{ margin:10px 0 5px 0; font-size:11px; color:#1e3a8a; text-transform:uppercase; letter-spacing:.08em; }}
    section p {{ margin:0; color:#334155; line-height:1.5; font-size:13px; word-break:break-word; overflow-wrap:anywhere; }}
    pre {{ margin:0; background:#111827; color:#e5e7eb; border-radius:8px; padding:10px; overflow:auto; font-size:11px; white-space:pre-wrap; word-break:break-word; max-height:420px; }}
    ul {{ margin:0; padding-left:18px; color:#334155; font-size:13px; }}
    details {{ border:1px solid var(--stroke); border-radius:8px; background:#fff; padding:8px; }}
    summary {{ cursor:pointer; color:#0f172a; font-weight:600; }}
    .empty {{ color:#64748b; padding:10px; background:#f8fafc; border:1px dashed #cbd5e1; border-radius:8px; }}
    .footer {{ margin-top:14px; color:#64748b; font-size:12px; }}
        @media (max-width:1100px) {{ .grid {{ grid-template-columns:1fr; }} .sev-row,.hrow {{ grid-template-columns:130px 1fr 80px; }} .hero p {{ word-break:break-all; }} }}
  </style>
</head>
<body>
  <div class=\"container\">
    <header class=\"hero\">
      <h1>Vyper Guard Security Report</h1>
      <p>Target: {_escape(report.file_path)} · Generated: {_escape(report.timestamp.strftime("%Y-%m-%d %H:%M UTC"))} · Tool: v{_escape(__version__)}</p>
    </header>

    <section class=\"cards\">
      <div class=\"card\"><div class=\"k\">Security Score</div><div class=\"v\">{report.security_score}</div></div>
      <div class=\"card\"><div class=\"k\">Grade</div><div class=\"v\">{_escape(report.grade.value)}</div></div>
      <div class=\"card\"><div class=\"k\">Total Findings</div><div class=\"v\">{len(report.findings)}</div></div>
      <div class=\"card\"><div class=\"k\">Critical</div><div class=\"v\">{counts[Severity.CRITICAL]}</div></div>
      <div class=\"card\"><div class=\"k\">High</div><div class=\"v\">{counts[Severity.HIGH]}</div></div>
      <div class=\"card\"><div class=\"k\">Medium</div><div class=\"v\">{counts[Severity.MEDIUM]}</div></div>
      <div class=\"card\"><div class=\"k\">Low</div><div class=\"v\">{counts[Severity.LOW]}</div></div>
      <div class=\"card\"><div class=\"k\">Info</div><div class=\"v\">{counts[Severity.INFO]}</div></div>
    </section>

    <section class=\"grid stack\">
      <article class=\"panel\">
        <h2>Severity Distribution</h2>
        {_severity_bar_html(report)}
      </article>
      <article class=\"panel\">
        <h2>Source Line Composition</h2>
        {_line_composition_chart_html(stats)}
      </article>
    </section>

    <section class=\"grid stack\">
      <article class=\"panel\">
        <h2>Contract Metrics</h2>
        <table class=\"table\">
          <thead><tr><th>Metric</th><th>Value</th></tr></thead>
          <tbody>
            <tr><td>Total lines</td><td>{stats["line_total"]}</td></tr>
            <tr><td>Code lines</td><td>{stats["line_code"]}</td></tr>
            <tr><td>Comment lines</td><td>{stats["line_comment"]}</td></tr>
            <tr><td>Blank lines</td><td>{stats["line_blank"]}</td></tr>
            <tr><td>Max line length</td><td>{stats["max_line_length"]}</td></tr>
            <tr><td>Functions</td><td>{len(stats["functions"])}</td></tr>
            <tr><td>Events</td><td>{len(stats["events"])}</td></tr>
            <tr><td>State variables (heuristic)</td><td>{len(stats["state_variables"])}</td></tr>
            <tr><td>Internal call edges</td><td>{len(stats["internal_call_edges"])}</td></tr>
            <tr><td>raw_call count</td><td>{stats["external_calls"]}</td></tr>
            <tr><td>send count</td><td>{stats["send_calls"]}</td></tr>
            <tr><td>delegate call signals</td><td>{stats["delegate_calls"]}</td></tr>
            <tr><td>create_* calls</td><td>{stats["create_calls"]}</td></tr>
            <tr><td>selfdestruct calls</td><td>{stats["selfdestruct_calls"]}</td></tr>
          </tbody>
        </table>
      </article>
      <article class=\"panel\">
        <h2>Issue Type Matrix</h2>
        {_issue_map_html(report)}
      </article>
    </section>

    <section class=\"grid stack\">
      <article class=\"panel\">
        <h2>Function Inventory</h2>
        {_function_inventory_html(stats)}
      </article>
      <article class=\"panel\">
        <h2>Internal Call Mapping</h2>
        {_call_edges_html(stats)}
      </article>
    </section>

        <section class=\"panel stack\">
      <h2>Findings Overview</h2>
      {_findings_overview_html(report)}
    </section>

        <section class=\"panel stack\">
      <h2>Prioritized Remediation Plan</h2>
      {_remediation_plan_html(report)}
    </section>

        <section class=\"stack\">
      {_finding_cards_html(report)}
    </section>

        <section class=\"grid stack\">
      <article class=\"panel\">
        <h2>Imports / Events / State Variables</h2>
                <details open><summary>Imports ({len(stats["imports"])})</summary><pre>{_escape(imports_text)}</pre></details>
                <details style=\"margin-top:8px;\"><summary>Events ({len(stats["events"])})</summary><pre>{_escape(events_text)}</pre></details>
                <details style=\"margin-top:8px;\"><summary>State Variables (heuristic, {len(stats["state_variables"])})</summary><pre>{_escape(state_vars_text)}</pre></details>
      </article>
      <article class=\"panel\">
        <h2>Analysis Context</h2>
                <details open><summary>Context JSON</summary><pre>{_escape(context_json)}</pre></details>
      </article>
    </section>

        <section class=\"panel stack\">
      <h2>Full Machine Payload (JSON)</h2>
            <details><summary>Expand Full Payload</summary><pre>{_escape(payload_json)}</pre></details>
    </section>

    <footer class=\"footer\">Generated by vyper-guard v{_escape(__version__)} · Detectors run: {len(report.detectors_run)} · Findings: {len(report.findings)}</footer>
  </div>
</body>
</html>
"""

    if output_path:
        path = _prepare_output_path(output_path)
        path.write_text(html, encoding="utf-8")

    return html
