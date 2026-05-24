"""Project-wide analysis graph utilities.

Builds an import graph, interface index, call graph, and a basic shared
state map from a directory of Vyper contracts. This is an offline,
source-only analysis intended to complement per-file scanning.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.models import (
    Confidence,
    ContractInfo,
    DetectorResult,
    Severity,
    VulnerabilityType,
)
from guardian.utils.helpers import FileLoadError, load_vyper_source

_IMPORT_FROM_RE = re.compile(r"^from\s+([A-Za-z0-9_./]+)\s+import\s+")
_IMPORT_RE = re.compile(r"^import\s+([A-Za-z0-9_./]+)")
_INTERFACE_RE = re.compile(r"^interface\s+(\w+)\s*:")
_DEF_RE = re.compile(r"^def\s+(\w+)\s*\(")
_INTERFACE_USE_RE = re.compile(r"^(implements|uses|initializes|exports)\s*:\s*(.+)$")


@dataclass
class ProjectGraphResult:
    graph: dict[str, object]
    findings: dict[str, list[DetectorResult]]


def build_project_graph(
    target_dir: Path, contract_paths: Iterable[Path]
) -> ProjectGraphResult:
    """Build a project-wide analysis graph.

    Args:
        target_dir: Root directory of the project scan.
        contract_paths: Iterable of Vyper contract file paths.

    Returns:
        ProjectGraphResult with graph payload and per-file findings.
    """
    target_dir = target_dir.resolve()
    contracts: list[ContractInfo] = []
    errors: list[str] = []

    for path in contract_paths:
        try:
            source = load_vyper_source(path)
            contracts.append(parse_vyper_source(source, str(path)))
        except FileLoadError as exc:
            errors.append(str(exc))

    module_map = _build_module_map(target_dir, contracts)

    interface_index: dict[str, dict[str, object]] = {}
    interface_sources: dict[str, str] = {}
    interface_defs: dict[str, list[str]] = {}

    for contract in contracts:
        defs = _extract_interface_defs(contract)
        for name, detail in defs.items():
            if name not in interface_index:
                interface_index[name] = detail
                interface_sources[name] = str(contract.file_path)
                interface_defs[name] = list(detail.get("functions") or [])

    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    unresolved_imports: list[dict[str, object]] = []
    interface_uses: list[dict[str, object]] = []
    call_graph: list[dict[str, object]] = []
    state_map: list[dict[str, object]] = []
    findings: dict[str, list[DetectorResult]] = {}

    for contract in contracts:
        rel_module = _module_name(target_dir, Path(contract.file_path))
        import_modules = _extract_import_modules(contract.imports)

        for module in import_modules:
            resolved = module_map.get(module)
            edge = {
                "from": str(contract.file_path),
                "to": resolved,
                "import": module,
                "resolved": resolved is not None,
            }
            edges.append(edge)
            if resolved is None:
                unresolved_imports.append({"file": str(contract.file_path), "import": module})

        nodes.append(
            {
                "file": str(contract.file_path),
                "module": rel_module,
                "imports": import_modules,
                "functions": [f.name for f in contract.functions],
                "state_variables": [v.name for v in contract.state_variables],
                "interfaces": list(_extract_interface_defs(contract).keys()),
            }
        )

        call_graph.extend(_build_internal_call_graph(contract))
        state_map.append(_build_state_map(contract))

        uses = _extract_interface_uses(contract)
        for use in uses:
            iface = use["name"]
            defined = interface_defs.get(iface)
            status = "resolved"
            missing_functions: list[str] = []
            if defined is None:
                status = "missing"
            else:
                declared = set(defined)
                implemented = {f.name for f in contract.functions}
                missing_functions = sorted(declared - implemented)
                if missing_functions:
                    status = "mismatch"

            interface_uses.append(
                {
                    "file": str(contract.file_path),
                    "interface": iface,
                    "status": status,
                    "missing_functions": missing_functions,
                    "line": use.get("line"),
                }
            )

            if status == "missing":
                _append_project_finding(
                    findings,
                    contract.file_path,
                    DetectorResult(
                        detector_name="project_interface_unresolved",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        vulnerability_type=VulnerabilityType.CODE_QUALITY,
                        title=f"Interface not found: {iface}",
                        description=(
                            "Contract declares an interface in implements/uses but no matching "
                            "interface definition exists in the project graph."
                        ),
                        line_number=use.get("line"),
                        source_snippet=use.get("line_text"),
                        fix_suggestion=(
                            "Define the interface in the project or update the import to reference "
                            "the correct interface file."
                        ),
                        why_flagged="Interface reference could not be resolved locally.",
                        evidence=[
                            f"interface={iface}",
                            f"file={contract.file_path}",
                        ],
                        why_not_suppressed="Project interface resolution failures are not suppressed.",
                    ),
                )
            elif status == "mismatch":
                missing_text = ", ".join(missing_functions) if missing_functions else "unknown"
                _append_project_finding(
                    findings,
                    contract.file_path,
                    DetectorResult(
                        detector_name="project_interface_mismatch",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        vulnerability_type=VulnerabilityType.CODE_QUALITY,
                        title=f"Interface mismatch: {iface}",
                        description=(
                            "Contract claims to implement an interface but is missing required "
                            f"function(s): {missing_text}."
                        ),
                        line_number=use.get("line"),
                        source_snippet=use.get("line_text"),
                        fix_suggestion=(
                            "Implement the missing interface functions or update the interface "
                            "declaration to match the contract's API."
                        ),
                        why_flagged="Interface contract and implementation are inconsistent.",
                        evidence=[
                            f"interface={iface}",
                            f"missing_functions={missing_text}",
                            f"file={contract.file_path}",
                        ],
                        why_not_suppressed="Interface mismatches are always reported.",
                    ),
                )

    graph: dict[str, object] = {
        "nodes": nodes,
        "edges": edges,
        "unresolved_imports": unresolved_imports,
        "interfaces": [
            {
                "name": name,
                "file": interface_sources.get(name),
                "functions": interface_defs.get(name, []),
            }
            for name in sorted(interface_defs)
        ],
        "interface_uses": interface_uses,
        "call_graph": call_graph,
        "state_map": state_map,
        "errors": errors,
    }

    return ProjectGraphResult(graph=graph, findings=findings)


def _append_project_finding(
    findings: dict[str, list[DetectorResult]],
    file_path: str,
    finding: DetectorResult,
) -> None:
    bucket = findings.setdefault(str(file_path), [])
    bucket.append(finding)


def _build_module_map(target_dir: Path, contracts: Iterable[ContractInfo]) -> dict[str, str]:
    module_map: dict[str, str] = {}
    for contract in contracts:
        path = Path(contract.file_path).resolve()
        try:
            rel = path.relative_to(target_dir).with_suffix("")
        except ValueError:
            continue
        rel_posix = rel.as_posix()
        module_map[rel_posix] = str(path)
        module_map[rel_posix.replace("/", ".")] = str(path)
    return module_map


def _module_name(target_dir: Path, file_path: Path) -> str:
    try:
        rel = file_path.resolve().relative_to(target_dir).with_suffix("")
    except ValueError:
        return file_path.with_suffix("").name
    return rel.as_posix().replace("/", ".")


def _extract_import_modules(import_lines: Iterable[str]) -> list[str]:
    modules: list[str] = []
    for line in import_lines:
        stripped = line.strip()
        from_match = _IMPORT_FROM_RE.match(stripped)
        if from_match:
            modules.append(from_match.group(1))
            continue
        if match := _IMPORT_RE.match(stripped):
            modules.append(match.group(1))
    return modules


def _extract_interface_defs(contract: ContractInfo) -> dict[str, dict[str, object]]:
    defs: dict[str, dict[str, object]] = {}
    lines = contract.lines
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if _is_top_level(line) and (match := _INTERFACE_RE.match(stripped)):
            name = match.group(1)
            idx += 1
            funcs: list[str] = []
            while idx < len(lines):
                inner = lines[idx]
                if not inner.strip():
                    idx += 1
                    continue
                if _is_top_level(inner):
                    break
                inner_stripped = inner.strip()
                if def_match := _DEF_RE.match(inner_stripped):
                    funcs.append(def_match.group(1))
                idx += 1
            defs[name] = {"functions": funcs}
            continue
        idx += 1
    return defs


def _extract_interface_uses(contract: ContractInfo) -> list[dict[str, object]]:
    uses: list[dict[str, object]] = []
    for idx, line in enumerate(contract.lines, start=1):
        stripped = line.strip()
        if not _is_top_level(line):
            continue
        match = _INTERFACE_USE_RE.match(stripped)
        if not match:
            continue
        names_raw = match.group(2)
        names = [name.strip() for name in names_raw.split(",") if name.strip()]
        for name in names:
            uses.append({"name": name, "line": idx, "line_text": stripped})
    return uses


def _build_internal_call_graph(contract: ContractInfo) -> list[dict[str, object]]:
    edges: list[dict[str, object]] = []
    func_names = [f.name for f in contract.functions]
    for func in contract.functions:
        for callee in func_names:
            if callee == func.name:
                continue
            if re.search(rf"\b{re.escape(callee)}\s*\(", func.body_text):
                edges.append(
                    {
                        "from": f"{contract.file_path}:{func.name}",
                        "to": f"{contract.file_path}:{callee}",
                        "type": "internal",
                    }
                )
    return edges


def _build_state_map(contract: ContractInfo) -> dict[str, object]:
    variables = {v.name: {"reads": set(), "writes": set()} for v in contract.state_variables}
    if not variables:
        return {"file": str(contract.file_path), "variables": {}}

    for func in contract.functions:
        body = func.body_text
        for name in variables:
            if _is_write(name, body):
                variables[name]["writes"].add(func.name)
            if _is_read(name, body):
                variables[name]["reads"].add(func.name)

    formatted = {
        name: {
            "reads": sorted(values["reads"]),
            "writes": sorted(values["writes"]),
        }
        for name, values in variables.items()
        if values["reads"] or values["writes"]
    }
    return {"file": str(contract.file_path), "variables": formatted}


def _is_write(name: str, body: str) -> bool:
    pattern = rf"(?:\bself\.)?{re.escape(name)}\b\s*([+\-*/%]?=)"
    return re.search(pattern, body) is not None


def _is_read(name: str, body: str) -> bool:
    pattern = rf"(?:\bself\.)?{re.escape(name)}\b"
    return re.search(pattern, body) is not None


def _is_top_level(line: str) -> bool:
    return len(line) == 0 or not line[0].isspace()
