"""Reusable path and callback analysis for Vyper functions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from guardian.analyzer.call_analysis import ExternalCallSite, external_call_sites
from guardian.analyzer.cfg import FunctionCFG, build_cfg
from guardian.models import ContractInfo, FunctionInfo

_STATE_RE = re.compile(r"\bself\.(\w+)")
_STATE_WRITE_RE = re.compile(r"\bself\.(\w+)(?:\[.*?\])*(?:\.\w+)*\s*[+\-*/%]?=")
_STATE_MUTATION_RE = re.compile(
    r"\bself\.(\w+)(?:\[.*?\])*(?:\.\w+)*\."
    r"(?:append|pop|remove|clear|extend|insert)\s*\("
)
_CALL_RE = re.compile(
    r"\b(?:send|raw_call)\s*\(\s*([^,\n)]+)|"
    r"\b[A-Za-z_]\w*\s*\(([^()\n]*)\)\s*\.\s*[A-Za-z_]\w*\s*\("
)
_ACCESS_RE = re.compile(
    r"\bassert\s+(?:msg\.sender\s*==\s*self\.\w+|self\.\w+\s*==\s*msg\.sender)\b"
    r"|\bself\._(?:check|enforce)_role\s*\("
)


@dataclass(frozen=True)
class CallPathEvidence:
    call_line: int
    write_lines: tuple[int, ...]
    callback_feasibility: str
    access_controlled: bool
    state_dependencies: tuple[str, ...]
    mutability: str = "unknown"
    target_trust: str = "unknown"


@dataclass(frozen=True)
class FunctionPathAnalysis:
    cfg: FunctionCFG
    dominators: dict[int, frozenset[int]]
    reachable: dict[int, frozenset[int]]
    call_paths: tuple[CallPathEvidence, ...]


def analyze_function_paths(
    func: FunctionInfo, contract: ContractInfo | None = None
) -> FunctionPathAnalysis:
    cfg = build_cfg(func)
    reachable = {bid: frozenset(_reachable_from(cfg, bid)) for bid in cfg.blocks}
    dominators = _dominators(cfg)
    body_start = func.end_line - len(func.body_lines) + 1
    guarded = any(_ACCESS_RE.search(line.split("#", 1)[0]) for line in func.body_lines)
    evidence: list[CallPathEvidence] = []
    sites = {site.line: site for site in external_call_sites(contract, func)} if contract else {}

    for block in cfg.blocks_with_external_call():
        for call_line in block.lines:
            call_index = call_line - body_start
            if not 0 <= call_index < len(func.body_lines):
                continue
            call_text = func.body_lines[call_index]
            if _CALL_RE.search(call_text.split("#", 1)[0]) is None:
                continue
            writes: list[int] = []
            for candidate_id in reachable[block.id]:
                candidate = cfg.blocks[candidate_id]
                candidate_writes = [
                    line_number
                    for line_number in candidate.lines
                    if 0 <= (line_number - body_start) < len(func.body_lines)
                    and (
                        _STATE_WRITE_RE.search(func.body_lines[line_number - body_start])
                        or _STATE_MUTATION_RE.search(func.body_lines[line_number - body_start])
                    )
                ]
                writes.extend(
                    line_number
                    for line_number in candidate_writes
                    if candidate_id != block.id or line_number > call_line
                )
            if not writes:
                continue

            preceding = "\n".join(func.body_lines[:call_index])
            dependencies = set(_STATE_RE.findall(preceding))
            written_names: set[str] = set()
            for line_number in writes:
                index = line_number - body_start
                if 0 <= index < len(func.body_lines):
                    written_names.update(_STATE_WRITE_RE.findall(func.body_lines[index]))
                    written_names.update(_STATE_MUTATION_RE.findall(func.body_lines[index]))
            evidence.append(
                CallPathEvidence(
                    call_line=call_line,
                    write_lines=tuple(sorted(set(writes))),
                    callback_feasibility=(
                        _site_callback_feasibility(sites[call_line])
                        if call_line in sites
                        else _callback_feasibility(call_text)
                    ),
                    access_controlled=guarded,
                    state_dependencies=tuple(sorted(dependencies & written_names)),
                    mutability=sites[call_line].mutability if call_line in sites else "unknown",
                    target_trust=(
                        sites[call_line].target_trust if call_line in sites else "unknown"
                    ),
                )
            )

    return FunctionPathAnalysis(cfg, dominators, reachable, tuple(evidence))


def _reachable_from(cfg: FunctionCFG, start: int) -> set[int]:
    seen: set[int] = set()
    pending = [start]
    while pending:
        current = pending.pop()
        if current in seen or current not in cfg.blocks:
            continue
        seen.add(current)
        pending.extend(cfg.blocks[current].successors)
    return seen


def _dominators(cfg: FunctionCFG) -> dict[int, frozenset[int]]:
    nodes = set(cfg.blocks)
    dom: dict[int, set[int]] = {
        node: ({node} if node == cfg.entry_id else set(nodes)) for node in nodes
    }
    changed = True
    while changed:
        changed = False
        for node in nodes - {cfg.entry_id}:
            predecessors = [pred for pred in cfg.blocks[node].predecessors if pred in nodes]
            shared = (
                set.intersection(*(dom[pred] for pred in predecessors)) if predecessors else set()
            )
            updated = {node} | shared
            if updated != dom[node]:
                dom[node] = updated
                changed = True
    return {node: frozenset(items) for node, items in dom.items()}


def _callback_feasibility(line: str) -> str:
    match = _CALL_RE.search(line.split("#", 1)[0])
    if match is None:
        return "unknown"
    target = next((item.strip() for item in match.groups() if item is not None), "")
    if "msg.sender" in target or (target and not target.startswith(("self.", "0x"))):
        return "attacker_controlled"
    if target.startswith("0x"):
        return "fixed_target"
    return "state_configured"


def _site_callback_feasibility(site: ExternalCallSite) -> str:
    if not site.callback_capable:
        return "not_callback_capable"
    if site.target_trust == "caller_controlled":
        return "attacker_controlled"
    if site.target_trust in {"fixed", "governance_configured"}:
        return "configured_target"
    return "unknown"
