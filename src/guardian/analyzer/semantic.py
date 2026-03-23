"""Semantic extraction helpers (Phase 3 foundation).

Builds a lightweight semantic summary from parsed Vyper contracts:
- function-level state reads/writes
- external call presence
- event emission presence
- delegate-call usage
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from guardian.models import ContractInfo, FunctionInfo

_STATE_ACCESS_RE = re.compile(r"\bself\.(\w+)")
_STATE_WRITE_RE = re.compile(r"\bself\.(\w+)\s*(?:\[.*?\])?(?:\.\w+)?\s*[+\-*/]?=")
_EXTERNAL_CALL_RE = re.compile(
    r"\b(send|raw_call|create_minimal_proxy_to|create_copy_of|create_from_blueprint)\s*\("
)
_DELEGATE_CALL_RE = re.compile(
    r"\braw_call\s*\(.*?is_delegate_call\s*=\s*(?:True|true|1)\b",
    re.DOTALL,
)
_EVENT_LOG_RE = re.compile(r"\blog\s+\w+")
_DYNARRAY_IN_MAPPING_RE = re.compile(
    r"HashMap\s*\[.*?,\s*DynArray\s*\[",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class FunctionSemantic:
    name: str
    state_reads: set[str]
    state_writes: set[str]
    external_calls: int
    external_calls_in_loop: bool
    emits_event: bool
    uses_delegatecall: bool


@dataclass(frozen=True)
class SemanticSummary:
    functions: dict[str, FunctionSemantic]
    uses_dynarray_in_mapping: bool


def _strip_inline_comment(line: str) -> str:
    """Drop inline ``#`` comments for lightweight source-pattern checks."""
    return line.split("#", 1)[0]


def _uses_dynarray_mapping(contract: ContractInfo) -> bool:
    """Detect ``HashMap[..., DynArray[...]]`` even when split across lines."""
    normalized = "\n".join(_strip_inline_comment(line) for line in contract.lines)
    return bool(_DYNARRAY_IN_MAPPING_RE.search(normalized))


def _analyze_function(func: FunctionInfo) -> FunctionSemantic:
    body = func.body_text

    writes = set(_STATE_WRITE_RE.findall(body))
    accesses = set(_STATE_ACCESS_RE.findall(body))
    reads = accesses - writes

    external_calls = len(_EXTERNAL_CALL_RE.findall(body))
    external_calls_in_loop = _has_external_call_in_loop(func.body_lines)
    emits_event = bool(_EVENT_LOG_RE.search(body))
    uses_delegatecall = any(_DELEGATE_CALL_RE.search(line) for line in func.body_lines)

    return FunctionSemantic(
        name=func.name,
        state_reads=reads,
        state_writes=writes,
        external_calls=external_calls,
        external_calls_in_loop=external_calls_in_loop,
        emits_event=emits_event,
        uses_delegatecall=uses_delegatecall,
    )


def _has_external_call_in_loop(body_lines: list[str]) -> bool:
    """Return True when an external call appears under any for-loop block."""
    loop_stack: list[int] = []

    for line in body_lines:
        stripped = line.strip()
        if not stripped:
            continue

        indent = len(line) - len(line.lstrip())
        while loop_stack and indent <= loop_stack[-1]:
            loop_stack.pop()

        if re.match(r"^\s*for\s+", line):
            loop_stack.append(indent)
            continue

        if loop_stack and _EXTERNAL_CALL_RE.search(stripped):
            return True

    return False


def build_semantic_summary(contract: ContractInfo) -> SemanticSummary:
    """Build a semantic summary from an already parsed contract."""
    functions = {func.name: _analyze_function(func) for func in contract.functions}
    return SemanticSummary(
        functions=functions,
        uses_dynarray_in_mapping=_uses_dynarray_mapping(contract),
    )
