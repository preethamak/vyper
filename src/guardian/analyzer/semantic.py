"""Semantic extraction helpers (Phase 3 foundation).

Builds a lightweight semantic summary from parsed Vyper contracts:
- function-level state reads/writes
- external call presence
- event emission presence
- delegate-call usage
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from guardian.models import ContractInfo, FunctionInfo
from guardian.utils.helpers import check_vyper_available
from guardian.utils.logger import get_logger

log = get_logger("analyzer.semantic")

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

_EXTERNAL_CALL_NAMES = {
    "send",
    "raw_call",
    "create_minimal_proxy_to",
    "create_copy_of",
    "create_from_blueprint",
}


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


def build_semantic_summary(contract: ContractInfo, mode: str | None = None) -> SemanticSummary:
    """Build a semantic summary from an already parsed contract.

    Args:
        contract: Parsed contract info.
        mode: Optional semantic mode override (auto | source | compiler).
    """
    resolved = (mode or contract.semantic_mode or "source").strip().lower()
    if resolved == "compiler":
        compiler_summary = _build_compiler_summary(contract)
        if compiler_summary is not None:
            return compiler_summary

    return _build_source_summary(contract)


def _build_source_summary(contract: ContractInfo) -> SemanticSummary:
    functions = {func.name: _analyze_function(func) for func in contract.functions}
    return SemanticSummary(
        functions=functions,
        uses_dynarray_in_mapping=_uses_dynarray_mapping(contract),
    )


def _build_compiler_summary(contract: ContractInfo) -> SemanticSummary | None:
    """Attempt compiler-backed semantic extraction.

    Returns None if the compiler is unavailable or parsing fails.
    """
    if check_vyper_available() is None:
        log.warning("semantic_mode=compiler requested but vyper is not installed; falling back")
        return None

    module = _parse_vyper_ast(contract.source_code)
    if module is None:
        return None

    functions: dict[str, FunctionSemantic] = {}
    for fn_node in _iter_function_nodes(module):
        name = _get_node_name(fn_node)
        if not name:
            continue
        functions[name] = _analyze_function_ast(fn_node)

    if not functions:
        log.warning("compiler AST parsed but no functions were extracted; falling back")
        return None

    return SemanticSummary(
        functions=functions,
        uses_dynarray_in_mapping=_uses_dynarray_mapping(contract),
    )


def _parse_vyper_ast(source: str):
    """Parse Vyper source to an AST module node using vyper's parser."""
    try:
        from vyper import ast as vy_ast  # type: ignore[import-untyped]
    except Exception as exc:  # pragma: no cover - import guard
        log.warning("Unable to import vyper AST parser: %s", exc)
        return None

    parse_fn_obj = getattr(vy_ast, "parse_to_ast", None)
    if parse_fn_obj is None:
        try:
            from vyper.ast import parse_to_ast as imported_parse_fn  # type: ignore[import-untyped]
        except Exception as exc:  # pragma: no cover - import guard
            log.warning("Vyper parse_to_ast unavailable: %s", exc)
            return None
        parse_fn_obj = imported_parse_fn

    if not callable(parse_fn_obj):
        log.warning("Vyper parse_to_ast is not callable; falling back")
        return None

    parse_fn: Callable[..., Any] = parse_fn_obj

    try:
        return parse_fn(source)
    except TypeError:
        pass
    except Exception as exc:
        log.warning("Vyper AST parse failed: %s", exc)
        return None

    try:
        return parse_fn(source, source_id=0)
    except TypeError:
        pass
    except Exception as exc:
        log.warning("Vyper AST parse failed: %s", exc)
        return None

    try:
        return parse_fn(source, 0)
    except Exception as exc:
        log.warning("Vyper AST parse failed: %s", exc)
        return None

    log.warning("Vyper AST parse signature mismatch; falling back")
    return None


def _iter_function_nodes(module) -> list[object]:
    """Return AST function nodes from the parsed module."""
    functions: list[object] = []
    for child in _iter_children(module):
        if child.__class__.__name__ == "FunctionDef":
            functions.append(child)
    return functions


def _analyze_function_ast(func_node) -> FunctionSemantic:
    writes: set[str] = set()
    reads: set[str] = set()
    external_calls = 0
    external_calls_in_loop = False
    emits_event = False
    uses_delegatecall = False

    def walk(node, in_loop: bool) -> None:
        nonlocal external_calls, external_calls_in_loop, emits_event, uses_delegatecall

        node_type = node.__class__.__name__
        if node_type in {"For", "While"}:
            in_loop = True

        if node_type in {"Assign", "AnnAssign", "AugAssign"}:
            for target in _iter_assign_targets(node):
                name = _self_target_name(target)
                if name:
                    writes.add(name)

        if node_type == "Call":
            name = _call_name(node)
            if name in _EXTERNAL_CALL_NAMES:
                external_calls += 1
                if in_loop:
                    external_calls_in_loop = True
                if name == "raw_call" and _call_has_delegatecall(node):
                    uses_delegatecall = True

            if name in {"log", "emit"}:
                emits_event = True

        if node_type in {"Log", "Emit"}:
            emits_event = True

        attr_name = _self_attr_name(node)
        if attr_name:
            reads.add(attr_name)

        for child in _iter_children(node):
            walk(child, in_loop)

    for child in _iter_children(func_node):
        walk(child, in_loop=False)

    reads -= writes
    return FunctionSemantic(
        name=_get_node_name(func_node) or "<unknown>",
        state_reads=reads,
        state_writes=writes,
        external_calls=external_calls,
        external_calls_in_loop=external_calls_in_loop,
        emits_event=emits_event,
        uses_delegatecall=uses_delegatecall,
    )


def _iter_children(node) -> list[object]:
    """Yield child AST nodes using best-effort introspection."""
    children: list[object] = []
    if hasattr(node, "get_children"):
        try:
            return list(node.get_children())
        except Exception:
            return []

    try:
        values = vars(node).values()
    except TypeError:
        return children

    for value in values:
        if _is_ast_node(value):
            children.append(value)
        elif isinstance(value, list):
            for item in value:
                if _is_ast_node(item):
                    children.append(item)
    return children


def _is_ast_node(obj: object) -> bool:
    return hasattr(obj, "__class__") and obj.__class__.__module__.startswith("vyper.ast")


def _get_node_name(node) -> str | None:
    return getattr(node, "name", None) or getattr(node, "id", None)


def _iter_assign_targets(node) -> list[object]:
    targets = []
    if hasattr(node, "target") and node.target is not None:
        targets.append(node.target)
    if hasattr(node, "targets") and node.targets:
        targets.extend(list(node.targets))
    return targets


def _self_target_name(node) -> str | None:
    attr = _self_attr_name(node)
    if attr:
        return attr
    if node.__class__.__name__ == "Subscript":
        return _self_target_name(getattr(node, "value", None))
    return None


def _self_attr_name(node) -> str | None:
    if node is None or node.__class__.__name__ != "Attribute":
        return None
    value = getattr(node, "value", None)
    if value is None:
        return None
    if getattr(value, "id", None) != "self" and getattr(value, "name", None) != "self":
        return None
    return getattr(node, "attr", None) or getattr(node, "attribute", None)


def _call_name(node) -> str | None:
    func = getattr(node, "func", None)
    if func is None:
        return None
    return (
        getattr(func, "id", None) or getattr(func, "attr", None) or getattr(func, "attribute", None)
    )


def _call_has_delegatecall(node) -> bool:
    for kw in getattr(node, "keywords", []) or []:
        key = getattr(kw, "arg", None) or getattr(kw, "name", None)
        if key != "is_delegate_call":
            continue
        val = getattr(kw, "value", None)
        if val is None:
            continue
        literal = getattr(val, "value", None)
        return bool(literal is True or literal == 1)
    return False
