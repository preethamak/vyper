"""Semantic extraction helpers (Phase 3 foundation).

Builds a lightweight semantic summary from parsed Vyper contracts:
- function-level state reads/writes
- external call presence
- event emission presence
- delegate-call usage
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guardian.analyzer.compiler_resolver import resolve_compiler
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
    engine: str = "source"
    compiler_version: str | None = None
    fallback_reason: str | None = None


_SEMANTIC_CACHE: OrderedDict[str, SemanticSummary] = OrderedDict()
_SEMANTIC_CACHE_MAX = 128


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
    cache_key = hashlib.sha256(
        f"{resolved}\0{contract.file_path}\0{contract.source_code}".encode()
    ).hexdigest()
    cached = _SEMANTIC_CACHE.get(cache_key)
    if cached is not None:
        _SEMANTIC_CACHE.move_to_end(cache_key)
        return cached

    if resolved == "compiler":
        compiler_summary, fallback_reason = _build_compiler_summary(contract)
        if compiler_summary is not None:
            summary = compiler_summary
        else:
            summary = _build_source_summary(
                contract,
                fallback_reason=fallback_reason
                or "Compiler AST extraction failed; source heuristics used.",
                compiler_version=check_vyper_available(),
            )
    else:
        summary = _build_source_summary(contract)

    _SEMANTIC_CACHE[cache_key] = summary
    _SEMANTIC_CACHE.move_to_end(cache_key)
    while len(_SEMANTIC_CACHE) > _SEMANTIC_CACHE_MAX:
        _SEMANTIC_CACHE.popitem(last=False)
    return summary


def _build_source_summary(
    contract: ContractInfo,
    fallback_reason: str | None = None,
    compiler_version: str | None = None,
) -> SemanticSummary:
    functions = {func.name: _analyze_function(func) for func in contract.functions}
    return SemanticSummary(
        functions=functions,
        uses_dynarray_in_mapping=_uses_dynarray_mapping(contract),
        engine="source",
        compiler_version=compiler_version,
        fallback_reason=fallback_reason,
    )


def _build_compiler_summary(contract: ContractInfo) -> tuple[SemanticSummary | None, str | None]:
    """Attempt compiler-backed semantic extraction.

    Returns None if the compiler is unavailable or parsing fails.
    """
    module = _parse_vyper_ast(contract.source_code)
    engine = "compiler-python"
    fallback_reason: str | None = None
    compiler_version = check_vyper_available()
    if module is None:
        module, fallback_reason, compiler_version = _parse_vyper_ast_cli(contract)
        engine = "compiler-cli"
    if module is None:
        return None, fallback_reason

    functions: dict[str, FunctionSemantic] = {}
    for fn_node in _iter_function_nodes(module):
        name = _get_node_name(fn_node)
        if not name:
            continue
        functions[name] = _analyze_function_ast(fn_node)

    if not functions:
        log.warning("compiler AST parsed but no functions were extracted; falling back")
        return None, "Compiler AST contained no function definitions."

    return (
        SemanticSummary(
            functions=functions,
            uses_dynarray_in_mapping=_uses_dynarray_mapping(contract),
            engine=engine,
            compiler_version=compiler_version,
        ),
        None,
    )


def _parse_vyper_ast_cli(
    contract: ContractInfo,
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Parse source through the Vyper executable and return its JSON AST."""
    resolution = resolve_compiler(contract.source_code)
    if resolution.candidate is None:
        return None, resolution.reason, None
    executable = resolution.candidate.executable
    compiler_version = resolution.candidate.version_text

    source_path = Path(contract.file_path)
    use_existing = False
    if source_path.is_file():
        try:
            use_existing = source_path.read_text(encoding="utf-8") == contract.source_code
        except OSError:
            use_existing = False

    temp_path: Path | None = None
    compile_path = source_path
    cwd = source_path.parent if source_path.parent.is_dir() else Path.cwd()
    try:
        if not use_existing:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".vy",
                prefix=".vyper-guard-semantic-",
                dir=cwd,
                delete=False,
            ) as handle:
                handle.write(contract.source_code)
                temp_path = Path(handle.name)
                compile_path = temp_path

        completed = subprocess.run(
            [executable, "-f", "ast", str(compile_path)],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            reason = completed.stderr.strip()[-1000:] or "Vyper CLI exited non-zero."
            log.warning("Vyper CLI AST extraction failed: %s", reason)
            return None, reason, compiler_version
        payload = json.loads(completed.stdout)
        module = payload.get("ast") if isinstance(payload, dict) else None
        if isinstance(module, dict):
            return module, None, compiler_version
        return None, "Vyper CLI output did not contain a JSON AST.", compiler_version
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        log.warning("Vyper CLI AST extraction failed: %s", exc)
        return None, str(exc), compiler_version
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


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
        if _node_type(child) == "FunctionDef":
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

        node_type = _node_type(node)
        if node_type in {"For", "While"}:
            in_loop = True

        if node_type in {"Assign", "AnnAssign", "AugAssign"}:
            for target in _iter_assign_targets(node):
                name = _self_target_name(target)
                if name:
                    writes.add(name)

        if node_type == "Call":
            name = _call_name(node)
            if name in _EXTERNAL_CALL_NAMES or _call_is_interface(node):
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
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"node_id", "ast_type", "src"}:
                continue
            if _is_ast_node(value):
                children.append(value)
            elif isinstance(value, list):
                children.extend(item for item in value if _is_ast_node(item))
        return children
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
    if isinstance(obj, dict):
        return isinstance(obj.get("ast_type"), str)
    return hasattr(obj, "__class__") and obj.__class__.__module__.startswith("vyper.ast")


def _node_type(node: object) -> str:
    if isinstance(node, dict):
        return str(node.get("ast_type") or "")
    return node.__class__.__name__


def _get_node_name(node) -> str | None:
    if isinstance(node, dict):
        value = node.get("name") or node.get("id")
        return str(value) if value is not None else None
    return getattr(node, "name", None) or getattr(node, "id", None)


def _iter_assign_targets(node) -> list[object]:
    if isinstance(node, dict):
        targets: list[object] = []
        target = node.get("target")
        if _is_ast_node(target):
            targets.append(target)
        raw_targets = node.get("targets")
        if isinstance(raw_targets, list):
            targets.extend(item for item in raw_targets if _is_ast_node(item))
        return targets
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
    if _node_type(node) == "Subscript":
        value = node.get("value") if isinstance(node, dict) else getattr(node, "value", None)
        return _self_target_name(value)
    return None


def _self_attr_name(node) -> str | None:
    if node is None or _node_type(node) != "Attribute":
        return None
    value = node.get("value") if isinstance(node, dict) else getattr(node, "value", None)
    if value is None:
        return None
    value_name = _get_node_name(value)
    if value_name != "self":
        return None
    if isinstance(node, dict):
        attr = node.get("attr") or node.get("attribute")
        return str(attr) if attr is not None else None
    return getattr(node, "attr", None) or getattr(node, "attribute", None)


def _call_name(node) -> str | None:
    func = node.get("func") if isinstance(node, dict) else getattr(node, "func", None)
    if func is None:
        return None
    if isinstance(func, dict):
        value = func.get("id") or func.get("attr") or func.get("attribute")
        return str(value) if value is not None else None
    return (
        getattr(func, "id", None) or getattr(func, "attr", None) or getattr(func, "attribute", None)
    )


def _call_has_delegatecall(node) -> bool:
    keywords = node.get("keywords", []) if isinstance(node, dict) else getattr(node, "keywords", [])
    for kw in keywords or []:
        if isinstance(kw, dict):
            key = kw.get("arg") or kw.get("name")
            val = kw.get("value")
        else:
            key = getattr(kw, "arg", None) or getattr(kw, "name", None)
            val = getattr(kw, "value", None)
        if key != "is_delegate_call":
            continue
        if val is None:
            continue
        literal = val.get("value") if isinstance(val, dict) else getattr(val, "value", None)
        return bool(literal is True or literal == 1)
    return False


def _call_is_interface(node: object) -> bool:
    """Return True for calls shaped like Interface(address).method(...)."""
    func = node.get("func") if isinstance(node, dict) else getattr(node, "func", None)
    if func is None or _node_type(func) != "Attribute":
        return False
    value = func.get("value") if isinstance(func, dict) else getattr(func, "value", None)
    return value is not None and _node_type(value) == "Call"
