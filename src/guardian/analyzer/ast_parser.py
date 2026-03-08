"""Source-level Vyper contract parser.

Parses ``.vy`` source code into a structured ``ContractInfo`` without
requiring the Vyper compiler.  This is a lightweight, regex-aided,
line-by-line parser that understands Vyper's indentation-based syntax
well enough for security analysis.

Limitations (by design):
  - Multi-line expressions that span 3+ lines may not be fully captured.
  - Complex constant expressions are stored as raw strings.
  - This is **not** a replacement for a full compiler AST — it is
    deliberately simple so it works on any ``.vy`` file even when
    ``vyper`` is not installed.
"""

from __future__ import annotations

import re

from guardian.models import ContractInfo, EventInfo, FunctionInfo, StateVariableInfo

# ---------------------------------------------------------------------------
# Regex patterns for Vyper syntax elements
# ---------------------------------------------------------------------------

# Version pragma — all known Vyper formats:
#   # pragma version ^0.4.0        (standard)
#   #pragma version ^0.4.0         (no space after #)
#   # @pragma version 0.4.1        (comment-style with 'version')
#   # @pragma 0.4.0                (comment-style WITHOUT 'version')
#   # @version ^0.3.9              (legacy pre-0.4.0 format)
_PRAGMA_RE = re.compile(
    r"^#\s*@?\s*pragma\s+version\s+(.+)$"  # with 'version' keyword
    r"|^#\s*@\s*pragma\s+([\^>=<~!]?\d+\..+)$"  # @pragma without 'version'
    r"|^#\s*@version\s+(.+)$",  # legacy @version
    re.IGNORECASE,
)

# Decorator line:  @external, @nonreentrant, etc.
_DECORATOR_RE = re.compile(r"^@(\w+)(?:\(.*\))?$")

# Function definition:  def foo(x: uint256) -> bool:
_FUNCDEF_RE = re.compile(r"^def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(.+?))?\s*:\s*$")

# Event declaration:  event Transfer:
_EVENT_RE = re.compile(r"^event\s+(\w+)\s*:\s*$")

# Import line:  from ethereum.ercs import IERC20  /  import foo
_IMPORT_RE = re.compile(r"^(?:from\s+\S+\s+)?import\s+.+$")

# State variable:  balances: HashMap[address, uint256]
# Also handles:  owner: public(address)
#                MAX: constant(uint256) = 100
#                x: immutable(uint256)
_STATEVAR_RE = re.compile(
    r"^(\w+)\s*:\s*(public\(|constant\(|immutable\()?\s*(.+?)\)?\s*(?:=\s*.+)?$"
)

# Blank / comment / docstring lines
_BLANK_OR_COMMENT_RE = re.compile(r"^\s*(?:#.*)?$")


def parse_vyper_source(source: str, file_path: str = "<unknown>") -> ContractInfo:
    """Parse raw Vyper source into a ``ContractInfo``.

    Args:
        source: The full source code of a ``.vy`` file.
        file_path: Used only for labelling — not read from disk.

    Returns:
        A ``ContractInfo`` populated with functions, events, state
        variables, imports, and the pragma version.
    """
    lines = source.splitlines()
    contract = ContractInfo(
        file_path=file_path,
        source_code=source,
        lines=lines,
    )

    idx = 0
    in_docstring = False
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        # --- Top-level triple-quoted strings (docstrings / license) ---
        # Skip entire blocks so lines like 'Contract: Foo' don't become
        # state variables.
        if not in_docstring and _is_top_level(line) and stripped.startswith('"""'):
            # Single-line docstring: """..."""
            if stripped.count('"""') >= 2:
                idx += 1
                continue
            # Multi-line: skip until closing """
            in_docstring = True
            idx += 1
            continue
        if in_docstring:
            if '"""' in stripped:
                in_docstring = False
            idx += 1
            continue

        # --- Pragma ---
        if m := _PRAGMA_RE.match(stripped):
            contract.pragma_version = (m.group(1) or m.group(2) or m.group(3)).strip()
            idx += 1
            continue

        # --- Skip Vyper directives that look like state vars ---
        if stripped.startswith(("implements:", "uses:", "initializes:", "exports:")):
            idx += 1
            continue

        # --- Interface / struct / flag block — skip the indented body ---
        if _is_top_level(line) and stripped.startswith(("interface ", "struct ", "flag ")):
            idx += 1
            while idx < len(lines) and (not lines[idx].strip() or not _is_top_level(lines[idx])):
                idx += 1
            continue

        # --- Import ---
        if _IMPORT_RE.match(stripped):
            contract.imports.append(stripped)
            idx += 1
            continue

        # --- Event ---
        if m := _EVENT_RE.match(stripped):
            event, idx = _parse_event(m.group(1), idx, lines)
            contract.events.append(event)
            continue

        # --- Decorator / function ---
        if stripped.startswith("@"):
            func, idx = _parse_function(idx, lines)
            if func:
                contract.functions.append(func)
            continue

        # --- Stand-alone ``def`` without decorators (possible internal helper) ---
        if stripped.startswith("def "):
            func, idx = _parse_function(idx, lines)
            if func:
                contract.functions.append(func)
            continue

        # --- State variable ---
        if (
            stripped
            and not stripped.startswith("#")
            and not stripped.startswith("@")
            and ":" in stripped
            and not stripped.startswith("def ")
            and not stripped.startswith("event ")
            and not stripped.startswith("interface ")
            and not stripped.startswith("struct ")
            and not stripped.startswith("flag ")
            and _is_top_level(line)
        ):
            var = _try_parse_state_variable(stripped, idx + 1)
            if var:
                contract.state_variables.append(var)

        idx += 1

    return contract


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------


def _is_top_level(line: str) -> bool:
    """Return True if *line* has zero indentation."""
    return len(line) == 0 or not line[0].isspace()


def _parse_event(name: str, start_idx: int, lines: list[str]) -> tuple[EventInfo, int]:
    """Parse an event block starting at *start_idx* (the ``event X:`` line)."""
    fields: list[str] = []
    idx = start_idx + 1
    while idx < len(lines):
        line = lines[idx]
        if not line.strip() or _is_top_level(line):
            break
        fields.append(line.strip())
        idx += 1
    return EventInfo(name=name, line_number=start_idx + 1, fields=fields), idx


def _parse_function(start_idx: int, lines: list[str]) -> tuple[FunctionInfo | None, int]:
    """Parse a function block (decorators + def + body).

    *start_idx* should point at the first decorator line or the ``def`` line.
    Handles multi-line function signatures where arguments span several lines.
    """
    decorators: list[str] = []
    idx = start_idx

    # Collect decorators
    while idx < len(lines):
        stripped = lines[idx].strip()
        if m := _DECORATOR_RE.match(stripped):
            decorators.append(m.group(1))
            idx += 1
        else:
            break

    if idx >= len(lines):
        return None, idx

    # Expect ``def ...():`` — possibly spanning multiple lines
    stripped = lines[idx].strip()
    m = _FUNCDEF_RE.match(stripped)
    def_end_idx = idx

    if not m and stripped.startswith("def "):
        # Multi-line function definition: join lines until we match
        combined = stripped
        for peek in range(idx + 1, min(idx + 15, len(lines))):
            next_line = lines[peek].strip()
            if not next_line:
                break  # blank line means something went wrong
            combined = combined + " " + next_line
            normalized = re.sub(r"\s+", " ", combined)
            m = _FUNCDEF_RE.match(normalized)
            if m:
                def_end_idx = peek
                break

    if not m:
        # Not a valid function — skip.
        return None, idx + 1

    name = m.group(1)
    args = m.group(2).strip()
    return_type = m.group(3).strip() if m.group(3) else None
    idx = def_end_idx + 1

    # Collect body (indented lines)
    body_lines: list[str] = []
    while idx < len(lines):
        line = lines[idx]
        if line.strip() == "":
            # Blank lines inside a function body are okay — but a blank
            # line followed by a top-level construct ends the function.
            # Peek ahead to decide.
            if idx + 1 < len(lines) and _is_top_level(lines[idx + 1]) and lines[idx + 1].strip():
                break
            body_lines.append(line)
            idx += 1
            continue
        if _is_top_level(line):
            break
        body_lines.append(line)
        idx += 1

    # Strip trailing blank lines from body
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()

    end_line = def_end_idx + 1 + len(body_lines)

    return (
        FunctionInfo(
            name=name,
            decorators=decorators,
            args=args,
            return_type=return_type,
            start_line=start_idx + 1,  # 1-based
            end_line=end_line,
            body_lines=body_lines,
        ),
        idx,
    )


def _try_parse_state_variable(stripped: str, line_number: int) -> StateVariableInfo | None:
    """Try to parse a top-level line as a state variable declaration."""
    m = _STATEVAR_RE.match(stripped)
    if not m:
        return None

    name = m.group(1)
    qualifier = (m.group(2) or "").rstrip("(")
    type_str = m.group(3).strip().rstrip(")")

    # Ignore identifiers that look like Python keywords / Vyper constructs.
    if name in {
        "implements",
        "uses",
        "initializes",
        "exports",
        "interface",
        "struct",
        "flag",
        "event",
    }:
        return None

    return StateVariableInfo(
        name=name,
        type_annotation=type_str if not qualifier else f"{qualifier}({type_str})",
        line_number=line_number,
        is_public=qualifier == "public",
        is_constant=qualifier == "constant",
        is_immutable=qualifier == "immutable",
    )
