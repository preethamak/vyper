"""Conservative arithmetic facts derived from preceding Vyper statements."""

from __future__ import annotations

import re

_ASSERT_GTE_RE = re.compile(r"\bassert\s+(.+?)\s*>=\s*(.+?)(?:\s*,|$)")
_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*([^#]+?)\s*$")


def normalize_expression(expression: str) -> str:
    return re.sub(r"\s+", "", expression.strip().strip("()"))


def proves_gte(preceding_source: str, left: str, right: str) -> bool:
    """Return whether supported preceding facts prove ``left >= right``.

    Supported facts are exact asserted inequalities, simple aliases, integer
    constants, and transitive combinations of those facts.
    """
    lhs = normalize_expression(left)
    rhs = normalize_expression(right)
    if lhs == rhs:
        return True
    if lhs.isdigit() and rhs.isdigit():
        return int(lhs) >= int(rhs)

    edges: dict[str, set[str]] = {}
    for raw_line in preceding_source.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        assertion = _ASSERT_GTE_RE.search(line)
        if assertion:
            _add_edge(edges, assertion.group(1), assertion.group(2))
            continue
        assignment = _ASSIGN_RE.match(line)
        if assignment:
            target = normalize_expression(assignment.group(1))
            value = normalize_expression(assignment.group(2))
            if _is_atomic(value):
                edges.setdefault(target, set()).add(value)
                edges.setdefault(value, set()).add(target)

    seen: set[str] = set()
    pending = [lhs]
    while pending:
        current = pending.pop()
        if current == rhs:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(edges.get(current, ()))
    return False


def _add_edge(edges: dict[str, set[str]], left: str, right: str) -> None:
    edges.setdefault(normalize_expression(left), set()).add(normalize_expression(right))


def _is_atomic(value: str) -> bool:
    return bool(re.fullmatch(r"(?:self\.)?[A-Za-z_]\w*(?:\[[^]]+\])*|\d+", value))
