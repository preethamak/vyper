"""Lightweight Control Flow Graph (CFG) builder for Vyper functions.

Builds a per-function CFG from a ``FunctionInfo`` object using indentation-
based analysis of Vyper's block structure.  The CFG is used by detectors
that need path-sensitive information (e.g. CEI violation detection).

This is intentionally simple — it does NOT require the Vyper compiler and
works purely from the source-level parse produced by ``ast_parser``.

Key concepts
------------
- A ``BasicBlock`` is a maximal sequence of lines with no branches.
- Blocks are connected by directed edges representing control flow.
- ``if``/``elif``/``else`` create conditional branch edges.
- ``for``/``while`` loops create a back-edge from the loop exit to entry.
- Each block tracks whether it contains an external call or state write,
  which detectors can query without re-scanning lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardian.models import FunctionInfo

# ---------------------------------------------------------------------------
# Patterns used to classify lines
# ---------------------------------------------------------------------------

_EXTERNAL_CALL_RE = re.compile(
    r"\b(send|raw_call|create_minimal_proxy_to|create_copy_of|create_from_blueprint)\s*\("
)
_INTERFACE_CALL_RE = re.compile(r"\b[A-Za-z_]\w*\s*\([^()\n]*\)\s*\.\s*[A-Za-z_]\w*\s*\(")
_STATE_WRITE_RE = re.compile(
    r"\bself\.\w+(?:\[.*?\])*(?:\.\w+)*\s*(?:(?:<<|>>|[+\-*/%&|^])?=)(?!=)"
)
_STATE_MUTATION_CALL_RE = re.compile(
    r"\bself\.\w+(?:\[.*?\])*(?:\.\w+)*\.(append|pop|remove|clear|extend|insert)\s*\("
)

_IF_RE = re.compile(r"^\s*if\s+")
_ELIF_RE = re.compile(r"^\s*elif\s+")
_ELSE_RE = re.compile(r"^\s*else\s*:")
_FOR_RE = re.compile(r"^\s*for\s+")
_WHILE_RE = re.compile(r"^\s*while\s+")
_RETURN_RE = re.compile(r"^\s*return\b")
_RAISE_RE = re.compile(r"^\s*raise\b")


def _indent(line: str) -> int:
    """Return the indentation level (number of leading spaces) of *line*."""
    return len(line) - len(line.lstrip())


def _is_external_call_line(line: str) -> bool:
    clean = line.split("#", 1)[0].strip()
    if not clean or clean.startswith("log "):
        return False
    return bool(_EXTERNAL_CALL_RE.search(clean) or _INTERFACE_CALL_RE.search(clean))


def _is_state_write_line(line: str) -> bool:
    clean = line.split("#", 1)[0].strip()
    if not clean:
        return False
    return bool(_STATE_WRITE_RE.search(clean) or _STATE_MUTATION_CALL_RE.search(clean))


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BasicBlock:
    """A straight-line sequence of lines with no branches."""

    id: int
    """Unique block identifier within the function's CFG."""

    lines: list[int] = field(default_factory=list)
    """Absolute (1-based) line numbers belonging to this block."""

    successors: list[int] = field(default_factory=list)
    """IDs of successor blocks."""

    predecessors: list[int] = field(default_factory=list)
    """IDs of predecessor blocks."""

    has_external_call: bool = False
    """True if any line in this block contains an external call."""

    first_external_call_line: int = -1
    """Absolute line number of the first external call in this block, or -1."""

    has_state_write: bool = False
    """True if any line in this block contains a state write."""

    first_state_write_line: int = -1
    """Absolute line number of the first state write in this block, or -1."""

    branch_type: str = "sequential"
    """Edge label: sequential | if_true | if_false | loop_body | loop_exit | merge"""

    is_loop_header: bool = False
    """True if this block is the header of a ``for``/``while`` loop."""


@dataclass
class FunctionCFG:
    """Complete CFG for a single Vyper function."""

    func_name: str
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_id: int = 0
    exit_id: int = -1  # set after construction

    def get_block(self, block_id: int) -> BasicBlock | None:
        return self.blocks.get(block_id)

    def blocks_with_external_call(self) -> list[BasicBlock]:
        return [b for b in self.blocks.values() if b.has_external_call]

    def blocks_with_state_write(self) -> list[BasicBlock]:
        return [b for b in self.blocks.values() if b.has_state_write]

    def state_write_after_external_call_in_same_path(self) -> bool:
        """Return True if any reachable execution path has: call then write.

        Path-sensitive: if the call is in an if-branch and the write is
        exclusively in the else-branch, they are mutually exclusive and
        this returns False.  Only flags when a write is reachable on
        at least one path that passes through the call first.

        Algorithm
        ---------
        For each block B with an external call:
        1. Intra-block: both call and write are in B, and call line < write line.
        2. Cross-block: BFS forward from B.  A block S is entered only if
           B is an ancestor of S — i.e., we do NOT traverse into S if the
           only path to S goes through a sibling branch (else-block) that
           B cannot reach without going backwards.
        """
        for block in self.blocks.values():
            if not block.has_external_call:
                continue

            # --- Case 1: intra-block ordering ---
            if block.has_state_write:
                ecl = block.first_external_call_line
                swl = block.first_state_write_line
                if ecl != -1 and swl != -1 and ecl < swl:
                    return True
                if ecl == -1 or swl == -1:
                    return True  # conservative

            # --- Case 2: cross-block path-sensitive BFS ---
            # We track the set of blocks reachable from `block`.
            # For each candidate block C, we only enter C if
            # it has no predecessor that is NOT reachable from `block`.
            # (i.e., we can only enter C via paths that went through `block`)
            reachable: set[int] = {block.id}
            queue: list[int] = [block.id]
            changed = True
            while changed:
                changed = False
                for bid in list(queue):
                    b = self.blocks.get(bid)
                    if b is None:
                        continue
                    for succ_id in b.successors:
                        if succ_id in reachable:
                            continue
                        succ = self.blocks.get(succ_id)
                        if succ is None:
                            continue
                        # Only enter succ if ALL its predecessors are in
                        # reachable (meaning we dominate it) OR if it has
                        # no predecessors outside reachable at all.
                        non_reachable_preds = [p for p in succ.predecessors if p not in reachable]
                        if non_reachable_preds and succ.branch_type == "if_false":
                            # succ has predecessors we haven't visited —
                            # it may be a join point. Allow entry only if
                            # at least one predecessor IS reachable (we
                            # can reach it), but mark it only as a "partial"
                            # join — DO NOT skip. Instead, just don't recurse
                            # further through blocks whose writes could only
                            # be caused by those non-reachable predecessors.
                            # Simplification: if succ is if_false type,
                            # skip (it's an else-branch we can't reach).
                            continue
                        reachable.add(succ_id)
                        queue.append(succ_id)
                        changed = True

            # Check if any reachable block (other than `block` itself) has
            # a state write. For `block` itself, we already checked ordering above.
            for rid in reachable:
                if rid == block.id:
                    continue
                rb = self.blocks.get(rid)
                if rb and rb.has_state_write:
                    return True

        return False


# ---------------------------------------------------------------------------
# CFG builder
# ---------------------------------------------------------------------------


class _CFGBuilder:
    """Internal builder — do not use directly; call ``build_cfg()``."""

    def __init__(self, func: FunctionInfo) -> None:
        self._func = func
        self._body = func.body_lines
        # 1-based absolute line offset for body_lines[0]
        self._line_offset = func.end_line - len(func.body_lines) + 1
        self._next_id = 0
        self._cfg = FunctionCFG(func_name=func.name)

    def _new_block(self, branch_type: str = "sequential") -> BasicBlock:
        bid = self._next_id
        self._next_id += 1
        block = BasicBlock(id=bid, branch_type=branch_type)
        self._cfg.blocks[bid] = block
        return block

    def _link(self, pred: BasicBlock, succ: BasicBlock) -> None:
        if succ.id not in pred.successors:
            pred.successors.append(succ.id)
        if pred.id not in succ.predecessors:
            succ.predecessors.append(pred.id)

    def _annotate(self, block: BasicBlock, line: str, abs_line: int) -> None:
        """Update the block's aggregate flags from a single source line."""
        if _is_external_call_line(line):
            block.has_external_call = True
            if block.first_external_call_line == -1:
                block.first_external_call_line = abs_line
        if _is_state_write_line(line):
            block.has_state_write = True
            if block.first_state_write_line == -1:
                block.first_state_write_line = abs_line

    def build(self) -> FunctionCFG:
        """Build and return the CFG."""
        entry = self._new_block()
        self._cfg.entry_id = entry.id

        exit_block = self._new_block("sequential")
        self._cfg.exit_id = exit_block.id

        # Parse body with a simple indent-stack approach
        continuation = self._parse_block(
            lines=self._body,
            start=0,
            current_block=entry,
            exit_block=exit_block,
            base_indent=None,
        )
        # Connect the last live block to exit
        if continuation is not None and continuation is not exit_block:
            self._link(continuation, exit_block)

        return self._cfg

    def _abs_line(self, body_idx: int) -> int:
        return self._line_offset + body_idx

    def _parse_block(
        self,
        lines: list[str],
        start: int,
        current_block: BasicBlock,
        exit_block: BasicBlock,
        base_indent: int | None,
    ) -> BasicBlock | None:
        """Scan *lines* from *start*, populating *current_block*.

        Returns the block that is "live" after this segment, or None if
        control definitely exits (return/raise).
        """
        i = start
        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()
            if not stripped:
                i += 1
                continue

            ind = _indent(raw)

            # If we've left the current scope, stop
            if base_indent is not None and ind < base_indent and stripped:
                break

            # Collect inline comment-stripped code
            code = raw.split("#", 1)[0].rstrip()
            abs_ln = self._abs_line(i)

            # ---- Unconditional exits ----
            if _RETURN_RE.match(stripped) or _RAISE_RE.match(stripped):
                current_block.lines.append(abs_ln)
                self._annotate(current_block, code, abs_ln)
                self._link(current_block, exit_block)
                return None  # control exits

            # ---- if / elif / else ----
            if _IF_RE.match(raw) or _ELIF_RE.match(raw) or _ELSE_RE.match(raw):
                # Finish current block and start branching
                merge_block = self._new_block("merge")

                # Find all branches at this indentation level
                i, branch_ends = self._collect_if_branches(lines, i, ind)

                live_from_branches: list[BasicBlock] = []
                for branch_start, branch_type in branch_ends:
                    b_block = self._new_block(branch_type)
                    self._link(current_block, b_block)
                    b_indent = ind + 4  # Vyper uses 4-space indent
                    result = self._parse_block(lines, branch_start, b_block, exit_block, b_indent)
                    if result is not None:
                        live_from_branches.append(result)

                # If no else branch, current_block also flows to merge
                has_else = any(bt == "if_false" for _, bt in branch_ends)
                if not has_else:
                    live_from_branches.append(current_block)

                for lb in live_from_branches:
                    self._link(lb, merge_block)

                current_block = merge_block
                continue  # i already advanced by _collect_if_branches

            # ---- for / while loops ----
            if _FOR_RE.match(raw) or _WHILE_RE.match(raw):
                loop_header = self._new_block("loop_body")
                loop_header.is_loop_header = True
                self._link(current_block, loop_header)

                current_block.lines.append(abs_ln)
                self._annotate(current_block, code, abs_ln)

                loop_exit = self._new_block("loop_exit")
                # header → exit (loop may not execute)
                self._link(loop_header, loop_exit)

                # Parse loop body
                body_start = i + 1
                b_indent = ind + 4
                result = self._parse_block(lines, body_start, loop_header, exit_block, b_indent)
                if result is not None:
                    self._link(result, loop_header)  # back-edge

                # Skip past loop body lines
                i += 1
                while i < len(lines):
                    inner = lines[i]
                    if not inner.strip():
                        i += 1
                        continue
                    if _indent(inner) > ind:
                        i += 1
                    else:
                        break

                current_block = loop_exit
                continue

            # ---- Regular statement ----
            current_block.lines.append(abs_ln)
            self._annotate(current_block, code, abs_ln)
            i += 1

        return current_block

    def _collect_if_branches(
        self, lines: list[str], start: int, if_indent: int
    ) -> tuple[int, list[tuple[int, str]]]:
        """Scan from *start* to collect all if/elif/else branch start indices.

        Returns (next_i_after_ALL_branch_bodies, [(body_start_idx, branch_type), ...]).

        Critically, after recording each branch header, we skip the entire
        indented body of that branch so the outer _parse_block loop does not
        re-process those lines into the wrong block.
        """
        branches: list[tuple[int, str]] = []
        i = start
        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()
            if not stripped:
                i += 1
                continue
            ind = _indent(raw)
            if ind != if_indent:
                break  # left the if/elif/else block
            if _IF_RE.match(raw) or _ELIF_RE.match(raw):
                branches.append((i + 1, "if_true"))
                i += 1
                # Skip the body of this branch
                while i < len(lines):
                    inner = lines[i]
                    if not inner.strip():
                        i += 1
                        continue
                    if _indent(inner) > if_indent:
                        i += 1
                    else:
                        break
            elif _ELSE_RE.match(raw):
                branches.append((i + 1, "if_false"))
                i += 1
                # Skip the body of this branch
                while i < len(lines):
                    inner = lines[i]
                    if not inner.strip():
                        i += 1
                        continue
                    if _indent(inner) > if_indent:
                        i += 1
                    else:
                        break
            else:
                break
        return i, branches


def build_cfg(func: FunctionInfo) -> FunctionCFG:
    """Build a ``FunctionCFG`` for the given *func*.

    Args:
        func: A parsed ``FunctionInfo`` from ``ast_parser``.

    Returns:
        A ``FunctionCFG`` containing basic blocks and their edges.

    Example::

        cfg = build_cfg(func)
        if cfg.state_write_after_external_call_in_same_path():
            # CEI violation on a reachable path
            ...
    """
    return _CFGBuilder(func).build()
