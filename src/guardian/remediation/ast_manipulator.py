"""Source-level code patcher for Vyper contracts.

Uses text / regex-based patching (NOT AST round-tripping) to apply
fixes to Vyper source files.  This pragmatic approach avoids the need
for a Vyper AST→source serialiser, which does not exist.

All operations work on a **list of source lines** and return a new list,
leaving the original untouched.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Patch:
    """A single source-level edit to apply.

    Line numbers are **1-based** and inclusive.
    """

    start_line: int
    end_line: int
    new_lines: list[str]
    description: str = ""


class CodePatcher:
    """Accumulate ``Patch`` objects and apply them to source lines.

    Patches are applied from **bottom to top** so earlier line-numbers
    are not invalidated by preceding edits.
    """

    def __init__(self, source_lines: list[str]) -> None:
        self._original = list(source_lines)
        self._patches: list[Patch] = []

    # -- Patch registration --------------------------------------------------

    def add_patch(self, patch: Patch) -> None:
        """Register a patch.

        Overlapping patches are rejected to avoid line-range corruption.
        """
        if patch.start_line < 1 or patch.end_line < patch.start_line:
            raise ValueError("Invalid patch range.")

        for i, existing in enumerate(self._patches):
            overlaps = not (
                patch.end_line < existing.start_line or patch.start_line > existing.end_line
            )
            if overlaps:
                # Identical range: coalesce compatible insert-style patches.
                if patch.start_line == existing.start_line and patch.end_line == existing.end_line:
                    if patch.start_line == patch.end_line:
                        base_line = self._original[patch.start_line - 1]
                        existing_is_insert = (
                            bool(existing.new_lines) and existing.new_lines[-1] == base_line
                        )
                        new_is_insert = bool(patch.new_lines) and patch.new_lines[-1] == base_line
                        if existing_is_insert and new_is_insert:
                            merged_prefix = list(existing.new_lines[:-1])
                            for line in patch.new_lines[:-1]:
                                if line not in merged_prefix:
                                    merged_prefix.append(line)
                            self._patches[i] = Patch(
                                start_line=existing.start_line,
                                end_line=existing.end_line,
                                new_lines=[*merged_prefix, base_line],
                                description=existing.description or patch.description,
                            )
                            return
                    # Fallback for exact same range non-insert edits: latest wins.
                    self._patches[i] = patch
                    return

                raise ValueError(
                    "Overlapping patches are not allowed: "
                    f"new [{patch.start_line},{patch.end_line}] conflicts with "
                    f"existing [{existing.start_line},{existing.end_line}]"
                )
        self._patches.append(patch)

    # -- High-level helpers that create patches ------------------------------

    def insert_decorator(self, func_start_line: int, decorator: str) -> Patch:
        """Insert a decorator line above the function at *func_start_line* (1-based).

        Walks *upward* from *func_start_line* to find the first existing
        decorator, then inserts *decorator* above it.
        """
        idx = func_start_line - 1  # 0-based
        # Walk backwards through decorators to find the top
        top = idx
        while top > 0 and self._original[top - 1].strip().startswith("@"):
            top -= 1
        indent = _get_indent(self._original[top])
        new_line = f"{indent}{decorator}"
        patch = Patch(
            start_line=top + 1,
            end_line=top + 1,
            new_lines=[new_line, self._original[top]],
            description=f"Insert {decorator} above line {top + 1}",
        )
        self.add_patch(patch)
        return patch

    def insert_line_before(self, line_number: int, text: str) -> Patch:
        """Insert *text* as a new line immediately before *line_number* (1-based)."""
        idx = line_number - 1
        indent = _get_indent(self._original[idx]) if idx < len(self._original) else ""
        new_line = f"{indent}{text}"
        patch = Patch(
            start_line=line_number,
            end_line=line_number,
            new_lines=[new_line, self._original[idx]],
            description=f"Insert line before {line_number}",
        )
        self.add_patch(patch)
        return patch

    def insert_line_after(self, line_number: int, text: str) -> Patch:
        """Insert *text* as a new line immediately after *line_number* (1-based)."""
        idx = line_number - 1
        indent = _get_indent(self._original[idx]) if idx < len(self._original) else ""
        new_line = f"{indent}{text}"
        patch = Patch(
            start_line=line_number,
            end_line=line_number,
            new_lines=[self._original[idx], new_line],
            description=f"Insert line after {line_number}",
        )
        self.add_patch(patch)
        return patch

    def replace_lines(self, start: int, end: int, new_lines: list[str]) -> Patch:
        """Replace lines *start..end* (1-based, inclusive) with *new_lines*."""
        patch = Patch(
            start_line=start,
            end_line=end,
            new_lines=new_lines,
            description=f"Replace lines {start}-{end}",
        )
        self.add_patch(patch)
        return patch

    def swap_lines(self, line_a: int, line_b: int) -> Patch:
        """Swap two lines (1-based)."""
        a_text = self._original[line_a - 1]
        b_text = self._original[line_b - 1]
        if line_a > line_b:
            line_a, line_b = line_b, line_a
            a_text, b_text = b_text, a_text
        patch = Patch(
            start_line=line_a,
            end_line=line_b,
            new_lines=[
                b_text,
                *self._original[line_a : line_b - 1],
                a_text,
            ],
            description=f"Swap lines {line_a} and {line_b}",
        )
        self.add_patch(patch)
        return patch

    # -- Application ---------------------------------------------------------

    def apply(self) -> list[str]:
        """Apply all registered patches and return the new source lines.

        Patches are applied bottom-to-top so line numbers stay valid.
        """
        result = list(self._original)
        # Sort patches by start_line descending so bottom-most is applied first
        sorted_patches = sorted(self._patches, key=lambda p: p.start_line, reverse=True)
        for p in sorted_patches:
            s = p.start_line - 1  # 0-based inclusive
            e = p.end_line  # 0-based exclusive (since end_line is 1-based inclusive)
            result[s:e] = p.new_lines
        return result

    @property
    def original(self) -> list[str]:
        return list(self._original)


# -- Utilities ---------------------------------------------------------------


def _get_indent(line: str) -> str:
    """Return the leading whitespace of *line*."""
    return line[: len(line) - len(line.lstrip())]


def generate_diff(original: list[str], patched: list[str], filename: str = "contract.vy") -> str:
    """Generate a unified diff between *original* and *patched* line lists."""
    import difflib

    orig = [line + "\n" if not line.endswith("\n") else line for line in original]
    new = [line + "\n" if not line.endswith("\n") else line for line in patched]
    diff = difflib.unified_diff(
        orig,
        new,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="\n",
    )
    return "".join(diff)
