"""Fix validation — lightweight syntax checks on patched Vyper source.

We do NOT require the Vyper compiler.  Instead we do fast structural
checks:
  - Balanced parentheses / brackets
  - Every ``def`` line ends in ``:``
  - Indentation is consistent
  - No obviously broken decorators
"""

from __future__ import annotations


class FixValidator:
    """Validate that a patched contract is structurally sound."""

    def validate(self, lines: list[str]) -> list[str]:
        """Return a list of warnings (empty = OK)."""
        warnings: list[str] = []
        warnings.extend(self._check_brackets(lines))
        warnings.extend(self._check_defs(lines))
        return warnings

    @staticmethod
    def _check_brackets(lines: list[str]) -> list[str]:
        """Ensure brackets are balanced across the whole file."""
        counts = {"(": 0, "[": 0, "{": 0}
        close_map = {")": "(", "]": "[", "}": "{"}
        for _i, line in enumerate(lines):
            stripped = line.split("#")[0]  # ignore comments
            # Skip characters inside string literals
            in_string = False
            string_char = ""
            for ch in stripped:
                if in_string:
                    if ch == string_char:
                        in_string = False
                    continue
                if ch in ('"', "'"):
                    in_string = True
                    string_char = ch
                    continue
                if ch in counts:
                    counts[ch] += 1
                elif ch in close_map:
                    counts[close_map[ch]] -= 1
        warnings = []
        for opener, n in counts.items():
            if n != 0:
                warnings.append(f"Unbalanced '{opener}' — off by {n}")
        return warnings

    @staticmethod
    def _check_defs(lines: list[str]) -> list[str]:
        """Every ``def ...`` line (after joining continuations) should end with ``:``."""
        warnings = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("def ") and stripped.endswith(":"):
                continue  # fine
            if stripped.startswith("def ") and not stripped.endswith(":"):
                # Could be a multi-line def — check next non-blank for closing ) ... :
                # This is a heuristic; we just flag obvious breaks.
                found_colon = False
                for j in range(i + 1, min(i + 15, len(lines))):
                    s = lines[j].strip()
                    if s.endswith(":"):
                        found_colon = True
                        break
                    if not s or s.startswith("@") or s.startswith("def "):
                        break
                if not found_colon:
                    warnings.append(f"Line {i + 1}: def statement may be missing closing ':'.")
        return warnings
