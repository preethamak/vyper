"""Fix validation — lightweight syntax checks on patched Vyper source.

We do NOT require the Vyper compiler.  Instead we do fast structural
checks:
  - Balanced parentheses / brackets
  - Every ``def`` line ends in ``:``
  - Indentation is consistent
  - No obviously broken decorators
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class FixValidator:
    """Validate that a patched contract is structurally sound."""

    def validate(self, lines: list[str]) -> list[str]:
        """Return a list of warnings (empty = OK)."""
        warnings: list[str] = []
        warnings.extend(self._check_brackets(lines))
        warnings.extend(self._check_defs(lines))
        warnings.extend(self._check_indentation(lines))
        warnings.extend(self._check_decorators(lines))
        warnings.extend(self._check_named_blocks(lines))
        return warnings

    def validate_for_release(
        self,
        lines: list[str],
        *,
        source_path: Path,
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        """Return structural and compiler-backed validation evidence."""
        structural_warnings = self.validate(lines)
        compiler = self._compile(lines, source_path=source_path, timeout_seconds=timeout_seconds)
        return {
            "ok": not structural_warnings and compiler["status"] != "failed",
            "structural": {
                "status": "passed" if not structural_warnings else "failed",
                "warnings": structural_warnings,
            },
            "compiler": compiler,
        }

    @staticmethod
    def _compile(
        lines: list[str],
        *,
        source_path: Path,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        executable = shutil.which("vyper")
        if executable is None:
            return {
                "status": "unavailable",
                "command": None,
                "exit_code": None,
                "stderr": "Vyper compiler is not installed.",
            }

        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".vy",
                prefix=f".{source_path.stem}.vyper-guard-",
                dir=source_path.parent,
                delete=False,
            ) as handle:
                handle.write("\n".join(lines) + "\n")
                temp_path = Path(handle.name)

            command = [executable, "-f", "ast", str(temp_path)]
            completed = subprocess.run(
                command,
                cwd=source_path.parent,
                capture_output=True,
                text=True,
                timeout=max(1, timeout_seconds),
                check=False,
            )
            return {
                "status": "passed" if completed.returncode == 0 else "failed",
                "command": [executable, "-f", "ast", source_path.name],
                "exit_code": completed.returncode,
                "stderr": completed.stderr[-4000:],
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "failed",
                "command": [executable, "-f", "ast", source_path.name],
                "exit_code": None,
                "stderr": f"Compiler validation timed out after {timeout_seconds} seconds.",
            }
        except OSError as exc:
            return {
                "status": "failed",
                "command": [executable, "-f", "ast", source_path.name],
                "exit_code": None,
                "stderr": str(exc),
            }
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

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

    @staticmethod
    def _check_indentation(lines: list[str]) -> list[str]:
        """Check for mixed tabs/spaces and non-4-space indentation."""
        warnings: list[str] = []
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            indent = line[: len(line) - len(line.lstrip())]
            if "\t" in indent:
                warnings.append(f"Line {i}: tab indentation detected; use spaces consistently.")
                continue
            if indent and (len(indent) % 4 != 0):
                warnings.append(
                    f"Line {i}: indentation width ({len(indent)}) is not a multiple of 4 spaces."
                )
        return warnings

    @staticmethod
    def _check_decorators(lines: list[str]) -> list[str]:
        """Flag malformed decorators and decorators not attached to a function."""
        warnings: list[str] = []
        decorator_re = re.compile(r"^@[A-Za-z_]\w*(?:\(.*\))?$")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped.startswith("@"):
                continue
            if not decorator_re.match(stripped):
                warnings.append(f"Line {i}: malformed decorator syntax '{stripped}'.")
                continue

            next_code = next(
                (candidate.strip() for candidate in lines[i:] if candidate.strip()),
                "",
            )
            if not (next_code.startswith("@") or next_code.startswith("def ")):
                warnings.append(f"Line {i}: decorator must immediately precede a function.")
        return warnings

    @staticmethod
    def _check_named_blocks(lines: list[str]) -> list[str]:
        """Require declarations such as events to contain an indented body."""
        warnings: list[str] = []
        block_re = re.compile(r"^(event|struct|interface|flag)\s+\w+.*:$")
        for i, line in enumerate(lines):
            if not block_re.match(line.strip()):
                continue
            next_line = next((candidate for candidate in lines[i + 1 :] if candidate.strip()), "")
            if next_line and not next_line.startswith((" ", "\t")):
                warnings.append(f"Line {i + 1}: declaration block has no indented body.")
        return warnings
