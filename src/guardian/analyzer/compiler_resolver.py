"""Pragma-aware Vyper compiler executable resolution."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_VERSION_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)")
_PRAGMA_RE = re.compile(r"^\s*#\s*(?:pragma\s+version|@version)\s+(.+?)\s*$", re.I)


@dataclass(frozen=True)
class CompilerCandidate:
    executable: str
    version: tuple[int, int, int]
    version_text: str
    source: str


@dataclass(frozen=True)
class CompilerResolution:
    candidate: CompilerCandidate | None
    pragma: str | None
    reason: str | None
    discovered: tuple[CompilerCandidate, ...]


def _parse_version(value: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(value)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def extract_pragma(source: str) -> str | None:
    for line in source.splitlines():
        match = _PRAGMA_RE.match(line)
        if match:
            return match.group(1).strip()
    return None


def _compatible(version: tuple[int, int, int], pragma: str | None) -> bool:
    if pragma is None:
        return True
    base = _parse_version(pragma)
    if base is None:
        return False
    normalized = pragma.replace(" ", "")
    if normalized.startswith("^"):
        upper = (base[0], base[1] + 1, 0) if base[0] == 0 else (base[0] + 1, 0, 0)
        return base <= version < upper
    if normalized.startswith("~"):
        return base <= version < (base[0], base[1] + 1, 0)
    if "," in normalized:
        return all(_compatible(version, part) for part in normalized.split(","))
    if normalized.startswith(">="):
        return version >= base
    if normalized.startswith("<="):
        return version <= base
    if normalized.startswith(">"):
        return version > base
    if normalized.startswith("<"):
        return version < base
    return version == base


def _candidate(path: str, source: str) -> CompilerCandidate | None:
    executable = Path(path).expanduser()
    resolved = shutil.which(str(executable)) if not executable.is_absolute() else str(executable)
    if resolved is None or not Path(resolved).is_file():
        return None
    try:
        completed = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    version_text = completed.stdout.strip()
    version = _parse_version(version_text)
    if version is None:
        return None
    return CompilerCandidate(resolved, version, version_text, source)


def discover_compilers() -> tuple[CompilerCandidate, ...]:
    configured: dict[str, str] = {}
    raw = os.getenv("GUARDIAN_VYPER_BINARIES", "").strip()
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            configured = {
                str(version): str(path)
                for version, path in payload.items()
                if isinstance(version, str) and isinstance(path, str)
            }

    candidates: list[CompilerCandidate] = []
    seen: set[str] = set()
    for version, path in configured.items():
        item = _candidate(path, f"GUARDIAN_VYPER_BINARIES[{version}]")
        if item is not None and item.executable not in seen:
            candidates.append(item)
            seen.add(item.executable)

    default = shutil.which("vyper")
    if default and default not in seen:
        item = _candidate(default, "PATH")
        if item is not None:
            candidates.append(item)

    return tuple(sorted(candidates, key=lambda item: item.version))


def resolve_compiler(source: str) -> CompilerResolution:
    pragma = extract_pragma(source)
    discovered = discover_compilers()
    compatible = [candidate for candidate in discovered if _compatible(candidate.version, pragma)]
    if compatible:
        # Prefer the newest compatible patch release.
        return CompilerResolution(compatible[-1], pragma, None, discovered)
    if not discovered:
        reason = "No validated Vyper compiler executable was discovered."
    elif pragma is None:
        reason = "No compiler could be selected."
    else:
        versions = ", ".join(candidate.version_text for candidate in discovered)
        reason = f"No discovered Vyper compiler satisfies pragma {pragma!r}; available: {versions}."
    return CompilerResolution(None, pragma, reason, discovered)
