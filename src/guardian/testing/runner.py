"""Verification helpers for unit and fuzz command execution."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CommandResult:
    name: str
    status: str
    command: list[str] | None
    exit_code: int | None
    duration_ms: float
    stdout: str
    stderr: str
    reason: str | None


def parse_command(value: str | list[str] | None) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        cleaned = [str(part).strip() for part in value if str(part).strip()]
        return cleaned or None
    text = str(value).strip()
    if not text:
        return None
    return shlex.split(text)


def command_available(command: list[str] | None) -> bool:
    if not command:
        return False
    return shutil.which(command[0]) is not None


def default_unit_command(cwd: Path) -> list[str] | None:
    if (cwd / "tests").exists() and command_available(["pytest"]):
        return ["pytest", "-q"]
    return None


def run_command(
    name: str,
    command: list[str] | None,
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_chars: int,
    skip_reason: str | None = None,
) -> CommandResult:
    if not command:
        return CommandResult(
            name=name,
            status="skipped",
            command=None,
            exit_code=None,
            duration_ms=0.0,
            stdout="",
            stderr="",
            reason=skip_reason or "No command configured.",
        )

    if not command_available(command):
        return CommandResult(
            name=name,
            status="skipped",
            command=command,
            exit_code=None,
            duration_ms=0.0,
            stdout="",
            stderr="",
            reason=f"Command not found: {command[0]}",
        )

    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = (time.perf_counter() - start) * 1000
        status = "passed" if completed.returncode == 0 else "failed"
        return CommandResult(
            name=name,
            status=status,
            command=command,
            exit_code=completed.returncode,
            duration_ms=round(duration_ms, 2),
            stdout=_truncate_output(completed.stdout, max_output_chars),
            stderr=_truncate_output(completed.stderr, max_output_chars),
            reason=None if status == "passed" else "Non-zero exit status.",
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        return CommandResult(
            name=name,
            status="error",
            command=command,
            exit_code=None,
            duration_ms=round(duration_ms, 2),
            stdout=_truncate_output(_coerce_text(exc.stdout), max_output_chars),
            stderr=_truncate_output(_coerce_text(exc.stderr), max_output_chars),
            reason=f"Timeout after {timeout_seconds}s.",
        )
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        return CommandResult(
            name=name,
            status="error",
            command=command,
            exit_code=None,
            duration_ms=round(duration_ms, 2),
            stdout="",
            stderr="",
            reason=str(exc),
        )


def result_to_dict(result: CommandResult) -> dict[str, object]:
    return {
        "name": result.name,
        "status": result.status,
        "command": result.command,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "reason": result.reason,
    }


def build_verification_summary(results: dict[str, CommandResult]) -> dict[str, object]:
    passed = sum(1 for result in results.values() if result.status == "passed")
    failed = sum(1 for result in results.values() if result.status == "failed")
    skipped = sum(1 for result in results.values() if result.status == "skipped")
    errors = sum(1 for result in results.values() if result.status == "error")
    duration_ms = sum(result.duration_ms for result in results.values())
    ok = failed == 0 and errors == 0
    return {
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "duration_ms": round(duration_ms, 2),
        "ok": ok,
    }


def _coerce_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _truncate_output(text: str, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
