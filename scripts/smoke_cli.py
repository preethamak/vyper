#!/usr/bin/env python3
"""Exercise the installed Vyper Guard CLI across its supported command surface."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "test_contracts" / "01_reentrancy_vault.vy"
SECOND_CONTRACT = ROOT / "test_contracts" / "02_unsafe_raw_call.vy"

TOP_LEVEL_COMMANDS = {
    "help",
    "analyze",
    "verify",
    "test",
    "fuzz",
    "ast",
    "flow",
    "fix",
    "analyze-address",
    "explorer",
    "agent",
    "agent-memory",
    "label-quality",
    "benchmark",
    "detectors",
    "stats",
    "diff",
    "init",
    "version",
    "monitor",
    "baseline",
    "ai",
}


def _run(args: list[str], *, cwd: Path, expected: int = 0) -> None:
    command = [sys.executable, "-m", "guardian", *args]
    result = subprocess.run(
        command,
        cwd=cwd,
        env={**os.environ, "NO_COLOR": "1"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != expected:
        rendered = " ".join(args) or "<root>"
        raise RuntimeError(
            f"command failed ({result.returncode}, expected {expected}): {rendered}\n"
            f"stdout:\n{result.stdout[-3000:]}\nstderr:\n{result.stderr[-3000:]}"
        )
    print(f"PASS  {' '.join(args) or '<root>'}")


def main() -> int:
    if not CONTRACT.is_file() or not SECOND_CONTRACT.is_file():
        raise RuntimeError("test_contracts fixtures are missing")

    with tempfile.TemporaryDirectory(prefix="vyper-guard-smoke-") as raw_tmp:
        tmp = Path(raw_tmp)

        _run(["--version"], cwd=tmp)
        _run(["--help"], cwd=tmp)
        for command in sorted(TOP_LEVEL_COMMANDS):
            _run([command, "--help"], cwd=tmp)

        _run(["help"], cwd=tmp)
        _run(["version"], cwd=tmp)
        _run(["detectors"], cwd=tmp)
        _run(["analyze", str(CONTRACT), "--semantic-mode", "source"], cwd=tmp)
        for output_format, extension in (
            ("json", "json"),
            ("markdown", "md"),
            ("sarif", "sarif"),
            ("html", "html"),
        ):
            destination = tmp / f"report.{extension}"
            _run(
                [
                    "analyze",
                    str(CONTRACT),
                    "--semantic-mode",
                    "source",
                    "--format",
                    output_format,
                    "--output",
                    str(destination),
                ],
                cwd=tmp,
            )
            if not destination.is_file() or destination.stat().st_size == 0:
                raise RuntimeError(f"empty {output_format} report")

        passing_command = f'{sys.executable} -c "raise SystemExit(0)"'
        _run(
            [
                "verify",
                str(CONTRACT),
                "--semantic-mode",
                "source",
                "--unit-cmd",
                passing_command,
                "--fuzz-cmd",
                passing_command,
                "--format",
                "json",
                "--output",
                str(tmp / "verify.json"),
            ],
            cwd=tmp,
        )
        _run(["test", str(CONTRACT), "--unit-cmd", passing_command], cwd=tmp)
        _run(["fuzz", str(CONTRACT), "--fuzz-cmd", passing_command], cwd=tmp)
        _run(["ast", str(CONTRACT), "--format", "json"], cwd=tmp)
        _run(
            ["flow", str(CONTRACT), "--format", "json", "--semantic-mode", "source"],
            cwd=tmp,
        )
        _run(["fix", str(CONTRACT), "--fix-dry-run", "--semantic-mode", "source"], cwd=tmp)
        _run(["stats", str(CONTRACT)], cwd=tmp)
        _run(["diff", str(CONTRACT), str(SECOND_CONTRACT)], cwd=tmp)
        _run(["benchmark", str(ROOT / "test_contracts"), "--format", "json"], cwd=tmp)
        _run(["init"], cwd=tmp)
        _run(["agent-memory", "stats", "--memory-file", str(tmp / "memory.jsonl")], cwd=tmp)
        _run(["ai", "config", "show"], cwd=tmp)
        _run(["explorer", "config", "show"], cwd=tmp)

    print(f"Validated {len(TOP_LEVEL_COMMANDS)} top-level command interfaces and offline workflows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
