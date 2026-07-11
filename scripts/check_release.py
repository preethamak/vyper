"""Validate release metadata before building or publishing distributions."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_match = re.search(
        r'^\[project\]\s*$.*?^version\s*=\s*"([^"]+)"',
        pyproject_text,
        re.MULTILINE | re.DOTALL,
    )
    if project_match is None:
        raise SystemExit("project version is missing from pyproject.toml")
    project_version = project_match.group(1)
    package_text = (ROOT / "src" / "guardian" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', package_text)
    if match is None or match.group(1) != project_version:
        raise SystemExit("pyproject.toml and guardian.__version__ do not match")

    tag = _current_tag()
    if tag is not None and tag != f"v{project_version}":
        raise SystemExit(f"release tag {tag} does not match v{project_version}")
    print(f"release metadata valid: vyper-guard {project_version}")
    return 0


def _current_tag() -> str | None:
    completed = subprocess.run(
        ["git", "describe", "--tags", "--exact-match"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


if __name__ == "__main__":
    raise SystemExit(main())
