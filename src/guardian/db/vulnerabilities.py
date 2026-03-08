"""Vulnerability database handler.

Loads the bundled JSON databases (known issues, detector rules, fix
templates) and provides lookup functions.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any


@lru_cache(maxsize=1)
def load_known_issues() -> list[dict[str, Any]]:
    """Return the list of known Vyper compiler vulnerabilities."""
    return _load_json("known_issues.json").get("vulnerabilities", [])


@lru_cache(maxsize=1)
def load_detector_rules() -> list[dict[str, Any]]:
    """Return detector rule metadata."""
    return _load_json("detector_rules.json").get("detectors", [])


@lru_cache(maxsize=1)
def load_fix_templates() -> list[dict[str, Any]]:
    """Return fix-template definitions."""
    return _load_json("fix_templates.json").get("templates", [])


def get_fix_template(template_id: str) -> dict[str, Any] | None:
    """Look up a fix template by its ``id`` field."""
    for tpl in load_fix_templates():
        if tpl.get("id") == template_id:
            return tpl
    return None


def get_known_issue(issue_id: str) -> dict[str, Any] | None:
    """Look up a known issue by its ``id`` field."""
    for issue in load_known_issues():
        if issue.get("id") == issue_id:
            return issue
    return None


def _load_json(filename: str) -> dict[str, Any]:
    """Load a JSON file bundled with the ``guardian.db`` package."""
    try:
        ref = resources.files("guardian.db").joinpath(filename)
        text = ref.read_text(encoding="utf-8")
        return json.loads(text)
    except Exception:
        # Fallback: load from the file path relative to this module.
        from pathlib import Path

        path = Path(__file__).parent / filename
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {}
