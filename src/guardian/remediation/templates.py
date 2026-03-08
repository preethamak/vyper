"""Secure code templates for Vyper contracts.

Provides parameterised templates for common security patterns:
  - @nonreentrant insertion
  - Access-control guards
  - Safe raw_call wrappers
  - Event emission boilerplate
  - CEI reordering guidance
  - Pull-pattern refactoring
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Fix templates — hardcoded so we never depend on external JSON at runtime
# ---------------------------------------------------------------------------

TEMPLATES: dict[str, dict[str, Any]] = {
    # ---- Reentrancy / nonreentrant ----
    "add_nonreentrant": {
        "detector": "missing_nonreentrant",
        "description": "Add @nonreentrant decorator to prevent reentrancy.",
        "decorator": "@nonreentrant",
    },
    # ---- Unsafe raw_call ----
    "wrap_raw_call": {
        "detector": "unsafe_raw_call",
        "description": "Wrap raw_call() in an assert to check for success.",
        "pattern_find": r"^(\s*)raw_call\(",
        "replacement_prefix": "assert raw_call(",
    },
    # ---- Missing event emission ----
    "add_event_stub": {
        "detector": "missing_event_emission",
        "description": "Add a log statement after state changes.",
        "event_name": "StateChanged",
        "event_def": "event StateChanged:\n    caller: indexed(address)",
        "log_line": "log StateChanged(msg.sender)",
    },
    # ---- Unprotected state change ----
    "add_access_control": {
        "detector": "unprotected_state_change",
        "description": "Add msg.sender == self.owner assertion.",
        "guard_line": 'assert msg.sender == self.owner, "Not owner"',
    },
    # ---- Unprotected selfdestruct ----
    "add_selfdestruct_guard": {
        "detector": "unprotected_selfdestruct",
        "description": "Add ownership check before selfdestruct.",
        "guard_line": 'assert msg.sender == self.owner, "Not owner"',
    },
    # ---- CEI violation ----
    "reorder_cei": {
        "detector": "cei_violation",
        "description": "Move state updates before external calls (Checks → Effects → Interactions).",
    },
    # ---- Send in loop ----
    "pull_pattern_comment": {
        "detector": "send_in_loop",
        "description": "Flag the push-loop with a TODO comment for pull-pattern refactor.",
        "comment": "# TODO: Replace push loop with pull-based withdrawal pattern",
    },
    # ---- Unchecked subtraction ----
    "add_balance_check": {
        "detector": "unchecked_subtraction",
        "description": "Add assert self.x >= y before the subtraction.",
    },
    # ---- Integer overflow ----
    "upgrade_pragma": {
        "detector": "integer_overflow",
        "description": "Upgrade pragma to Vyper >=0.4.0 for built-in overflow protection.",
        "new_pragma": "# pragma version ^0.4.0",
    },
    # ---- Compiler version CVE ----
    "upgrade_compiler": {
        "detector": "compiler_version_check",
        "description": "Upgrade pragma to a non-vulnerable Vyper version.",
        "new_pragma": "# pragma version ^0.4.0",
    },
}


def get_template(detector_name: str) -> dict[str, Any] | None:
    """Return the fix template for a detector, or None."""
    for _id, tmpl in TEMPLATES.items():
        if tmpl["detector"] == detector_name:
            return tmpl
    return None
