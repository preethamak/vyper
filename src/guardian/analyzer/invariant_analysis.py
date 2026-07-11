"""Recognize protocol arithmetic invariants and their proof strength."""

from __future__ import annotations

import re
from dataclasses import dataclass

from guardian.models import FunctionInfo


@dataclass(frozen=True)
class InvariantEvidence:
    name: str
    strength: str
    explanation: str


def subtraction_invariant(
    func: FunctionInfo, lhs: str, rhs: str, position: int
) -> InvariantEvidence | None:
    """Return a recognized invariant supporting ``lhs -= rhs``."""
    normalized_lhs = re.sub(r"\s+", "", lhs)
    normalized_rhs = re.sub(r"\s+", "", rhs)

    if "changes_" in normalized_lhs:
        base = normalized_lhs.split("[", 1)[0]
        rhs_suffix = normalized_rhs.rsplit(".", 1)[-1]
        addition = re.compile(
            rf"{re.escape(base)}(?:\[[^]]+\])+\+=\s*(?:[A-Za-z_]\w*\.)?"
            rf"{re.escape(rhs_suffix)}"
        )
        if addition.search(re.sub(r"\s+", "", func.body_text)):
            return InvariantEvidence(
                "scheduled_slope_balance",
                "protocol_assumption",
                "Cancellation is paired with scheduling of the same slope and key shape; "
                "cross-transaction initialization must still be verified.",
            )
    return None
