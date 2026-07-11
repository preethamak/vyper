"""Classify timestamp use by protocol domain instead of syntax alone."""

from __future__ import annotations

import re

_ACCOUNTING_NAMES = re.compile(
    r"checkpoint|epoch|supply|point|claim|distribution|accru|history|cursor|slope|bias|"
    r"_get_(?:sum|total|weight|type_weight)",
    re.I,
)
_SCHEDULING_TERMS = re.compile(
    r"week|deadline|delay|unlock|lock_end|locked|expired|\.end\b|last_user_vote|"
    r"vote_delay|timelock|ramp",
    re.I,
)
_RANDOM_TERMS = re.compile(r"random|rand|seed|lottery|winner|shuffle|dice|roll", re.I)


def classify_timestamp_use(function_name: str, line: str, context: str = "") -> str:
    combined = f"{function_name}\n{line}\n{context}"
    if _RANDOM_TERMS.search(combined):
        return "randomness"
    if _ACCOUNTING_NAMES.search(function_name) or _ACCOUNTING_NAMES.search(line):
        return "accounting"
    if _SCHEDULING_TERMS.search(combined):
        return "protocol_scheduling"
    if re.search(r"\bassert\b", line):
        return "authorization_window"
    if re.search(r"\b(?:if|elif)\b", line):
        return "state_transition"
    return "observation"
