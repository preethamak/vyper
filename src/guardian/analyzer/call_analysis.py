"""Source-level external call signatures, mutability, and target trust."""

from __future__ import annotations

import re
from dataclasses import dataclass

from guardian.models import ContractInfo, FunctionInfo

_INTERFACE_START_RE = re.compile(r"^(?:interface|contract)\s+([A-Za-z_]\w*)\s*:")
_INTERFACE_METHOD_RE = re.compile(
    r"^\s*def\s+([A-Za-z_]\w*)\s*\([^)]*\)(?:\s*->\s*[^:]+)?\s*:\s*"
    r"(view|pure|nonpayable|payable|constant|modifying)\b"
)
_INTERFACE_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^()\n]+)\)\s*\.\s*([A-Za-z_]\w*)\s*\(")
_LOW_LEVEL_RE = re.compile(r"\b(send|raw_call)\s*\(\s*([^,\n)]+)")
_ALIAS_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::\s*address)?\s*=\s*([^#]+?)\s*$")
_BUILTIN_MUTABILITY = {
    ("ERC20", "allowance"): "view",
    ("ERC20", "balanceOf"): "view",
    ("ERC20", "totalSupply"): "view",
    ("ERC20", "approve"): "nonpayable",
    ("ERC20", "transfer"): "nonpayable",
    ("ERC20", "transferFrom"): "nonpayable",
}


@dataclass(frozen=True)
class ExternalCallSite:
    line: int
    interface: str | None
    method: str
    target: str
    mutability: str
    target_trust: str

    @property
    def callback_capable(self) -> bool:
        return self.mutability not in {"view", "pure"}


def interface_mutability(contract: ContractInfo) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    current: str | None = None
    interface_indent = 0
    for line in contract.lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        start = _INTERFACE_START_RE.match(stripped)
        if start and indent == 0:
            current = start.group(1)
            interface_indent = indent
            continue
        if current is not None and stripped and indent <= interface_indent:
            current = None
        if current is None:
            continue
        method = _INTERFACE_METHOD_RE.match(line)
        if method:
            mutability = {"constant": "view", "modifying": "nonpayable"}.get(
                method.group(2), method.group(2)
            )
            result[(current, method.group(1))] = mutability
    return result


def external_call_sites(contract: ContractInfo, func: FunctionInfo) -> tuple[ExternalCallSite, ...]:
    signatures = {**_BUILTIN_MUTABILITY, **interface_mutability(contract)}
    aliases: dict[str, str] = {}
    body_start = func.end_line - len(func.body_lines) + 1
    sites: list[ExternalCallSite] = []
    immutable_names = {var.name for var in contract.state_variables if var.is_immutable}
    constructor_pinned = {
        var.name
        for var in contract.state_variables
        if all(
            function.name == "__init__" or "deploy" in function.decorators
            for function in contract.functions
            if re.search(rf"\bself\.{re.escape(var.name)}\s*=", function.body_text)
        )
        and any(
            re.search(rf"\bself\.{re.escape(var.name)}\s*=", function.body_text)
            for function in contract.functions
        )
    }

    for index, line in enumerate(func.body_lines):
        code = line.split("#", 1)[0]
        alias = _ALIAS_RE.match(code)
        if alias:
            aliases[alias.group(1)] = _resolve_alias(alias.group(2).strip(), aliases)
        for match in _INTERFACE_CALL_RE.finditer(code):
            target = _resolve_alias(match.group(2).strip(), aliases)
            sites.append(
                ExternalCallSite(
                    line=body_start + index,
                    interface=match.group(1),
                    method=match.group(3),
                    target=target,
                    mutability=signatures.get((match.group(1), match.group(3)), "unknown"),
                    target_trust=_target_trust(target, func, immutable_names | constructor_pinned),
                )
            )
        for match in _LOW_LEVEL_RE.finditer(code):
            target = _resolve_alias(match.group(2).strip(), aliases)
            sites.append(
                ExternalCallSite(
                    line=body_start + index,
                    interface=None,
                    method=match.group(1),
                    target=target,
                    mutability="nonpayable",
                    target_trust=_target_trust(target, func, immutable_names | constructor_pinned),
                )
            )
    return tuple(sites)


def _resolve_alias(value: str, aliases: dict[str, str]) -> str:
    seen: set[str] = set()
    while value in aliases and value not in seen:
        seen.add(value)
        value = aliases[value]
    return value


def _target_trust(target: str, func: FunctionInfo, immutable_names: set[str]) -> str:
    if target in {"self", "self.address"} or target.startswith("0x"):
        return "fixed"
    if target.startswith("self."):
        name = target.split(".", 1)[1].split("[", 1)[0]
        return "fixed" if name in immutable_names else "governance_configured"
    parameter_names = {
        item.strip().split(":", 1)[0].strip() for item in func.args.split(",") if item.strip()
    }
    if target == "msg.sender" or target in parameter_names:
        return "caller_controlled"
    return "unknown"
