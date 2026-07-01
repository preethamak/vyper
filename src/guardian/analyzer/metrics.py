"""Cyclomatic complexity metric computation for Vyper functions.

Cyclomatic complexity (M) is a software metric that measures the number
of linearly independent paths through a function's control flow graph.

    M = E - N + 2P

where E = edges, N = nodes, P = connected components (1 for a single
function).  For source-level analysis we use the decision-point formula:

    M = 1 + number_of_branching_decisions

where a "branching decision" is an ``if``, ``elif``, ``for``, or ``while``
statement.  This is equivalent to counting the number of predicates that
can independently determine the flow of control.

Interpretation
--------------
- 1-5: Simple function, easy to test and maintain.
- 6-10: Moderate complexity, manageable.
- 11-20: High complexity - consider refactoring.
- >20: Very high — hard to test, likely to contain bugs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardian.models import ContractInfo, FunctionInfo

# Branching decision patterns in Vyper
_BRANCH_RE = re.compile(r"^\s*(?:if|elif|for|while)\b")


@dataclass
class FunctionComplexity:
    """Cyclomatic complexity for a single Vyper function."""

    func_name: str
    """Name of the function."""

    complexity: int
    """Cyclomatic complexity (M)."""

    start_line: int
    """Source line where the function starts."""

    end_line: int
    """Source line where the function ends."""

    @property
    def risk_level(self) -> str:
        """Human-readable risk level based on complexity."""
        if self.complexity <= 5:
            return "LOW"
        elif self.complexity <= 10:
            return "MEDIUM"
        elif self.complexity <= 20:
            return "HIGH"
        else:
            return "CRITICAL"


@dataclass
class ContractComplexityReport:
    """Aggregated complexity metrics for a contract."""

    contract_name: str
    functions: list[FunctionComplexity] = field(default_factory=list)

    @property
    def max_complexity(self) -> int:
        if not self.functions:
            return 0
        return max(f.complexity for f in self.functions)

    @property
    def mean_complexity(self) -> float:
        if not self.functions:
            return 0.0
        return sum(f.complexity for f in self.functions) / len(self.functions)

    @property
    def high_complexity_functions(self) -> list[FunctionComplexity]:
        """Return functions with complexity > 10."""
        return [f for f in self.functions if f.complexity > 10]

    def as_dict(self) -> dict[str, object]:
        """Serialise to a JSON-safe dict for inclusion in reports."""
        return {
            "contract_name": self.contract_name,
            "max_complexity": self.max_complexity,
            "mean_complexity": round(self.mean_complexity, 2),
            "functions": [
                {
                    "name": f.func_name,
                    "complexity": f.complexity,
                    "risk_level": f.risk_level,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                }
                for f in self.functions
            ],
        }


def _count_decisions(func: FunctionInfo) -> int:
    """Count the number of branching decision points in a function body."""
    count = 0
    for line in func.body_lines:
        # Strip inline comments before checking
        code = line.split("#", 1)[0]
        if _BRANCH_RE.match(code):
            count += 1
    return count


def compute_function_complexity(func: FunctionInfo) -> FunctionComplexity:
    """Compute cyclomatic complexity for a single function.

    Args:
        func: A parsed ``FunctionInfo`` from ``ast_parser``.

    Returns:
        A ``FunctionComplexity`` dataclass with M = 1 + decision_points.
    """
    decisions = _count_decisions(func)
    return FunctionComplexity(
        func_name=func.name,
        complexity=1 + decisions,
        start_line=func.start_line,
        end_line=func.end_line,
    )


def compute_contract_complexity(contract: ContractInfo) -> ContractComplexityReport:
    """Compute cyclomatic complexity for all functions in a contract.

    Args:
        contract: A parsed ``ContractInfo`` from ``ast_parser``.

    Returns:
        A ``ContractComplexityReport`` with per-function metrics.
    """
    from pathlib import Path as _Path

    contract_name = _Path(contract.file_path).stem if contract.file_path else "unknown"
    report = ContractComplexityReport(contract_name=contract_name)
    for func in contract.functions:
        report.functions.append(compute_function_complexity(func))
    return report
