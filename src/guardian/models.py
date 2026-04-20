"""Shared data models for Vyper Guard.

All core types used across modules: severity levels, detector results,
contract info, and analysis reports.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """Vulnerability severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score_penalty(self) -> int:
        """Points deducted from the base security score of 100.

        Weights are calibrated so that a single CRITICAL issue dominates
        the score, while LOW/INFO findings nudge it gently.
        """
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }[self]


class Confidence(str, enum.Enum):
    """Confidence level of a detector finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnerabilityType(str, enum.Enum):
    """Categorisation of vulnerability classes."""

    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    EXTERNAL_CALL = "external_call"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    CODE_QUALITY = "code_quality"
    SELF_DESTRUCT = "self_destruct"
    DELEGATE_CALL = "delegate_call"
    COMPILER_BUG = "compiler_bug"
    DENIAL_OF_SERVICE = "denial_of_service"
    INPUT_VALIDATION = "input_validation"


class DetectorResult(BaseModel):
    """A single finding produced by a detector."""

    detector_name: str = Field(description="Machine name of the detector that produced this.")
    severity: Severity
    confidence: Confidence
    vulnerability_type: VulnerabilityType
    title: str = Field(description="One-line human-readable title.")
    description: str = Field(description="Detailed explanation of the finding.")
    line_number: int | None = Field(default=None, description="1-based line number in source.")
    end_line_number: int | None = Field(default=None)
    source_snippet: str | None = Field(default=None, description="Relevant source code excerpt.")
    fix_suggestion: str | None = Field(default=None, description="Suggested code fix.")
    why_flagged: str | None = Field(default=None, description="Short rationale for this finding.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Concrete evidence fragments (source snippets, line references, matched patterns).",
    )
    why_not_suppressed: str | None = Field(
        default=None,
        description="Why suppression heuristics did not suppress this finding.",
    )
    semantic_context: dict[str, str | int | bool | list[str]] = Field(
        default_factory=dict,
        description="Lightweight semantic summary for the enclosing function/context.",
    )


class FunctionInfo(BaseModel):
    """Parsed representation of a single Vyper function."""

    name: str
    decorators: list[str] = Field(default_factory=list)
    args: str = Field(default="", description="Raw argument string from the def line.")
    return_type: str | None = None
    start_line: int = Field(description="1-based line where the first decorator appears.")
    end_line: int = Field(description="1-based line of the last line of the body.")
    body_lines: list[str] = Field(default_factory=list, description="Raw body source lines.")

    @property
    def is_external(self) -> bool:
        return "external" in self.decorators

    @property
    def is_internal(self) -> bool:
        return "internal" in self.decorators

    @property
    def is_view(self) -> bool:
        return "view" in self.decorators

    @property
    def is_pure(self) -> bool:
        return "pure" in self.decorators

    @property
    def is_nonreentrant(self) -> bool:
        return "nonreentrant" in self.decorators

    @property
    def is_payable(self) -> bool:
        return "payable" in self.decorators

    @property
    def body_text(self) -> str:
        return "\n".join(self.body_lines)


class EventInfo(BaseModel):
    """Parsed representation of a Vyper event declaration."""

    name: str
    line_number: int
    fields: list[str] = Field(default_factory=list)


class StateVariableInfo(BaseModel):
    """Parsed representation of a Vyper state variable."""

    name: str
    type_annotation: str
    line_number: int
    is_public: bool = False
    is_constant: bool = False
    is_immutable: bool = False


class ContractInfo(BaseModel):
    """Structured representation of a parsed Vyper contract."""

    file_path: str
    source_code: str
    pragma_version: str | None = None
    functions: list[FunctionInfo] = Field(default_factory=list)
    events: list[EventInfo] = Field(default_factory=list)
    state_variables: list[StateVariableInfo] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    lines: list[str] = Field(default_factory=list, description="All source lines (0-indexed).")


class SecurityGrade(str, enum.Enum):
    """Letter grade derived from the numeric security score."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    F = "F"

    @classmethod
    def from_score(cls, score: int) -> SecurityGrade:
        if score >= 90:
            return cls.A_PLUS
        if score >= 75:
            return cls.A
        if score >= 60:
            return cls.B
        if score >= 45:
            return cls.C
        return cls.F

    @property
    def label(self) -> str:
        labels = {
            SecurityGrade.A_PLUS: "Production Ready",
            SecurityGrade.A: "Minor fixes needed",
            SecurityGrade.B: "Review required",
            SecurityGrade.C: "Risky — major fixes needed",
            SecurityGrade.F: "Do not deploy",
        }
        return labels[self]


class AnalysisReport(BaseModel):
    """Complete output of a static analysis run."""

    file_path: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    vyper_version: str | None = None
    analysis_context: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional context about the analyzed artifact, such as explorer metadata or ABI-derived stats.",
    )
    findings: list[DetectorResult] = Field(default_factory=list)
    ai_triage: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Optional AI-assisted triage metadata (post-processor only).",
    )
    ai_triage_policy: dict[str, Any] = Field(
        default_factory=dict,
        description="Policy contract metadata for AI triage payload compatibility/governance.",
    )
    detectors_run: list[str] = Field(default_factory=list)
    failed_detectors: list[str] = Field(
        default_factory=list,
        description="Detector names that failed during execution.",
    )
    detector_errors: dict[str, str] = Field(
        default_factory=dict,
        description="Best-effort detector failure reasons keyed by detector name.",
    )
    security_score: int = 100
    grade: SecurityGrade = SecurityGrade.A_PLUS

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


# =====================================================================
# Phase 2: Monitoring models
# =====================================================================


class AlertSeverity(str, enum.Enum):
    """Severity level for live-monitoring alerts."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class TransactionRecord(BaseModel):
    """A single observed transaction to/from the monitored contract."""

    tx_hash: str
    block_number: int
    timestamp: datetime
    from_address: str
    to_address: str | None = None
    value_wei: int = 0
    gas_used: int = 0
    gas_price_wei: int = 0
    input_data: str = Field(default="0x", description="Hex-encoded calldata.")
    function_selector: str | None = None
    success: bool = True


class BaselineProfile(BaseModel):
    """Statistical profile of 'normal' contract behaviour."""

    contract_address: str
    window_start: datetime
    window_end: datetime
    tx_count: int = 0
    avg_gas: float = 0.0
    std_gas: float = 0.0
    avg_value_wei: float = 0.0
    function_call_counts: dict[str, int] = Field(default_factory=dict)
    avg_tx_interval_secs: float = 0.0
    failed_tx_ratio: float = 0.0
    max_observed_gas: int = 0


class MonitorAlert(BaseModel):
    """An alert raised by the live monitoring system."""

    alert_id: str = Field(default="", description="Unique alert identifier.")
    severity: AlertSeverity
    rule_name: str
    title: str
    description: str
    contract_address: str
    tx_hash: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, str | int | float] = Field(default_factory=dict)
