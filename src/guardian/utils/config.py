"""Configuration management for Vyper Guard.

Loads settings from (in priority order):
  1. CLI flags
  2. Environment variables
  3. .guardianrc in the current directory
  4. ~/.guardianrc
"""

from __future__ import annotations

import contextlib
import copy
import os
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_DEFAULT_CONFIG_NAMES = [".guardianrc", ".guardianrc.yaml", ".guardianrc.yml"]
_ALLOWED_FORMATS = {"cli", "json", "markdown", "sarif", "html"}
_ALLOWED_THRESHOLDS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_ALLOWED_FIX_TIERS = {"A", "B", "C"}


def _is_truthy_env(value: str | None) -> bool:
    return bool(value and value.strip().lower() in {"1", "true", "yes", "on"})


class AnalysisConfig(BaseModel):
    """Settings that control which detectors run and how."""

    enabled_detectors: list[str] = Field(
        default_factory=lambda: ["all"],
        description="List of detector names to run, or ['all'].",
    )
    disabled_detectors: list[str] = Field(default_factory=list)
    severity_threshold: str = Field(
        default="LOW",
        description="Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL).",
    )
    max_findings: int = Field(default=100, ge=1)


class ReportingConfig(BaseModel):
    """Settings for output formatting."""

    default_format: str = Field(default="cli", description="cli | json | markdown | sarif | html")
    show_source_snippets: bool = True
    show_fix_suggestions: bool = True
    show_severity_breakdown: bool = True


class PerformanceConfig(BaseModel):
    """Resource limits."""

    max_file_size_mb: int = Field(default=10, ge=1)
    cache_enabled: bool = True
    cache_directory: str = ".guardian_cache"


class RemediationConfig(BaseModel):
    """Settings controlling auto-remediation behavior."""

    max_auto_fix_tier: str = Field(default="C", description="A | B | C")


class AITriageConfig(BaseModel):
    """Settings for optional AI-assisted triage post-processing."""

    enabled: bool = False
    min_severity: str = Field(default="LOW", description="INFO | LOW | MEDIUM | HIGH | CRITICAL")
    max_items: int = Field(default=50, ge=1)
    policy_status: str = Field(default="stable", description="stable | experimental | deprecated")
    deprecation_announced: bool = False
    deprecation_sunset_after: str | date | None = None


class LLMConfig(BaseModel):
    """Settings for LLM-backed triage/agent features."""

    enabled: bool = False
    provider: str = Field(default="openai_compatible")
    model: str = Field(default="gpt-5")
    base_url: str = Field(default="https://api.openai.com/v1")
    api_key: str | None = None
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    max_items: int = Field(default=50, ge=1)
    memory_file: str = Field(default=".guardian_agent_memory.jsonl")
    memory_max_entries: int = Field(default=2000, ge=1)


class ExplorerConfig(BaseModel):
    """Settings for block explorer lookups."""

    provider: str = Field(default="etherscan")
    network: str = Field(default="ethereum")
    api_key: str | None = None


class GuardianConfig(BaseModel):
    """Top-level configuration container."""

    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    ai_triage: AITriageConfig = Field(default_factory=AITriageConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    explorer: ExplorerConfig = Field(default_factory=ExplorerConfig)


def _find_config_file(start_dir: Path | None = None) -> Path | None:
    """Walk up from *start_dir* looking for a config file."""
    directory = Path(start_dir) if start_dir else Path.cwd()
    trust_parent = _is_truthy_env(os.getenv("GUARDIAN_TRUST_PARENT_CONFIG"))
    # Default: only the current directory config is trusted.
    candidates = [directory, *directory.parents] if trust_parent else [directory]
    for parent in candidates:
        for name in _DEFAULT_CONFIG_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
        if trust_parent and parent == Path.home():
            break
    return None


def _user_config_path() -> Path:
    return Path.home() / ".guardianrc"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base.

    Scalars/lists from override replace base values.
    """
    out: dict[str, Any] = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_config(
    config_path: str | None = None,
    start_dir: Path | None = None,
) -> GuardianConfig:
    """Load and merge configuration from disk.

    Args:
        config_path: Explicit path to a YAML config file. If provided, only
            this file is loaded (no auto-discovery).
        start_dir: Directory from which to begin auto-discovery if
            *config_path* is not given.

    Returns:
        A fully resolved ``GuardianConfig``.
    """
    raw: dict[str, Any] = {}

    if config_path:
        path = Path(config_path)
        if path.is_file():
            raw = _load_yaml(path)
    else:
        # Merge order (low -> high): user ~/.guardianrc, project .guardianrc
        # Environment variable overrides are applied below.
        user_cfg = _user_config_path()
        if user_cfg.is_file():
            raw = _deep_merge(raw, _load_yaml(user_cfg))

        found = _find_config_file(start_dir)
        if found and found.resolve() != user_cfg.resolve():
            raw = _deep_merge(raw, _load_yaml(found))

    # Allow environment variable overrides for common settings.
    if env_fmt := os.getenv("GUARDIAN_DEFAULT_FORMAT"):
        env_fmt_norm = env_fmt.strip().lower()
        if env_fmt_norm in _ALLOWED_FORMATS:
            raw.setdefault("reporting", {})["default_format"] = env_fmt_norm

    if env_thresh := os.getenv("GUARDIAN_SEVERITY_THRESHOLD"):
        env_thresh_norm = env_thresh.strip().upper()
        if env_thresh_norm in _ALLOWED_THRESHOLDS:
            raw.setdefault("analysis", {})["severity_threshold"] = env_thresh_norm

    if env_fix_tier := os.getenv("GUARDIAN_MAX_AUTO_FIX_TIER"):
        env_fix_norm = env_fix_tier.strip().upper()
        if env_fix_norm in _ALLOWED_FIX_TIERS:
            raw.setdefault("remediation", {})["max_auto_fix_tier"] = env_fix_norm

    if env_ai_triage := os.getenv("GUARDIAN_AI_TRIAGE"):
        raw.setdefault("ai_triage", {})["enabled"] = _is_truthy_env(env_ai_triage)

    if env_ai_min := os.getenv("GUARDIAN_AI_TRIAGE_MIN_SEVERITY"):
        raw.setdefault("ai_triage", {})["min_severity"] = env_ai_min

    if env_ai_max := os.getenv("GUARDIAN_AI_TRIAGE_MAX_ITEMS"):
        with contextlib.suppress(ValueError):
            raw.setdefault("ai_triage", {})["max_items"] = int(env_ai_max)

    if env_ai_status := os.getenv("GUARDIAN_AI_TRIAGE_POLICY_STATUS"):
        raw.setdefault("ai_triage", {})["policy_status"] = env_ai_status

    if env_ai_dep_ann := os.getenv("GUARDIAN_AI_TRIAGE_DEPRECATION_ANNOUNCED"):
        raw.setdefault("ai_triage", {})["deprecation_announced"] = _is_truthy_env(env_ai_dep_ann)

    if env_ai_dep_sunset := os.getenv("GUARDIAN_AI_TRIAGE_DEPRECATION_SUNSET_AFTER"):
        raw.setdefault("ai_triage", {})["deprecation_sunset_after"] = env_ai_dep_sunset

    if env_llm_enabled := os.getenv("GUARDIAN_LLM_ENABLED"):
        raw.setdefault("llm", {})["enabled"] = _is_truthy_env(env_llm_enabled)

    if env_llm_provider := os.getenv("GUARDIAN_LLM_PROVIDER"):
        raw.setdefault("llm", {})["provider"] = env_llm_provider

    if env_llm_model := os.getenv("GUARDIAN_LLM_MODEL"):
        raw.setdefault("llm", {})["model"] = env_llm_model

    if env_llm_url := os.getenv("GUARDIAN_LLM_BASE_URL"):
        raw.setdefault("llm", {})["base_url"] = env_llm_url

    if env_llm_key := os.getenv("GUARDIAN_LLM_API_KEY"):
        raw.setdefault("llm", {})["api_key"] = env_llm_key

    if env_llm_mem := os.getenv("GUARDIAN_LLM_MEMORY_FILE"):
        raw.setdefault("llm", {})["memory_file"] = env_llm_mem

    if env_llm_mem_max := os.getenv("GUARDIAN_LLM_MEMORY_MAX_ENTRIES"):
        with contextlib.suppress(ValueError):
            raw.setdefault("llm", {})["memory_max_entries"] = int(env_llm_mem_max)

    if env_exp_provider := os.getenv("GUARDIAN_EXPLORER_PROVIDER"):
        raw.setdefault("explorer", {})["provider"] = env_exp_provider

    if env_exp_net := os.getenv("GUARDIAN_EXPLORER_NETWORK"):
        raw.setdefault("explorer", {})["network"] = env_exp_net

    if env_exp_key := os.getenv("GUARDIAN_EXPLORER_API_KEY"):
        raw.setdefault("explorer", {})["api_key"] = env_exp_key

    return GuardianConfig.model_validate(raw)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Safely load a YAML file and return its contents as a dict."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        return {}
    return data
