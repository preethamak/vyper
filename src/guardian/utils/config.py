"""Configuration management for Vyper Guard.

Loads settings from (in priority order):
  1. CLI flags
  2. Environment variables
  3. .guardianrc in the current directory
  4. ~/.guardianrc
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_DEFAULT_CONFIG_NAMES = [".guardianrc", ".guardianrc.yaml", ".guardianrc.yml"]


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

    default_format: str = Field(default="cli", description="cli | json | markdown")
    show_source_snippets: bool = True
    show_fix_suggestions: bool = True
    show_severity_breakdown: bool = True


class PerformanceConfig(BaseModel):
    """Resource limits."""

    max_file_size_mb: int = Field(default=10, ge=1)
    cache_enabled: bool = True
    cache_directory: str = ".guardian_cache"


class GuardianConfig(BaseModel):
    """Top-level configuration container."""

    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)


def _find_config_file(start_dir: Path | None = None) -> Path | None:
    """Walk up from *start_dir* looking for a config file."""
    directory = Path(start_dir) if start_dir else Path.cwd()
    # Check the starting directory and parents up to the home dir.
    for parent in [directory, *directory.parents]:
        for name in _DEFAULT_CONFIG_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
        if parent == Path.home():
            break
    return None


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
        found = _find_config_file(start_dir)
        if found:
            raw = _load_yaml(found)

    # Allow environment variable overrides for common settings.
    if env_fmt := os.getenv("GUARDIAN_DEFAULT_FORMAT"):
        raw.setdefault("reporting", {})["default_format"] = env_fmt

    if env_thresh := os.getenv("GUARDIAN_SEVERITY_THRESHOLD"):
        raw.setdefault("analysis", {})["severity_threshold"] = env_thresh

    return GuardianConfig.model_validate(raw)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Safely load a YAML file and return its contents as a dict."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        return {}
    return data
