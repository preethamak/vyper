"""Executable spec checks to prevent docs/metadata drift."""

from __future__ import annotations

import json
import re
from pathlib import Path

from guardian.analyzer.ai_triage import (
    SCORING_VERSION,
    TRIAGE_POLICY_STATUS,
    TRIAGE_POLICY_VERSION,
    triage_policy_contract,
)
from guardian.analyzer.compiler_check import _KNOWN_VULNERABILITIES
from guardian.analyzer.static import _TIER_CAPS
from guardian.analyzer.vyper_detector import ALL_DETECTORS
from guardian.models import Severity
from guardian.remediation.fix_generator import (
    REMEDIATION_POLICY_VERSION,
    remediation_policy_contract,
    validate_remediation_policy,
)

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_detector_rules_cover_runtime_catalog_and_severity() -> None:
    data = json.loads(_read("src/guardian/db/detector_rules.json"))
    by_name = {d["name"]: d for d in data["detectors"]}

    runtime_names = {cls.NAME for cls in ALL_DETECTORS}
    expected = runtime_names | {"compiler_version_check"}

    assert set(by_name) == expected

    for cls in ALL_DETECTORS:
        assert by_name[cls.NAME]["severity"] == cls.SEVERITY.value

    assert by_name["compiler_version_check"]["severity"] == "HIGH/INFO"


def test_known_issues_align_with_compiler_check_advisories() -> None:
    data = json.loads(_read("src/guardian/db/known_issues.json"))
    by_cve = {item["cve"]: item for item in data["vulnerabilities"] if item.get("cve")}

    expected_cves = {advisory for _, _, _, advisory, _ in _KNOWN_VULNERABILITIES}
    assert set(by_cve) == expected_cves

    for _, _, severity, advisory, _ in _KNOWN_VULNERABILITIES:
        assert by_cve[advisory]["severity"] == severity.value


def test_detector_docs_scoring_matches_runtime_model() -> None:
    text = _read("docs/DETECTORS.md")

    points = {
        sev: int(val)
        for sev, val in re.findall(
            r"\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\|\s*(-?\d+)\s*\|", text
        )
    }
    assert points == {sev.value: -sev.score_penalty for sev in Severity}

    caps = {
        sev: int(val)
        for sev, val in re.findall(
            r"-\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO) max deduction:\s*(\d+)", text
        )
    }
    assert caps == {sev.value: _TIER_CAPS[sev] for sev in Severity}


def test_readme_does_not_claim_directory_scan_for_analyze() -> None:
    readme = _read("README.md")
    assert "## Analyze a Folder" not in readme
    assert "vyper-guard analyze contracts/" not in readme


def test_ai_triage_policy_contract_is_governed_and_deterministic() -> None:
    policy = triage_policy_contract()

    assert policy["policy_version"] == TRIAGE_POLICY_VERSION
    assert policy["status"] == TRIAGE_POLICY_STATUS
    assert policy["deterministic"] is True
    assert policy["can_override_verdict"] is False

    dep = policy["deprecation"]
    assert isinstance(dep, dict)
    assert set(dep) == {"announced", "sunset_after"}
    assert isinstance(dep["announced"], bool)


def test_ai_triage_scoring_version_is_explicit_and_stable() -> None:
    assert SCORING_VERSION == "triage_scoring_v1"


def test_changelog_contains_latest_phase4_governance_notes() -> None:
    changelog = _read("docs/CHANGELOG.md")

    assert "## 2026-03-22" in changelog
    assert "AI-assisted triage" in changelog
    assert "ai_triage_policy" in changelog
    assert "deprecated-policy" in changelog


def test_remediation_policy_contract_is_versioned_and_valid() -> None:
    policy = remediation_policy_contract()
    assert policy["policy_version"] == REMEDIATION_POLICY_VERSION
    assert policy["risk_tiers"] == ["A", "B", "C"]
    assert isinstance(policy["detector_tiers"], dict)
    assert isinstance(policy["tier_rules"], dict)
    assert set(policy["tier_rules"]) == {"A", "B", "C"}
    assert policy["planning_contract"]["eligibility_rule"] == "tier_rank <= max_auto_fix_tier"

    errors = validate_remediation_policy()
    assert errors == []
