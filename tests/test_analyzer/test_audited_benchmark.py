from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.run_audited_benchmark import _verify_sources, render_markdown, run

SOURCE = """\
# @version ^0.3.9

owner: address

@external
def set_owner(new_owner: address):
    assert msg.sender == self.owner
    self.owner = new_owner
"""


def _engagement(tmp_path: Path) -> tuple[Path, Path]:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "Contract.vy"
    source.write_text(SOURCE, encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    engagement = {
        "$schema": "vyper-guard-audit-engagement/v1",
        "id": "test-engagement",
        "protocol": "Test Protocol",
        "repository": "example/contracts",
        "audited_commit": "a" * 40,
        "verified_fix_commit": "b" * 40,
        "auditor": "Independent Auditor",
        "engagement_end": "2026-01-01",
        "audit_report": "https://example.com/audit.pdf",
        "sources": [{"path": "contracts/Contract.vy", "sha256": digest}],
        "coverage": [
            {
                "finding_id": "AUDIT-001",
                "title": "Missing event",
                "severity": "LOW",
                "support": "supported",
                "detector": "missing_event_emission",
            },
            {
                "finding_id": "AUDIT-002",
                "title": "Economic issue",
                "severity": "HIGH",
                "support": "unsupported",
            },
        ],
        "cases": [
            {
                "id": "AUDIT-001-01",
                "finding_id": "AUDIT-001",
                "file": "Contract.vy",
                "function": "set_owner",
                "detector": "missing_event_emission",
            }
        ],
    }
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    return engagement_path, source_dir


def test_audited_benchmark_reports_coverage_and_case_recall(tmp_path: Path) -> None:
    engagement, source_dir = _engagement(tmp_path)

    result = run(engagement, source_dir)

    assert result["summary"]["audit_findings_total"] == 2
    assert result["summary"]["audit_findings_supported"] == 1
    assert result["summary"]["supported_cases_rediscovered"] == 1
    assert result["summary"]["supported_case_recall"] == 1.0
    assert result["summary"]["precision"] is None
    assert result["cases"][0]["status"] == "rediscovered"
    assert "Precision: not measured" in render_markdown(result)


def test_audited_benchmark_rejects_source_hash_mismatch(tmp_path: Path) -> None:
    engagement_path, source_dir = _engagement(tmp_path)
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    engagement["sources"][0]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        _verify_sources(engagement, source_dir)
