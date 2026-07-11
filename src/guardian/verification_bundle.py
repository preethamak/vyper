"""Generate reviewable exploit-verification bundles from JSON reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def generate_verification_bundle(report_path: Path, output_dir: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = _findings(report)
    candidates = [
        finding
        for finding in findings
        if isinstance(finding.get("exploit_verification"), dict)
        and finding["exploit_verification"].get("status") == "reachable"
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "vyper-guard-verification-bundle/v1",
        "source_report": str(report_path),
        "candidates": [
            {
                "detector": finding.get("detector"),
                "title": finding.get("title"),
                "line": finding.get("line_number"),
                "verification": finding["exploit_verification"],
            }
            for finding in candidates
        ],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "test_verification.py").write_text(_pytest_template(manifest), encoding="utf-8")
    (output_dir / "README.md").write_text(_readme(manifest), encoding="utf-8")
    return manifest


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(report.get("reports"), list):
        return [
            finding
            for child in report["reports"]
            if isinstance(child, dict)
            for finding in child.get("findings", [])
            if isinstance(finding, dict)
        ]
    return [finding for finding in report.get("findings", []) if isinstance(finding, dict)]


def _pytest_template(manifest: dict[str, Any]) -> str:
    candidate_count = len(manifest["candidates"])
    return f'''"""Generated Titanoboa verification worklist."""

import json
from pathlib import Path

import pytest
MANIFEST = json.loads((Path(__file__).parent / "manifest.json").read_text())


def test_verification_bundle_is_attributable():
    assert len(MANIFEST["candidates"]) == {candidate_count}
    for candidate in MANIFEST["candidates"]:
        verification = candidate["verification"]
        assert verification["status"] == "reachable"
        assert verification["finding_fingerprint_inputs"]["detector"]


@pytest.mark.skip(reason="Provide deployment and attacker fixtures before claiming reproduction")
def test_exploit_reproduction():
    boa = pytest.importorskip("boa")
    # Implement the manifest regression plan with boa.load and an attacker fixture.
    # Record reproduced/refuted evidence only after this test executes without skip.
    raise AssertionError("verification fixture not implemented")
'''


def _readme(manifest: dict[str, Any]) -> str:
    return (
        "# Exploit Verification Bundle\n\n"
        f"Candidates: {len(manifest['candidates'])}\n\n"
        "Static analysis established reachability only. Implement deployment and attacker "
        "fixtures in `test_verification.py`; do not mark a finding reproduced while the "
        "reproduction test is skipped.\n"
    )
