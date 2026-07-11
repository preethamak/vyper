"""Team policy evaluation for pull-request and CI security gates."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def evaluate_team_policy(report_path: Path, policy_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    if not isinstance(policy, dict):
        raise ValueError("team policy must be a YAML object")
    findings = _findings(report)
    gate = policy.get("gate", {}) if isinstance(policy.get("gate", {}), dict) else {}
    min_severity = str(gate.get("min_severity", "HIGH")).upper()
    min_confidence = str(gate.get("min_confidence", "HIGH")).upper()
    allowed_classifications = set(gate.get("classifications", ["new_candidate"]))
    owners = policy.get("owners", {}) if isinstance(policy.get("owners", {}), dict) else {}
    acceptances = _active_acceptances(policy.get("acceptances", []))

    blocking: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    for finding in findings:
        fingerprint = str(finding.get("fingerprint") or _fingerprint(finding))
        item = {
            "fingerprint": fingerprint,
            "detector": str(finding.get("detector") or finding.get("ruleId") or "unknown"),
            "severity": str(finding.get("severity") or "INFO").upper(),
            "confidence": str(finding.get("confidence") or "LOW").upper(),
            "title": str(finding.get("title") or finding.get("message", {}).get("text") or ""),
            "line": finding.get("line_number"),
            "owner": owners.get(str(finding.get("detector")), owners.get("default", "unassigned")),
            "classification": _classification(finding),
        }
        if fingerprint in acceptances:
            item["acceptance"] = acceptances[fingerprint]
            accepted.append(item)
        elif _blocks(item, min_severity, min_confidence, allowed_classifications):
            blocking.append(item)
        else:
            advisory.append(item)

    policy_digest = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    return {
        "schema": "vyper-guard-team-policy/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report": str(report_path),
        "policy": str(policy_path),
        "policy_digest": policy_digest,
        "passed": not blocking,
        "summary": {
            "total": len(findings),
            "blocking": len(blocking),
            "accepted": len(accepted),
            "advisory": len(advisory),
        },
        "blocking": blocking,
        "accepted": accepted,
        "advisory": advisory,
    }


def render_pr_markdown(result: dict[str, Any]) -> str:
    status = "PASS" if result["passed"] else "FAIL"
    summary = result["summary"]
    lines = [
        f"## Vyper Guard: {status}",
        "",
        f"Blocking: **{summary['blocking']}** | Accepted: **{summary['accepted']}** | "
        f"Advisory: **{summary['advisory']}**",
        "",
    ]
    if result["blocking"]:
        lines.extend(
            [
                "| Severity | Confidence | Detector | Owner | Finding |",
                "|---|---|---|---|---|",
            ]
        )
        for item in result["blocking"][:20]:
            lines.append(
                f"| {item['severity']} | {item['confidence']} | `{item['detector']}` | "
                f"{item['owner']} | {item['title']} |"
            )
        lines.append("")
    lines.append("Raw scanner findings remain available in the uploaded SARIF/JSON artifacts.")
    return "\n".join(lines) + "\n"


def append_history(result: dict[str, Any], history_path: Path, metadata: dict[str, str]) -> None:
    history_path.parent.mkdir(parents=True, exist_ok=True)
    record = {**result, "metadata": metadata}
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(report.get("reports"), list):
        return [
            finding
            for child in report["reports"]
            if isinstance(child, dict)
            for finding in child.get("findings", [])
            if isinstance(finding, dict)
        ]
    return [item for item in report.get("findings", []) if isinstance(item, dict)]


def _active_acceptances(raw: object) -> dict[str, dict[str, Any]]:
    now = datetime.now(timezone.utc)
    active: dict[str, dict[str, Any]] = {}
    if not isinstance(raw, list):
        return active
    for item in raw:
        if not isinstance(item, dict) or not item.get("fingerprint"):
            continue
        expires = item.get("expires_at")
        if expires:
            expiry = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if expiry <= now:
                continue
        if not item.get("owner") or not item.get("reason"):
            continue
        active[str(item["fingerprint"])] = item
    return active


def _blocks(
    item: dict[str, Any],
    min_severity: str,
    min_confidence: str,
    classifications: set[str],
) -> bool:
    return (
        _SEVERITY_RANK.get(item["severity"], 4) <= _SEVERITY_RANK[min_severity]
        and _CONFIDENCE_RANK.get(item["confidence"], 2) <= _CONFIDENCE_RANK[min_confidence]
        and item["classification"] in classifications
    )


def _classification(finding: dict[str, Any]) -> str:
    audit = finding.get("audit_classification", {})
    return (
        str(audit.get("classification", "new_candidate"))
        if isinstance(audit, dict)
        else "new_candidate"
    )


def _fingerprint(finding: dict[str, Any]) -> str:
    material = "|".join(str(finding.get(key, "")) for key in ("detector", "title", "line_number"))
    return hashlib.sha256(material.encode()).hexdigest()
