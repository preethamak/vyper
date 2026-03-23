"""LLM-backed triage post-processor.

This module is optional and only used when explicitly requested.
It calls an OpenAI-compatible Chat Completions endpoint.
"""

from __future__ import annotations

import json
from typing import Any

import requests

from guardian.models import AnalysisReport, Severity

LLM_TRIAGE_POLICY_VERSION = "1.0.0"


class LLMTriageError(RuntimeError):
    """Raised when LLM triage execution fails."""


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _meets_min_severity(severity: Severity, min_severity: Severity) -> bool:
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[min_severity]


def _build_messages(
    report: AnalysisReport,
    source_code: str,
    *,
    min_severity: Severity,
    max_items: int,
) -> list[dict[str, str]]:
    findings = [
        {
            "finding_index": idx,
            "detector": f.detector_name,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "line_number": f.line_number,
            "evidence": f.evidence,
            "fix_suggestion": f.fix_suggestion,
        }
        for idx, f in enumerate(report.findings)
        if _meets_min_severity(f.severity, min_severity)
    ]

    context = {
        "file_path": report.file_path,
        "vyper_version": report.vyper_version,
        "security_score": report.security_score,
        "findings": findings,
        "max_items": max_items,
        "source_excerpt": source_code[:12000],
    }

    system_prompt = (
        "You are Vyper Guard AI Security Triage. "
        "You are assisting a static analyzer, not replacing it. "
        "Hard rules: never claim findings are safe/unsafe beyond provided evidence, "
        "never invent line numbers, never remove findings, and return valid JSON only. "
        "Return JSON object with key 'items' containing ordered triage items. "
        "Each item must include: finding_index (int), priority_rank (int), triage_bucket "
        "(review_now|review_soon|review_later), confidence (0..1 float), "
        "suggested_next_step (short string), reasoning (short string). "
        "Prioritize exploitability, blast radius, and fix urgency."
    )

    user_prompt = "Analyze and triage these findings:\n" + json.dumps(context, ensure_ascii=False)

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _extract_json_payload(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise LLMTriageError("LLM response did not contain a JSON object")

    chunk = text[start : end + 1]
    try:
        data = json.loads(chunk)
    except json.JSONDecodeError as exc:
        raise LLMTriageError(f"Failed to parse LLM triage JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise LLMTriageError("LLM triage payload must be a JSON object")
    return data


def _normalize_items(
    data: dict[str, Any], report: AnalysisReport, max_items: int
) -> list[dict[str, Any]]:
    raw_items = data.get("items", [])
    if not isinstance(raw_items, list):
        raise LLMTriageError("LLM triage payload must contain list field 'items'")

    triage: list[dict[str, Any]] = []
    for rank, item in enumerate(raw_items[: max(1, max_items)], start=1):
        if not isinstance(item, dict):
            continue
        idx = item.get("finding_index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(report.findings):
            continue

        finding = report.findings[idx]
        bucket = str(item.get("triage_bucket", "review_soon"))
        if bucket not in {"review_now", "review_soon", "review_later"}:
            bucket = "review_soon"

        try:
            confidence = float(item.get("confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        confidence = round(min(0.99, max(0.0, confidence)), 2)

        triage.append(
            {
                "finding_index": idx,
                "priority_rank": rank,
                "detector": finding.detector_name,
                "title": finding.title,
                "severity": finding.severity.value,
                "triage_bucket": bucket,
                "confidence": confidence,
                "scoring_rationale": {
                    "version": "llm_triage_v1",
                    "severity_base": None,
                    "evidence_bonus": None,
                    "evidence_count": len(finding.evidence),
                    "final_confidence": confidence,
                },
                "suggested_next_step": str(
                    item.get("suggested_next_step", "Review finding and patch urgently.")
                ),
                "reasoning": str(item.get("reasoning", "")),
                "evidence_refs": finding.evidence,
                "provenance": {
                    "mode": "llm_triage_v1",
                    "policy_version": LLM_TRIAGE_POLICY_VERSION,
                    "deterministic": False,
                    "model": "external_llm",
                    "can_override_verdict": False,
                },
            }
        )

    return triage


def apply_llm_triage(
    report: AnalysisReport,
    source_code: str,
    *,
    api_key: str,
    model: str,
    base_url: str = "https://api.openai.com/v1",
    min_severity: Severity = Severity.LOW,
    max_items: int = 50,
    temperature: float = 0.1,
    timeout: float = 45.0,
) -> AnalysisReport:
    """Attach LLM-backed triage metadata to report in advisory mode."""
    if not api_key.strip():
        raise LLMTriageError("Missing API key for LLM triage")

    messages = _build_messages(
        report,
        source_code,
        min_severity=min_severity,
        max_items=max_items,
    )

    payload = {
        "model": model,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
        "messages": messages,
    }

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        body = response.json()
    except requests.RequestException as exc:
        raise LLMTriageError(f"LLM request failed: {exc}") from exc
    except ValueError as exc:
        raise LLMTriageError("LLM response was not valid JSON") from exc

    try:
        content = body["choices"][0]["message"]["content"]
    except Exception as exc:
        raise LLMTriageError("LLM response did not include choices/message/content") from exc

    data = _extract_json_payload(str(content))
    triage = _normalize_items(data, report, max_items=max_items)

    report.ai_triage = triage
    report.ai_triage_policy = {
        "policy_version": LLM_TRIAGE_POLICY_VERSION,
        "status": "stable",
        "deterministic": False,
        "can_override_verdict": False,
        "provider": "openai_compatible",
        "model": model,
        "deprecation": {"announced": False, "sunset_after": None},
        "warnings": [
            "LLM triage is advisory only and cannot override deterministic detector verdicts.",
        ],
    }
    return report
