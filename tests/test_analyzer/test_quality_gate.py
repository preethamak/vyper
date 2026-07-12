import json

from guardian.analyzer.quality_gate import evaluate_label_quality


def test_label_quality_requires_positive_negative_and_reviewers(tmp_path) -> None:
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-labels/v2",
                "labels": [
                    {
                        "file": "one.vy",
                        "detector": "unsafe_raw_call",
                        "verdict": "true_positive",
                        "reviewer": "reviewer-a",
                        "reviewed_at": "2026-01-01T00:00:00Z",
                        "evidence": "https://example.org/one",
                    },
                    {
                        "file": "two.vy",
                        "detector": "unsafe_raw_call",
                        "verdict": "true_negative",
                        "reviewer": "reviewer-b",
                        "reviewed_at": "2026-01-02T00:00:00Z",
                        "evidence": "https://example.org/two",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    payload = evaluate_label_quality(labels, min_positive=1, min_negative=1, min_reviewers=2)
    result = next(item for item in payload["detectors"] if item["detector"] == "unsafe_raw_call")
    assert result["eligible"] is True


def test_label_quality_deduplicates_locations_from_one_audit_finding(tmp_path) -> None:
    labels = tmp_path / "labels.json"
    common = {
        "detector": "missing_event_emission",
        "verdict": "true_positive",
        "reviewer": "auditor-a",
        "reviewed_at": "2026-01-01T00:00:00Z",
        "evidence": "https://example.org/audit",
        "finding_id": "AUDIT-001",
    }
    labels.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-labels/v2",
                "labels": [
                    {**common, "file": "one.vy", "function": "set_owner"},
                    {**common, "file": "two.vy", "function": "set_admin"},
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = evaluate_label_quality(labels, min_positive=2, min_negative=1, min_reviewers=1)
    result = next(
        item for item in payload["detectors"] if item["detector"] == "missing_event_emission"
    )

    assert result["positive"] == 1
    assert "positive labels 1/2" in result["reasons"]
