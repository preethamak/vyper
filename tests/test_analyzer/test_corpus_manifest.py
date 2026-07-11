from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from guardian.analyzer.benchmark import _load_labels
from scripts.fetch_real_world_corpus import _load_manifest, fetch

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "corpus" / "real_world" / "manifest.json"


def test_real_world_manifest_has_reproducible_provenance() -> None:
    entries = _load_manifest(MANIFEST)
    assert len(entries) >= 5
    for entry in entries:
        assert len(entry["commit"]) == 40
        assert len(entry["sha256"]) == 64
        assert entry["source_url"].startswith("https://raw.githubusercontent.com/")
        assert isinstance(entry["known_false_positive_detectors"], list)


def test_fetch_verifies_hash_and_writes_contract(monkeypatch, tmp_path) -> None:
    content = b"# pragma version ^0.4.0\n"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-corpus/v1",
                "entries": [
                    {
                        "id": "sample-contract",
                        "source_url": "https://raw.githubusercontent.com/example/repo/sha/a.vy",
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    class Response:
        def __init__(self) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr("scripts.fetch_real_world_corpus.requests.get", lambda *a, **k: Response())
    destination = tmp_path / "corpus"
    paths = fetch(manifest, destination)

    assert paths == [destination / "sample-contract.vy"]
    assert paths[0].read_bytes() == content


def test_reviewed_labels_require_complete_provenance(tmp_path: Path) -> None:
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-labels/v2",
                "labels": [{"file": "vault.vy", "detector": "cei_violation"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing"):
        _load_labels(labels)


def test_reviewed_labels_count_only_confirmed_security_positives(tmp_path: Path) -> None:
    labels = tmp_path / "labels.json"
    common = {
        "reviewer": "independent-auditor@example.org",
        "reviewed_at": "2026-07-11T00:00:00Z",
        "evidence": "https://example.org/review/1",
    }
    labels.write_text(
        json.dumps(
            {
                "$schema": "vyper-guard-labels/v2",
                "labels": [
                    {
                        **common,
                        "file": "vault.vy",
                        "detector": "cei_violation",
                        "verdict": "true_positive",
                    },
                    {
                        **common,
                        "file": "safe.vy",
                        "detector": "unsafe_raw_call",
                        "verdict": "false_positive",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    loaded = _load_labels(labels)
    assert loaded["vault.vy"] == (True, {"cei_violation"})
    assert loaded["safe.vy"] == (False, set())
