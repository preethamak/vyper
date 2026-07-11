"""Fetch and optionally scan the pinned real-world calibration corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "corpus" / "real_world" / "manifest.json"


def _load_manifest(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("$schema") != "vyper-guard-corpus/v1":
        raise ValueError("Unsupported corpus manifest schema.")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Corpus manifest must contain entries.")
    return entries


def _safe_filename(entry: dict[str, Any]) -> str:
    identifier = str(entry["id"])
    if not identifier.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"Unsafe corpus id: {identifier}")
    return f"{identifier}.vy"


def fetch(manifest: Path, destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    for entry in _load_manifest(manifest):
        response = requests.get(str(entry["source_url"]), timeout=30)
        response.raise_for_status()
        content = response.content
        digest = hashlib.sha256(content).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"SHA-256 mismatch for {entry['id']}: {digest}")
        output = destination / _safe_filename(entry)
        output.write_bytes(content)
        downloaded.append(output)
    return downloaded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--destination", type=Path, default=Path("/tmp/vyper-guard-corpus"))
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--report", type=Path, default=Path("/tmp/vyper-guard-corpus.json"))
    args = parser.parse_args()

    downloaded = fetch(args.manifest.resolve(), args.destination.resolve())
    print(f"Fetched {len(downloaded)} verified contracts to {args.destination.resolve()}")
    if not args.scan:
        return 0

    command = [
        "vyper-guard",
        "analyze",
        str(args.destination.resolve()),
        "--format",
        "json",
        "--output",
        str(args.report.resolve()),
    ]
    completed = subprocess.run(command, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
