from __future__ import annotations

import json
import subprocess

from guardian.analyzer.compiler_resolver import extract_pragma, resolve_compiler


def _mock_compilers(monkeypatch, tmp_path, versions: dict[str, str]) -> dict[str, str]:
    paths: dict[str, str] = {}
    for label, version in versions.items():
        path = tmp_path / label
        path.write_text("compiler", encoding="utf-8")
        paths[version] = str(path)

    monkeypatch.setenv("GUARDIAN_VYPER_BINARIES", json.dumps(paths))
    monkeypatch.setattr("guardian.analyzer.compiler_resolver.shutil.which", lambda _: None)

    def run(command, **kwargs):
        selected = next(version for version, path in paths.items() if path == command[0])
        return subprocess.CompletedProcess(command, 0, selected, "")

    monkeypatch.setattr("guardian.analyzer.compiler_resolver.subprocess.run", run)
    return paths


def test_extracts_modern_and_legacy_pragmas() -> None:
    assert extract_pragma("# pragma version ^0.4.0") == "^0.4.0"
    assert extract_pragma("# @version 0.3.10") == "0.3.10"


def test_exact_pragma_selects_matching_registered_compiler(monkeypatch, tmp_path) -> None:
    paths = _mock_compilers(
        monkeypatch,
        tmp_path,
        {"vyper-0310": "0.3.10", "vyper-043": "0.4.3"},
    )
    resolution = resolve_compiler("# pragma version 0.3.10")

    assert resolution.candidate is not None
    assert resolution.candidate.executable == paths["0.3.10"]


def test_caret_pragma_selects_newest_compatible_patch(monkeypatch, tmp_path) -> None:
    _mock_compilers(
        monkeypatch,
        tmp_path,
        {"vyper-040": "0.4.0", "vyper-043": "0.4.3", "vyper-050": "0.5.0"},
    )
    resolution = resolve_compiler("# pragma version ^0.4.0")

    assert resolution.candidate is not None
    assert resolution.candidate.version == (0, 4, 3)


def test_resolution_reports_available_versions_when_no_match(monkeypatch, tmp_path) -> None:
    _mock_compilers(monkeypatch, tmp_path, {"vyper-043": "0.4.3"})
    resolution = resolve_compiler("# @version 0.3.10")

    assert resolution.candidate is None
    assert "0.3.10" in (resolution.reason or "")
    assert "0.4.3" in (resolution.reason or "")
