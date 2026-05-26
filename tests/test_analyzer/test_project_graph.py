"""Project graph analysis tests."""

from __future__ import annotations

from pathlib import Path

from guardian.analyzer.project_graph import build_project_graph


def _write_contract(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")


def test_project_graph_resolves_imports_and_interfaces(tmp_path: Path) -> None:
    token = tmp_path / "token.vy"
    vault = tmp_path / "vault.vy"

    _write_contract(
        token,
        """# pragma version ^0.4.0

interface IERC20:
    def transfer(_to: address, _value: uint256) -> bool: nonpayable
""",
    )

    _write_contract(
        vault,
        """# pragma version ^0.4.0
import token
import missing
implements: IERC20

@external
def foo():
    pass
""",
    )

    result = build_project_graph(tmp_path, [vault, token])
    graph = result.graph

    edges = graph.get("edges", [])
    assert any(
        edge.get("import") == "token" and edge.get("resolved") is True for edge in edges
    )

    unresolved = graph.get("unresolved_imports", [])
    assert any(item.get("import") == "missing" for item in unresolved)

    vault_findings = result.findings.get(str(vault), [])
    assert any(
        finding.detector_name == "project_interface_mismatch" for finding in vault_findings
    )
