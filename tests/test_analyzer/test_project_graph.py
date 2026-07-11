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
    assert any(edge.get("import") == "token" and edge.get("resolved") is True for edge in edges)

    unresolved = graph.get("unresolved_imports", [])
    assert any(item.get("import") == "missing" for item in unresolved)

    vault_findings = result.findings.get(str(vault), [])
    assert any(finding.detector_name == "project_interface_mismatch" for finding in vault_findings)


def test_project_graph_records_external_calls_and_roles(tmp_path: Path) -> None:
    vault = tmp_path / "vault.vy"
    _write_contract(
        vault,
        """# pragma version ^0.4.0
interface IERC20:
    def transfer(to: address, amount: uint256) -> bool: nonpayable
owner: address
token: address
@external
def sweep(recipient: address):
    assert msg.sender == self.owner
    IERC20(self.token).transfer(recipient, 1)
""",
    )
    graph = build_project_graph(tmp_path, [vault]).graph
    external_calls = graph["external_call_graph"]
    assert external_calls[0]["interface"] == "IERC20"
    assert external_calls[0]["target"] == "self.token"
    role = next(item for item in graph["role_map"] if str(item["function"]).endswith(":sweep"))
    assert role["guards"] == ["owner"]


def test_project_graph_accepts_imported_implemented_interface(tmp_path: Path) -> None:
    token = tmp_path / "token.vy"
    _write_contract(
        token,
        """# pragma version ^0.3.10
from vyper.interfaces import ERC20
implements: ERC20
""",
    )
    result = build_project_graph(tmp_path, [token])
    use = result.graph["interface_uses"][0]
    assert use["status"] == "external_import"
    assert result.findings == {}


def test_project_graph_counts_public_state_getters_as_interface_functions(tmp_path: Path) -> None:
    interface = tmp_path / "interface.vy"
    token = tmp_path / "token.vy"
    _write_contract(
        interface,
        """# pragma version ^0.3.10
interface Metadata:
    def name() -> String[32]: view
""",
    )
    _write_contract(
        token,
        """# pragma version ^0.3.10
implements: Metadata
name: public(String[32])
""",
    )
    result = build_project_graph(tmp_path, [interface, token])
    use = next(item for item in result.graph["interface_uses"] if item["interface"] == "Metadata")
    assert use["status"] == "resolved"
