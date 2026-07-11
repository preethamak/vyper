from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.path_analysis import analyze_function_paths


def test_call_path_evidence_excludes_mutually_exclusive_write() -> None:
    contract = parse_vyper_source(
        """# pragma version ^0.4.0
owner: address
balance: uint256
@external
def withdraw(recipient: address, enabled: bool):
    assert msg.sender == self.owner
    if enabled:
        raw_call(recipient, b\"\")
    else:
        self.balance = 0
""",
        "sample.vy",
    )
    analysis = analyze_function_paths(contract.functions[0])
    assert analysis.call_paths == ()


def test_call_path_evidence_records_callback_and_dependency() -> None:
    contract = parse_vyper_source(
        """# pragma version ^0.4.0
balance: uint256
@external
def withdraw(recipient: address):
    assert self.balance > 0
    raw_call(recipient, b\"\")
    self.balance = 0
""",
        "sample.vy",
    )
    evidence = analyze_function_paths(contract.functions[0]).call_paths[0]
    assert evidence.callback_feasibility == "attacker_controlled"
    assert evidence.state_dependencies == ("balance",)
