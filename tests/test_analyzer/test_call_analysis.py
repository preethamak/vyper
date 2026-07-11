from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.call_analysis import external_call_sites, interface_mutability


def test_interface_view_call_and_state_alias_are_resolved() -> None:
    contract = parse_vyper_source(
        """# pragma version ^0.3.10
interface VotingEscrow:
    def locked__end(user: address) -> uint256: view
voting_escrow: address
@external
def vote():
    escrow: address = self.voting_escrow
    end: uint256 = VotingEscrow(escrow).locked__end(msg.sender)
    self.voting_escrow = escrow
""",
        "sample.vy",
    )
    assert interface_mutability(contract)[("VotingEscrow", "locked__end")] == "view"
    site = external_call_sites(contract, contract.functions[0])[0]
    assert site.mutability == "view"
    assert site.target == "self.voting_escrow"
    assert site.target_trust == "governance_configured"
    assert site.callback_capable is False


def test_parameter_target_is_caller_controlled() -> None:
    contract = parse_vyper_source(
        """# pragma version ^0.4.0
interface Hook:
    def run(): nonpayable
@external
def execute(target: address):
    Hook(target).run()
""",
        "sample.vy",
    )
    site = external_call_sites(contract, contract.functions[0])[0]
    assert site.target_trust == "caller_controlled"
    assert site.callback_capable is True
