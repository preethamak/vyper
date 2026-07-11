from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.invariant_analysis import subtraction_invariant


def test_scheduled_slope_cancellation_is_protocol_assumption() -> None:
    contract = parse_vyper_source(
        """# pragma version ^0.3.10
changes_weight: HashMap[address, HashMap[uint256, uint256]]
@external
def vote(gauge: address, end: uint256, slope: uint256):
    self.changes_weight[gauge][end] -= slope
    self.changes_weight[gauge][end] += slope
""",
        "sample.vy",
    )
    func = contract.functions[0]
    position = func.body_text.index("self.changes_weight")
    evidence = subtraction_invariant(func, "self.changes_weight[gauge][end]", "slope", position)
    assert evidence is not None
    assert evidence.strength == "protocol_assumption"
