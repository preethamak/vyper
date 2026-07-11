from guardian.analyzer.range_analysis import proves_gte


def test_proves_transitive_bound_through_alias() -> None:
    source = """assert self.balance[msg.sender] >= available
amount = available
"""
    assert proves_gte(source, "self.balance[msg.sender]", "amount")


def test_does_not_merge_different_mapping_keys() -> None:
    source = "assert self.balance[owner] >= amount"
    assert not proves_gte(source, "self.balance[msg.sender]", "amount")
