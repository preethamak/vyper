# @version ^0.3.7
# Edge case: syntax error — should handle gracefully
# Expected: parser should not crash

owner: public(address)

@external
def __init__(
    self.owner = msg.sender
    # Missing closing paren for __init__

@external
def broken_function(
    x: uint256,
    y: uint256
) -> uint256
    # Missing colon after return type
    return x + y

@external
def another_broken():
    if True
        # Missing colon after if
        pass
