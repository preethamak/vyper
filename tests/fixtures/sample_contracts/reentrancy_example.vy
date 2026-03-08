# pragma version ^0.3.9

# Demonstrates reentrancy vulnerability: external call BEFORE state update,
# AND missing @nonreentrant.

balances: public(HashMap[address, uint256])

event Withdrawal:
    sender: indexed(address)
    amount: uint256

@external
@payable
@nonreentrant
def deposit():
    self.balances[msg.sender] += msg.value

# VULNERABILITY: sends ETH before zeroing balance, no @nonreentrant
@external
def withdraw():
    amount: uint256 = self.balances[msg.sender]
    assert amount > 0, "Nothing to withdraw"
    # External call BEFORE state update — classic reentrancy pattern
    send(msg.sender, amount)
    self.balances[msg.sender] = 0
    log Withdrawal(msg.sender, amount)
