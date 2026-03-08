# @version ^0.3.9
# Vulnerability: Missing @nonreentrant decorator on external functions with sends
# Expected detections: missing_nonreentrant, missing_event_emission

event Deposit:
    sender: indexed(address)
    amount: uint256

balances: public(HashMap[address, uint256])
total_deposits: public(uint256)

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
    self.total_deposits += msg.value
    log Deposit(msg.sender, msg.value)

@external
def withdraw(amount: uint256):
    # VULNERABILITY: No @nonreentrant — classic reentrancy
    # VULNERABILITY: No event emission for withdrawal
    assert self.balances[msg.sender] >= amount, "Insufficient"
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
    self.total_deposits -= amount

@external
def transfer(to: address, amount: uint256):
    # VULNERABILITY: No @nonreentrant and no event
    assert self.balances[msg.sender] >= amount, "Insufficient"
    self.balances[msg.sender] -= amount
    self.balances[to] += amount
