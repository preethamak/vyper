# pragma version ^0.4.0
# Vulnerability: Missing @nonreentrant decorator on external functions with sends
# Expected detections: missing_nonreentrant, missing_event_emission

event Deposit:
    sender: indexed(address)
    amount: uint256


event TransferExecuted:
    caller: indexed(address)


event WithdrawExecuted:
    caller: indexed(address)

balances: public(HashMap[address, uint256])
total_deposits: public(uint256)

@nonreentrant
@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
    self.total_deposits += msg.value
    log Deposit(msg.sender, msg.value)

@nonreentrant
@external
def withdraw(amount: uint256):
    # VULNERABILITY: No @nonreentrant — classic reentrancy
    # VULNERABILITY: No event emission for withdrawal
    assert self.balances[msg.sender] >= amount, "Insufficient"
    # FIXME: CEI violation — move state updates ABOVE this external call
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
    assert self.total_deposits >= amount, "Insufficient balance"
    self.total_deposits -= amount
    log WithdrawExecuted(msg.sender)

@nonreentrant
@external
def transfer(to: address, amount: uint256):
    # VULNERABILITY: No @nonreentrant and no event
    assert self.balances[msg.sender] >= amount, "Insufficient"
    self.balances[msg.sender] -= amount
    self.balances[to] += amount
    log TransferExecuted(msg.sender)