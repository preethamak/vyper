# pragma version ^0.3.9

# A deliberately VULNERABLE vault contract for testing.
# Contains multiple security issues that the detectors should catch.

owner: public(address)
balances: public(HashMap[address, uint256])
total_deposited: uint256

event Deposit:
    sender: indexed(address)
    amount: uint256

@deploy
def __init__():
    self.owner = msg.sender

# VULNERABILITY: @external + send() but NO @nonreentrant
@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount

# VULNERABILITY: state change without event emission
@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
    self.total_deposited += msg.value

# VULNERABILITY: raw_call without assert
@external
def execute(target: address, data: Bytes[1024]):
    raw_call(target, data)

# VULNERABILITY: writes to self.owner with NO access control
@external
def set_owner(new_owner: address):
    self.owner = new_owner

# VULNERABILITY: selfdestruct with NO access control
@external
def destroy():
    selfdestruct(self.owner)

@external
@view
def get_balance(addr: address) -> uint256:
    return self.balances[addr]
