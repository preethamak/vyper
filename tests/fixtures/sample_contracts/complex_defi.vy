# pragma version ^0.4.0

# A DeFi-like contract with a mix of safe and unsafe patterns.

owner: public(address)
paused: public(bool)
fee_recipient: address
balances: HashMap[address, uint256]
last_update: uint256

event Deposited:
    user: indexed(address)
    amount: uint256

event Withdrawn:
    user: indexed(address)
    amount: uint256

@deploy
def __init__(fee_addr: address):
    self.owner = msg.sender
    self.fee_recipient = fee_addr

# Safe: has @nonreentrant + event
@external
@payable
@nonreentrant
def deposit():
    self.balances[msg.sender] += msg.value
    log Deposited(msg.sender, msg.value)

# VULNERABILITY: timestamp dependence in condition
@external
@nonreentrant
def withdraw(amount: uint256):
    assert not self.paused, "Paused"
    assert self.balances[msg.sender] >= amount, "Insufficient"
    assert block.timestamp > self.last_update + 3600, "Too soon"
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)
    self.last_update = block.timestamp
    log Withdrawn(msg.sender, amount)

# VULNERABILITY: raw_call with is_delegate_call=True — dangerous
@external
def upgrade_call(target: address, data: Bytes[1024]):
    assert msg.sender == self.owner, "Not owner"
    raw_call(target, data, is_delegate_call=True)

# VULNERABILITY: writes to self.paused without access control
@external
def toggle_pause():
    self.paused = not self.paused

# VULNERABILITY: writes to self.fee_recipient without access control
# AND no event emission
@external
def set_fee_recipient(new_addr: address):
    self.fee_recipient = new_addr

@external
@view
def get_balance(user: address) -> uint256:
    return self.balances[user]
