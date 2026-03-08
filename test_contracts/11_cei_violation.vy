# @version ^0.3.9
# Vulnerability: Checks-Effects-Interactions pattern violation
# Expected detections: cei_violation

balances: public(HashMap[address, uint256])
last_withdrawal: public(HashMap[address, uint256])

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value

@external
def withdraw(amount: uint256):
    # VULNERABILITY: CEI violation — send (interaction) before state update (effect)
    assert self.balances[msg.sender] >= amount, "Insufficient"
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount

@external
def withdraw_with_raw_call(amount: uint256):
    # VULNERABILITY: CEI violation — raw_call before state update
    assert self.balances[msg.sender] >= amount, "Insufficient"
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount

@external
def withdraw_with_tracking(amount: uint256):
    # VULNERABILITY: CEI violation — external call before state update
    assert self.balances[msg.sender] >= amount, "Insufficient"
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
    self.last_withdrawal[msg.sender] = block.timestamp

@external
def safe_withdraw(amount: uint256):
    # SAFE: Correct CEI order — check, effect, interaction
    assert self.balances[msg.sender] >= amount, "Insufficient"
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)
