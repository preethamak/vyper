# pragma version ^0.3.7

# ============================================================
# DELIBERATELY VULNERABLE — For demonstration purposes only!
# Run: vyper-guard analyze docs/examples/vulnerable_vault.vy
# ============================================================

# State variables
owner: public(address)
balances: public(HashMap[address, uint256])
is_paused: public(bool)
recipients: DynArray[address, 100]

@deploy
def __init__():
    self.owner = msg.sender

# BUG 1: Missing @nonreentrant (CRITICAL)
# BUG 2: CEI violation — sends before state update (HIGH)
# BUG 3: Missing event emission (MEDIUM)
@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount

# BUG 4: Unprotected state change — no msg.sender check (HIGH)
# BUG 5: Missing event emission (MEDIUM)
@external
def set_owner(new_owner: address):
    self.owner = new_owner

# BUG 6: Unprotected selfdestruct (CRITICAL)
@external
def emergency():
    selfdestruct(self.owner)

# BUG 7: Send in loop — DoS if one recipient reverts (HIGH)
@external
def distribute():
    assert msg.sender == self.owner
    for addr: address in self.recipients:
        send(addr, 1)

# BUG 8: Unsafe raw_call — return value not checked (HIGH)
@external
def forward(target: address, data: Bytes[1024]):
    assert msg.sender == self.owner
    raw_call(target, data)

# BUG 9: Timestamp dependence (MEDIUM)
@external
def time_locked_withdraw(amount: uint256):
    assert block.timestamp > 1700000000, "Too early"
    send(msg.sender, amount)

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
