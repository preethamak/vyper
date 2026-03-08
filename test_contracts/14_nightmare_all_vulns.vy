# @version ^0.3.3
# NIGHTMARE CONTRACT: Every possible vulnerability in one file
# Expected: Maximum findings from ALL 12 detectors

owner: public(address)
balances: public(HashMap[address, uint256])
staked: public(HashMap[address, uint256])
rewards: public(HashMap[address, uint256])
total_supply: public(uint256)
implementation: public(address)
treasury: public(address)
fee_rate: public(uint256)
paused: public(bool)
unlock_time: public(uint256)
recipients: public(DynArray[address, 100])
shares: public(HashMap[address, uint256])

@external
def __init__():
    self.owner = msg.sender
    self.total_supply = 1000000
    self.unlock_time = block.timestamp + 86400

# ── Reentrancy (missing @nonreentrant) ──────────────────────────
@external
def withdraw(amount: uint256):
    # VULN: missing @nonreentrant
    # VULN: CEI violation (send before state update)
    # VULN: missing event emission
    assert self.balances[msg.sender] >= amount, "Insufficient"
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount

@external
@payable
def deposit():
    # VULN: missing @nonreentrant
    # VULN: missing event emission
    self.balances[msg.sender] += msg.value
    self.total_supply += msg.value

# ── Unsafe raw_call ─────────────────────────────────────────────
@external
def execute(target: address, data: Bytes[1024]):
    # VULN: raw_call without assert
    raw_call(target, data)

# ── Timestamp dependence ────────────────────────────────────────
@external
def time_locked_withdraw():
    # VULN: timestamp dependence in assert
    assert block.timestamp > self.unlock_time, "Locked"
    send(msg.sender, self.balances[msg.sender])

# ── Unprotected selfdestruct ────────────────────────────────────
@external
def destroy():
    # VULN: selfdestruct without access control
    selfdestruct(msg.sender)

# ── Dangerous delegatecall ──────────────────────────────────────
@external
def delegate(data: Bytes[1024]):
    # VULN: delegatecall without access control
    raw_call(self.implementation, data, is_delegate_call=True)

# ── Unprotected state changes ───────────────────────────────────
@external
def set_owner(new_owner: address):
    # VULN: no msg.sender check
    # VULN: no event emission
    self.owner = new_owner

@external
def set_treasury(new_treasury: address):
    # VULN: no msg.sender check
    # VULN: no event emission
    self.treasury = new_treasury

@external
def set_fee_rate(rate: uint256):
    # VULN: no msg.sender check
    # VULN: no event emission
    self.fee_rate = rate

# ── Send in loop ────────────────────────────────────────────────
@external
@payable
def distribute():
    # VULN: send in loop
    for r: address in self.recipients:
        send(r, msg.value * self.shares[r] / 10000)

# ── Unchecked subtraction ───────────────────────────────────────
@external
def unstake(amount: uint256):
    # VULN: subtraction without balance check
    # VULN: missing event emission
    self.staked[msg.sender] -= amount
    self.balances[msg.sender] += amount

@external
def claim_rewards():
    # VULN: subtraction without check
    reward: uint256 = self.rewards[msg.sender]
    self.total_supply -= reward
    self.balances[msg.sender] += reward

# ── CEI violation ───────────────────────────────────────────────
@external
def withdraw_all():
    # VULN: CEI violation — interaction before effect
    # VULN: missing @nonreentrant
    # VULN: missing event
    bal: uint256 = self.balances[msg.sender]
    send(msg.sender, bal)
    self.balances[msg.sender] = 0
