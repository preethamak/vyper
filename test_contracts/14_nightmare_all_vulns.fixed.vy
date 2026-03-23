# pragma version ^0.4.0
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

event WithdrawAllExecuted:
    caller: indexed(address)


event ClaimRewardsExecuted:
    caller: indexed(address)


event UnstakeExecuted:
    caller: indexed(address)


event SetFeeRateExecuted:
    caller: indexed(address)


event SetTreasuryExecuted:
    caller: indexed(address)


event SetOwnerExecuted:
    caller: indexed(address)


event DepositExecuted:
    caller: indexed(address)


event WithdrawExecuted:
    caller: indexed(address)


@external
def __init__():
    self.owner = msg.sender
    self.total_supply = 1000000
    self.unlock_time = block.timestamp + 86400

# ── Reentrancy (missing @nonreentrant) ──────────────────────────
@nonreentrant
@external
def withdraw(amount: uint256):
    # VULN: missing @nonreentrant
    # VULN: CEI violation (send before state update)
    # VULN: missing event emission
    assert self.balances[msg.sender] >= amount, "Insufficient"
    # FIXME: CEI violation — move state updates ABOVE this external call
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount
    log WithdrawExecuted(msg.sender)

@nonreentrant
@external
@payable
def deposit():
    # VULN: missing @nonreentrant
    # VULN: missing event emission
    self.balances[msg.sender] += msg.value
    self.total_supply += msg.value
    log DepositExecuted(msg.sender)

# ── Unsafe raw_call ─────────────────────────────────────────────
@nonreentrant
@external
def execute(target: address, data: Bytes[1024]):
    # VULN: raw_call without assert
    raw_call(target, data)

# ── Timestamp dependence ────────────────────────────────────────
@nonreentrant
@external
def time_locked_withdraw():
    # VULN: timestamp dependence in assert
    assert block.timestamp > self.unlock_time, "Locked"
    send(msg.sender, self.balances[msg.sender])

# ── Unprotected selfdestruct ────────────────────────────────────
@external
def destroy():
    assert msg.sender == self.owner, "Not owner"
    # VULN: selfdestruct without access control
    selfdestruct(msg.sender)

# ── Dangerous delegatecall ──────────────────────────────────────
@nonreentrant
@external
def delegate(data: Bytes[1024]):
    assert msg.sender == self.owner, "Not owner"
    # VULN: delegatecall without access control
    assert raw_call(self.implementation, data, is_delegate_call=True)

# ── Unprotected state changes ───────────────────────────────────
@nonreentrant
@external
def set_owner(new_owner: address):
    assert msg.sender == self.owner, "Not owner"
    # VULN: no msg.sender check
    # VULN: no event emission
    self.owner = new_owner
    log SetOwnerExecuted(msg.sender)

@nonreentrant
@external
def set_treasury(new_treasury: address):
    # VULN: no msg.sender check
    # VULN: no event emission
    self.treasury = new_treasury
    log SetTreasuryExecuted(msg.sender)

@nonreentrant
@external
def set_fee_rate(rate: uint256):
    # VULN: no msg.sender check
    # VULN: no event emission
    self.fee_rate = rate
    log SetFeeRateExecuted(msg.sender)

# ── Send in loop ────────────────────────────────────────────────
@nonreentrant
@external
@payable
def distribute():
    # VULN: send in loop
    for r: address in self.recipients:
        # FIXME: DoS risk — replace push loop with pull-based withdrawal
        send(r, msg.value * self.shares[r] / 10000)

# ── Unchecked subtraction ───────────────────────────────────────
@nonreentrant
@external
def unstake(amount: uint256):
    # VULN: subtraction without balance check
    # VULN: missing event emission
    assert self.staked[msg.sender] >= amount, "Insufficient balance"
    self.staked[msg.sender] -= amount
    self.balances[msg.sender] += amount
    log UnstakeExecuted(msg.sender)

@nonreentrant
@external
def claim_rewards():
    assert msg.sender == self.owner, "Not owner"
    # VULN: subtraction without check
    reward: uint256 = self.rewards[msg.sender]
    assert self.total_supply >= reward, "Insufficient balance"
    self.total_supply -= reward
    self.balances[msg.sender] += reward
    log ClaimRewardsExecuted(msg.sender)

# ── CEI violation ───────────────────────────────────────────────
@nonreentrant
@external
def withdraw_all():
    # VULN: CEI violation — interaction before effect
    # VULN: missing @nonreentrant
    # VULN: missing event
    bal: uint256 = self.balances[msg.sender]
    # FIXME: CEI violation — move state updates ABOVE this external call
    send(msg.sender, bal)
    self.balances[msg.sender] = 0
    log WithdrawAllExecuted(msg.sender)