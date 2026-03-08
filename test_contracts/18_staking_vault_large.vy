# @version ^0.3.7
# ═══════════════════════════════════════════════════════════════════════
# StakingVault — Multi-asset staking with epochs, rewards, slashing
# Large contract (~400 lines) for stress-testing vyper-guard
# Expected vulnerabilities: reentrancy, missing events, timestamp,
#   CEI, unchecked subtraction, send in loop, unprotected state, raw_call
# ═══════════════════════════════════════════════════════════════════════

interface ERC20:
    def balanceOf(account: address) -> uint256: view
    def transfer(to: address, amount: uint256) -> bool: nonpayable
    def transferFrom(sender: address, to: address, amount: uint256) -> bool: nonpayable

# ── Constants ────────────────────────────────────────────────────────
MAX_VALIDATORS: constant(uint256) = 100
MAX_DELEGATORS: constant(uint256) = 500
EPOCH_DURATION: constant(uint256) = 7 * 86400  # 1 week
MIN_STAKE: constant(uint256) = 32 * 10 ** 18  # 32 tokens
SLASH_RATE: constant(uint256) = 10  # 10%
UNBONDING_PERIOD: constant(uint256) = 21 * 86400  # 21 days
PRECISION: constant(uint256) = 10 ** 18

# ── State ────────────────────────────────────────────────────────────
owner: public(address)
operator: public(address)
staking_token: public(address)
reward_token: public(address)

# Global staking state
total_staked: public(uint256)
total_rewards: public(uint256)
reward_per_token_stored: public(uint256)
last_update_time: public(uint256)
reward_rate: public(uint256)
period_finish: public(uint256)

# Epoch tracking
current_epoch: public(uint256)
epoch_start_time: public(HashMap[uint256, uint256])
epoch_reward: public(HashMap[uint256, uint256])
epoch_total_stake: public(HashMap[uint256, uint256])

# Per-user staking
user_staked: public(HashMap[address, uint256])
user_reward_per_token_paid: public(HashMap[address, uint256])
user_rewards: public(HashMap[address, uint256])
user_last_stake_time: public(HashMap[address, uint256])
user_unbonding: public(HashMap[address, uint256])
user_unbonding_end: public(HashMap[address, uint256])

# Validator set
validators: public(DynArray[address, MAX_VALIDATORS])
validator_active: public(HashMap[address, bool])
validator_stake: public(HashMap[address, uint256])
validator_commission: public(HashMap[address, uint256])
validator_jailed: public(HashMap[address, bool])
validator_jail_end: public(HashMap[address, uint256])
validator_slash_count: public(HashMap[address, uint256])

# Delegation
delegator_validator: public(HashMap[address, address])
delegator_amount: public(HashMap[address, uint256])

# Withdrawal queue
pending_withdrawals: public(DynArray[address, 200])
pending_amounts: public(HashMap[address, uint256])

# Slashing proposals
slash_proposal_count: public(uint256)
slash_target: public(HashMap[uint256, address])
slash_amount: public(HashMap[uint256, uint256])
slash_votes: public(HashMap[uint256, uint256])
slash_executed: public(HashMap[uint256, bool])

@external
def __init__(_staking_token: address, _reward_token: address):
    self.owner = msg.sender
    self.operator = msg.sender
    self.staking_token = _staking_token
    self.reward_token = _reward_token
    self.current_epoch = 1
    self.epoch_start_time[1] = block.timestamp

# ═══════════════════════════════════════════════════════════════════
# STAKING — missing @nonreentrant, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def stake(_amount: uint256):
    # VULN: missing @nonreentrant
    # VULN: no event emission
    assert _amount >= MIN_STAKE, "Below minimum"
    self._update_reward(msg.sender)

    # VULN: unchecked raw_call
    raw_call(
        self.staking_token,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(msg.sender, bytes32),
            convert(self, bytes32),
            convert(_amount, bytes32),
        ),
    )

    self.user_staked[msg.sender] += _amount
    self.total_staked += _amount
    # VULN: timestamp dependence
    self.user_last_stake_time[msg.sender] = block.timestamp

@external
def request_unstake(_amount: uint256):
    # VULN: no @nonreentrant, no event
    assert self.user_staked[msg.sender] >= _amount, "Insufficient"
    self._update_reward(msg.sender)

    # VULN: unchecked subtraction
    self.user_staked[msg.sender] -= _amount
    self.total_staked -= _amount
    self.user_unbonding[msg.sender] += _amount
    # VULN: timestamp dependence
    self.user_unbonding_end[msg.sender] = block.timestamp + UNBONDING_PERIOD

@external
def complete_unstake():
    # VULN: no @nonreentrant, timestamp, CEI violation, no event
    # VULN: timestamp dependence
    assert block.timestamp >= self.user_unbonding_end[msg.sender], "Unbonding"
    amount: uint256 = self.user_unbonding[msg.sender]
    assert amount > 0, "Nothing"

    # VULN: CEI — transfer before state update
    raw_call(
        self.staking_token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(amount, bytes32),
        ),
    )
    self.user_unbonding[msg.sender] = 0

# ═══════════════════════════════════════════════════════════════════
# REWARDS — timestamp, missing events, CEI
# ═══════════════════════════════════════════════════════════════════

@internal
def _update_reward(_account: address):
    # VULN: timestamp dependence throughout
    self.reward_per_token_stored = self._reward_per_token()
    self.last_update_time = self._last_time_applicable()
    if _account != empty(address):
        self.user_rewards[_account] = self._earned(_account)
        self.user_reward_per_token_paid[_account] = self.reward_per_token_stored

@internal
@view
def _reward_per_token() -> uint256:
    if self.total_staked == 0:
        return self.reward_per_token_stored
    # VULN: timestamp
    return self.reward_per_token_stored + (
        (self._last_time_applicable() - self.last_update_time) * self.reward_rate * PRECISION / self.total_staked
    )

@internal
@view
def _last_time_applicable() -> uint256:
    # VULN: timestamp
    if block.timestamp < self.period_finish:
        return block.timestamp
    return self.period_finish

@internal
@view
def _earned(_account: address) -> uint256:
    return (
        self.user_staked[_account]
        * (self._reward_per_token() - self.user_reward_per_token_paid[_account])
        / PRECISION
        + self.user_rewards[_account]
    )

@external
def claim_rewards():
    # VULN: no @nonreentrant, no event, CEI
    self._update_reward(msg.sender)
    reward: uint256 = self.user_rewards[msg.sender]
    assert reward > 0, "Nothing"

    # VULN: CEI — transfer before state update
    raw_call(
        self.reward_token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(reward, bytes32),
        ),
    )
    self.user_rewards[msg.sender] = 0
    self.total_rewards -= reward

# ═══════════════════════════════════════════════════════════════════
# EPOCH MANAGEMENT — timestamp, unprotected
# ═══════════════════════════════════════════════════════════════════

@external
def advance_epoch():
    # VULN: no access control, no event, timestamp
    assert block.timestamp >= self.epoch_start_time[self.current_epoch] + EPOCH_DURATION, "Too early"

    self.epoch_total_stake[self.current_epoch] = self.total_staked
    self.current_epoch += 1
    self.epoch_start_time[self.current_epoch] = block.timestamp

@external
def set_epoch_reward(_epoch: uint256, _reward: uint256):
    # VULN: no access control, no event
    self.epoch_reward[_epoch] = _reward

@external
def notify_reward_amount(_reward: uint256):
    # VULN: no access control, timestamp, no event
    self._update_reward(empty(address))

    if block.timestamp >= self.period_finish:
        self.reward_rate = _reward / EPOCH_DURATION
    else:
        remaining: uint256 = self.period_finish - block.timestamp
        leftover: uint256 = remaining * self.reward_rate
        self.reward_rate = (_reward + leftover) / EPOCH_DURATION

    self.last_update_time = block.timestamp
    self.period_finish = block.timestamp + EPOCH_DURATION
    self.total_rewards += _reward

# ═══════════════════════════════════════════════════════════════════
# VALIDATOR MANAGEMENT — unprotected state, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def register_validator(_commission: uint256):
    # VULN: no event
    assert not self.validator_active[msg.sender], "Already active"
    assert self.user_staked[msg.sender] >= MIN_STAKE, "Below minimum"
    self.validators.append(msg.sender)
    self.validator_active[msg.sender] = True
    self.validator_commission[msg.sender] = _commission

@external
def update_commission(_commission: uint256):
    # VULN: no event
    assert self.validator_active[msg.sender], "Not active"
    self.validator_commission[msg.sender] = _commission

@external
def delegate_to_validator(_validator: address, _amount: uint256):
    # VULN: no @nonreentrant, no event, unchecked subtraction
    assert self.validator_active[_validator], "Inactive"
    assert not self.validator_jailed[_validator], "Jailed"

    self.user_staked[msg.sender] -= _amount
    self.delegator_validator[msg.sender] = _validator
    self.delegator_amount[msg.sender] = _amount
    self.validator_stake[_validator] += _amount

# ═══════════════════════════════════════════════════════════════════
# SLASHING — send in loop, unprotected state, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def propose_slash(_validator: address, _amount: uint256):
    # VULN: no access control, no event
    sid: uint256 = self.slash_proposal_count
    self.slash_target[sid] = _validator
    self.slash_amount[sid] = _amount
    self.slash_proposal_count = sid + 1

@external
def vote_slash(sid: uint256):
    # VULN: no access control, no event
    self.slash_votes[sid] += self.user_staked[msg.sender]

@external
def execute_slash(sid: uint256):
    # VULN: no access control, no event, unchecked subtraction
    assert not self.slash_executed[sid], "Done"
    assert self.slash_votes[sid] >= self.total_staked / 2, "No quorum"

    target: address = self.slash_target[sid]
    amount: uint256 = self.slash_amount[sid]

    self.validator_stake[target] -= amount
    self.total_staked -= amount
    self.validator_jailed[target] = True
    # VULN: timestamp
    self.validator_jail_end[target] = block.timestamp + 30 * 86400
    self.validator_slash_count[target] += 1
    self.slash_executed[sid] = True

@external
def unjail():
    # VULN: timestamp, no event
    assert self.validator_jailed[msg.sender], "Not jailed"
    assert block.timestamp >= self.validator_jail_end[msg.sender], "Too early"
    self.validator_jailed[msg.sender] = False

# ═══════════════════════════════════════════════════════════════════
# BATCH OPERATIONS — send in loop
# ═══════════════════════════════════════════════════════════════════

@external
def batch_distribute_rewards(users: DynArray[address, 50]):
    # VULN: no access control, send in loop, no event
    for u: address in users:
        reward: uint256 = self.user_rewards[u]
        if reward > 0:
            send(u, reward)
            self.user_rewards[u] = 0

@external
def process_withdrawals():
    # VULN: no access control, send in loop, no event
    for addr: address in self.pending_withdrawals:
        amt: uint256 = self.pending_amounts[addr]
        if amt > 0:
            send(addr, amt)
            self.pending_amounts[addr] = 0

# ═══════════════════════════════════════════════════════════════════
# ADMIN — unprotected state, delegatecall, selfdestruct
# ═══════════════════════════════════════════════════════════════════

@external
def set_operator(_op: address):
    # VULN: no access control, no event
    self.operator = _op

@external
def set_reward_token(_token: address):
    # VULN: no access control, no event
    self.reward_token = _token

@external
def upgrade(impl: address, data: Bytes[1024]):
    # VULN: no access control, delegatecall
    raw_call(impl, data, is_delegate_call=True)

@external
def emergency_drain(_to: address):
    # VULN: no access control, selfdestruct
    selfdestruct(_to)
