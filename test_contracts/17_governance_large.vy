# @version ^0.3.7
# ═══════════════════════════════════════════════════════════════════════
# GovernorDAO — On-chain governance with voting, proposals, timelock
# Large contract (~350 lines) for stress-testing vyper-guard
# Expected vulnerabilities: timestamp, unprotected state, missing events,
#   delegatecall, raw_call, reentrancy, CEI, send in loop
# ═══════════════════════════════════════════════════════════════════════

interface ERC20:
    def balanceOf(account: address) -> uint256: view
    def transfer(to: address, amount: uint256) -> bool: nonpayable
    def transferFrom(sender: address, to: address, amount: uint256) -> bool: nonpayable

# ── Constants ────────────────────────────────────────────────────────
MAX_ACTIONS: constant(uint256) = 10
MAX_VOTERS: constant(uint256) = 200
QUORUM_VOTES: constant(uint256) = 400000 * 10 ** 18
PROPOSAL_THRESHOLD: constant(uint256) = 100000 * 10 ** 18
VOTING_DELAY: constant(uint256) = 1  # 1 block
VOTING_PERIOD: constant(uint256) = 17280  # ~3 days
TIMELOCK_DELAY: constant(uint256) = 2 * 86400  # 2 days
GRACE_PERIOD: constant(uint256) = 14 * 86400

# ── Enums / Constants for State ──────────────────────────────────────
STATE_PENDING: constant(uint256) = 0
STATE_ACTIVE: constant(uint256) = 1
STATE_CANCELED: constant(uint256) = 2
STATE_DEFEATED: constant(uint256) = 3
STATE_SUCCEEDED: constant(uint256) = 4
STATE_QUEUED: constant(uint256) = 5
STATE_EXPIRED: constant(uint256) = 6
STATE_EXECUTED: constant(uint256) = 7

# ── State ────────────────────────────────────────────────────────────
admin: public(address)
pending_admin: public(address)
governance_token: public(address)
guardian: public(address)
implementation: public(address)

proposal_count: public(uint256)
# Proposal data stored in HashMaps keyed by proposal_id
prop_proposer: public(HashMap[uint256, address])
prop_eta: public(HashMap[uint256, uint256])
prop_start_block: public(HashMap[uint256, uint256])
prop_end_block: public(HashMap[uint256, uint256])
prop_for_votes: public(HashMap[uint256, uint256])
prop_against_votes: public(HashMap[uint256, uint256])
prop_abstain_votes: public(HashMap[uint256, uint256])
prop_canceled: public(HashMap[uint256, bool])
prop_executed: public(HashMap[uint256, bool])
prop_state: public(HashMap[uint256, uint256])
prop_description: public(HashMap[uint256, String[1024]])

# Action targets per proposal
prop_targets: public(HashMap[uint256, HashMap[uint256, address]])
prop_values: public(HashMap[uint256, HashMap[uint256, uint256]])
prop_action_count: public(HashMap[uint256, uint256])

# Voting receipts: proposal_id -> voter -> vote_value
votes_cast: public(HashMap[uint256, HashMap[address, uint256]])
has_voted: public(HashMap[uint256, HashMap[address, bool]])

# Delegation
delegates: public(HashMap[address, address])
voting_power: public(HashMap[address, uint256])
nonces: public(HashMap[address, uint256])

# Treasury
treasury_balance: public(uint256)
grant_recipients: public(DynArray[address, 100])
grant_amounts: public(HashMap[address, uint256])

# Timelock queue
queued_txn: public(HashMap[bytes32, bool])

@external
def __init__(_token: address, _guardian: address):
    self.admin = msg.sender
    self.governance_token = _token
    self.guardian = _guardian

# ═══════════════════════════════════════════════════════════════════
# DELEGATION — missing events
# ═══════════════════════════════════════════════════════════════════

@external
def delegate(_delegatee: address):
    # VULN: no event emission for delegation change
    old_delegate: address = self.delegates[msg.sender]
    self.delegates[msg.sender] = _delegatee
    # VULN: unchecked subtraction
    self.voting_power[old_delegate] -= self.voting_power[msg.sender]
    self.voting_power[_delegatee] += self.voting_power[msg.sender]

@external
def deposit_voting_tokens(_amount: uint256):
    # VULN: missing @nonreentrant, no event
    raw_call(
        self.governance_token,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(msg.sender, bytes32),
            convert(self, bytes32),
            convert(_amount, bytes32),
        ),
    )
    self.voting_power[msg.sender] += _amount
    delegatee: address = self.delegates[msg.sender]
    if delegatee != empty(address):
        self.voting_power[delegatee] += _amount

# ═══════════════════════════════════════════════════════════════════
# PROPOSALS — timestamp, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def propose(
    _targets: DynArray[address, 10],
    _values: DynArray[uint256, 10],
    _description: String[1024],
) -> uint256:
    # VULN: no event
    assert len(_targets) > 0, "No actions"
    assert len(_targets) == len(_values), "Length mismatch"

    pid: uint256 = self.proposal_count + 1
    self.proposal_count = pid

    self.prop_proposer[pid] = msg.sender
    self.prop_description[pid] = _description
    self.prop_start_block[pid] = block.number + VOTING_DELAY
    self.prop_end_block[pid] = block.number + VOTING_DELAY + VOTING_PERIOD
    self.prop_state[pid] = STATE_PENDING

    for i: uint256 in range(MAX_ACTIONS):
        if i >= len(_targets):
            break
        self.prop_targets[pid][i] = _targets[i]
        self.prop_values[pid][i] = _values[i]
    self.prop_action_count[pid] = len(_targets)

    return pid

@external
def cast_vote(pid: uint256, support: uint256):
    # VULN: no event, timestamp dependence via block check
    assert self.prop_state[pid] == STATE_ACTIVE or block.number >= self.prop_start_block[pid], "Not active"
    assert not self.has_voted[pid][msg.sender], "Already voted"

    power: uint256 = self.voting_power[msg.sender]
    assert power > 0, "No power"

    self.has_voted[pid][msg.sender] = True
    self.votes_cast[pid][msg.sender] = support

    if support == 0:
        self.prop_against_votes[pid] += power
    elif support == 1:
        self.prop_for_votes[pid] += power
    else:
        self.prop_abstain_votes[pid] += power

# ═══════════════════════════════════════════════════════════════════
# QUEUE & EXECUTE — timestamp, raw_call, CEI, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def queue(pid: uint256):
    # VULN: no access control, timestamp, no event
    assert self.prop_for_votes[pid] > self.prop_against_votes[pid], "Defeated"
    assert self.prop_for_votes[pid] >= QUORUM_VOTES, "No quorum"

    # VULN: timestamp dependence
    eta: uint256 = block.timestamp + TIMELOCK_DELAY
    self.prop_eta[pid] = eta
    self.prop_state[pid] = STATE_QUEUED

    for i: uint256 in range(MAX_ACTIONS):
        if i >= self.prop_action_count[pid]:
            break
        txn_hash: bytes32 = keccak256(
            concat(
                convert(self.prop_targets[pid][i], bytes32),
                convert(self.prop_values[pid][i], bytes32),
                convert(eta, bytes32),
            )
        )
        self.queued_txn[txn_hash] = True

@external
def execute(pid: uint256):
    # VULN: timestamp, no event, unchecked raw_call, CEI
    assert self.prop_state[pid] == STATE_QUEUED, "Not queued"
    # VULN: timestamp dependence
    assert block.timestamp >= self.prop_eta[pid], "Locked"
    assert block.timestamp <= self.prop_eta[pid] + GRACE_PERIOD, "Expired"

    self.prop_state[pid] = STATE_EXECUTED
    self.prop_executed[pid] = True

    for i: uint256 in range(MAX_ACTIONS):
        if i >= self.prop_action_count[pid]:
            break
        target: address = self.prop_targets[pid][i]
        value: uint256 = self.prop_values[pid][i]
        # VULN: unchecked raw_call
        raw_call(target, b"", value=value)

@external
def cancel(pid: uint256):
    # VULN: no access control — anyone can cancel
    # VULN: no event
    self.prop_state[pid] = STATE_CANCELED
    self.prop_canceled[pid] = True

# ═══════════════════════════════════════════════════════════════════
# TREASURY — send in loop, missing events, unprotected
# ═══════════════════════════════════════════════════════════════════

@external
@payable
def fund_treasury():
    # VULN: no event
    self.treasury_balance += msg.value

@external
def add_grant(_recipient: address, _amount: uint256):
    # VULN: no access control, no event
    self.grant_recipients.append(_recipient)
    self.grant_amounts[_recipient] = _amount

@external
def distribute_grants():
    # VULN: no access control, send in loop, no event
    for r: address in self.grant_recipients:
        amt: uint256 = self.grant_amounts[r]
        if amt > 0:
            # VULN: send in loop
            send(r, amt)
            # VULN: unchecked subtraction
            self.treasury_balance -= amt
            self.grant_amounts[r] = 0

@external
def emergency_treasury_withdraw(_to: address, _amount: uint256):
    # VULN: no access control, CEI violation, no event
    send(_to, _amount)
    self.treasury_balance -= _amount

# ═══════════════════════════════════════════════════════════════════
# ADMIN — unprotected state, delegatecall, selfdestruct
# ═══════════════════════════════════════════════════════════════════

@external
def set_admin(_new: address):
    # VULN: no access control, no event
    self.pending_admin = _new

@external
def accept_admin():
    # VULN: no access control
    self.admin = self.pending_admin

@external
def set_guardian(_new: address):
    # VULN: no access control, no event
    self.guardian = _new

@external
def set_implementation(_impl: address):
    # VULN: no access control, no event
    self.implementation = _impl

@external
def upgrade(data: Bytes[1024]):
    # VULN: no access control, dangerous delegatecall
    raw_call(self.implementation, data, is_delegate_call=True)

@external
def abdicate():
    # VULN: no access control
    self.guardian = empty(address)

@external
def nuke():
    # VULN: selfdestruct without access control
    selfdestruct(self.admin)
