# @version ^0.3.7
# ═══════════════════════════════════════════════════════════════════════
# LendingPool — Aave/Compound-style Lending Protocol
# Large contract (~400 lines) for stress-testing vyper-guard
# Expected vulnerabilities: reentrancy, missing events, CEI, unprotected state,
#   timestamp, unchecked subtraction, raw_call, send in loop
# ═══════════════════════════════════════════════════════════════════════

interface ERC20:
    def balanceOf(account: address) -> uint256: view
    def transfer(to: address, amount: uint256) -> bool: nonpayable
    def transferFrom(sender: address, to: address, amount: uint256) -> bool: nonpayable

# ── Constants ────────────────────────────────────────────────────────
MAX_ASSETS: constant(uint256) = 10
PRECISION: constant(uint256) = 10 ** 18
SECONDS_PER_YEAR: constant(uint256) = 365 * 86400
LIQUIDATION_BONUS: constant(uint256) = 105  # 5% bonus
LIQUIDATION_THRESHOLD: constant(uint256) = 80  # 80%
MAX_LTV: constant(uint256) = 75  # 75%
HEALTH_FACTOR_THRESHOLD: constant(uint256) = PRECISION

# ── Structs ──────────────────────────────────────────────────────────
struct AssetConfig:
    token: address
    price_feed: address
    decimals: uint256
    borrow_rate: uint256
    supply_rate: uint256
    is_active: bool
    ltv: uint256
    liquidation_threshold: uint256

struct UserPosition:
    supplied: uint256
    borrowed: uint256
    last_update: uint256
    accrued_interest: uint256

# ── State ────────────────────────────────────────────────────────────
owner: public(address)
guardian: public(address)
paused: public(bool)
asset_count: public(uint256)

assets: public(HashMap[uint256, AssetConfig])
asset_index: public(HashMap[address, uint256])
total_supplied: public(HashMap[address, uint256])
total_borrowed: public(HashMap[address, uint256])
reserves: public(HashMap[address, uint256])
positions: public(HashMap[address, HashMap[address, UserPosition]])

# Flash loan state
flash_loan_fee: public(uint256)
flash_loan_active: public(bool)

# Governance / proposals
proposal_count: public(uint256)
proposal_targets: public(HashMap[uint256, address])
proposal_values: public(HashMap[uint256, uint256])
proposal_executed: public(HashMap[uint256, bool])
proposal_deadline: public(HashMap[uint256, uint256])

# Reward tracking
reward_token: public(address)
reward_per_block: public(uint256)
total_reward_distributed: public(uint256)
user_rewards: public(HashMap[address, uint256])
user_reward_debt: public(HashMap[address, uint256])

@external
def __init__(_reward_token: address):
    self.owner = msg.sender
    self.guardian = msg.sender
    self.paused = False
    self.flash_loan_fee = 9  # 0.09%
    self.reward_token = _reward_token

# ═══════════════════════════════════════════════════════════════════
# ASSET MANAGEMENT — missing events, unprotected state
# ═══════════════════════════════════════════════════════════════════

@external
def add_asset(
    _token: address,
    _price_feed: address,
    _decimals: uint256,
    _borrow_rate: uint256,
    _supply_rate: uint256,
    _ltv: uint256,
    _liq_threshold: uint256,
):
    # VULN: no access control — anyone can add assets
    # VULN: no event emission
    idx: uint256 = self.asset_count
    self.assets[idx] = AssetConfig(
        token=_token,
        price_feed=_price_feed,
        decimals=_decimals,
        borrow_rate=_borrow_rate,
        supply_rate=_supply_rate,
        is_active=True,
        ltv=_ltv,
        liquidation_threshold=_liq_threshold,
    )
    self.asset_index[_token] = idx
    self.asset_count = idx + 1

@external
def disable_asset(_token: address):
    # VULN: no access control, no event
    idx: uint256 = self.asset_index[_token]
    self.assets[idx].is_active = False

@external
def update_rates(_token: address, _borrow_rate: uint256, _supply_rate: uint256):
    # VULN: no access control, no event
    idx: uint256 = self.asset_index[_token]
    self.assets[idx].borrow_rate = _borrow_rate
    self.assets[idx].supply_rate = _supply_rate

# ═══════════════════════════════════════════════════════════════════
# SUPPLY — missing @nonreentrant, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def supply(_token: address, _amount: uint256):
    # VULN: missing @nonreentrant
    # VULN: no event
    assert not self.paused, "Paused"
    idx: uint256 = self.asset_index[_token]
    assert self.assets[idx].is_active, "Inactive"

    self._accrue_interest(_token, msg.sender)

    # VULN: unchecked raw_call
    raw_call(
        _token,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(msg.sender, bytes32),
            convert(self, bytes32),
            convert(_amount, bytes32),
        ),
    )

    self.positions[msg.sender][_token].supplied += _amount
    self.total_supplied[_token] += _amount

@external
def withdraw(_token: address, _amount: uint256):
    # VULN: missing @nonreentrant, no event
    assert not self.paused, "Paused"
    pos: UserPosition = self.positions[msg.sender][_token]
    assert pos.supplied >= _amount, "Insufficient"

    self._accrue_interest(_token, msg.sender)

    # VULN: CEI violation — external call before state update
    raw_call(
        _token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(_amount, bytes32),
        ),
    )

    self.positions[msg.sender][_token].supplied -= _amount
    self.total_supplied[_token] -= _amount

# ═══════════════════════════════════════════════════════════════════
# BORROW — missing @nonreentrant, missing events, timestamp
# ═══════════════════════════════════════════════════════════════════

@external
def borrow(_token: address, _amount: uint256):
    # VULN: missing @nonreentrant, no event
    assert not self.paused, "Paused"

    self._accrue_interest(_token, msg.sender)

    self.positions[msg.sender][_token].borrowed += _amount
    self.total_borrowed[_token] += _amount

    # VULN: CEI violation — external call after partial state update, but before health check
    raw_call(
        _token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(_amount, bytes32),
        ),
    )

@external
def repay(_token: address, _amount: uint256):
    # VULN: missing @nonreentrant, no event
    self._accrue_interest(_token, msg.sender)

    pos: UserPosition = self.positions[msg.sender][_token]
    repay_amount: uint256 = min(_amount, pos.borrowed + pos.accrued_interest)

    # VULN: unchecked raw_call
    raw_call(
        _token,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(msg.sender, bytes32),
            convert(self, bytes32),
            convert(repay_amount, bytes32),
        ),
    )

    # VULN: unchecked subtraction
    self.positions[msg.sender][_token].borrowed -= repay_amount
    self.total_borrowed[_token] -= repay_amount

# ═══════════════════════════════════════════════════════════════════
# LIQUIDATION — timestamp dependence, CEI violation
# ═══════════════════════════════════════════════════════════════════

@external
def liquidate(
    _borrower: address,
    _debt_token: address,
    _collateral_token: address,
    _amount: uint256,
):
    # VULN: missing @nonreentrant, no event, timestamp
    assert not self.paused, "Paused"

    self._accrue_interest(_debt_token, _borrower)
    self._accrue_interest(_collateral_token, _borrower)

    debt_pos: UserPosition = self.positions[_borrower][_debt_token]
    coll_pos: UserPosition = self.positions[_borrower][_collateral_token]

    # Simplified health check
    assert debt_pos.borrowed > 0, "No debt"

    liquidation_amount: uint256 = min(_amount, debt_pos.borrowed / 2)
    bonus_amount: uint256 = liquidation_amount * LIQUIDATION_BONUS / 100

    # VULN: CEI — transfer before state update
    raw_call(
        _debt_token,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(msg.sender, bytes32),
            convert(self, bytes32),
            convert(liquidation_amount, bytes32),
        ),
    )
    raw_call(
        _collateral_token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(bonus_amount, bytes32),
        ),
    )

    # State updates after transfers
    # VULN: unchecked subtraction
    self.positions[_borrower][_debt_token].borrowed -= liquidation_amount
    self.positions[_borrower][_collateral_token].supplied -= bonus_amount
    self.total_borrowed[_debt_token] -= liquidation_amount
    self.total_supplied[_collateral_token] -= bonus_amount

# ═══════════════════════════════════════════════════════════════════
# INTEREST ACCRUAL — timestamp dependence
# ═══════════════════════════════════════════════════════════════════

@internal
def _accrue_interest(_token: address, _user: address):
    pos: UserPosition = self.positions[_user][_token]
    if pos.last_update == 0:
        self.positions[_user][_token].last_update = block.timestamp
        return

    # VULN: timestamp dependence
    time_elapsed: uint256 = block.timestamp - pos.last_update
    idx: uint256 = self.asset_index[_token]
    rate: uint256 = self.assets[idx].borrow_rate

    interest: uint256 = pos.borrowed * rate * time_elapsed / (SECONDS_PER_YEAR * PRECISION)
    self.positions[_user][_token].accrued_interest += interest
    self.positions[_user][_token].last_update = block.timestamp

    self.reserves[_token] += interest / 10

# ═══════════════════════════════════════════════════════════════════
# FLASH LOANS — unchecked raw_call, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def flash_loan(_token: address, _amount: uint256, _receiver: address, _data: Bytes[1024]):
    # VULN: missing @nonreentrant, no event
    assert not self.flash_loan_active, "Reentrancy"
    self.flash_loan_active = True

    fee: uint256 = _amount * self.flash_loan_fee / 10000

    # VULN: unchecked raw_call
    raw_call(
        _token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(_receiver, bytes32),
            convert(_amount, bytes32),
        ),
    )

    # callback
    raw_call(
        _receiver,
        concat(
            method_id("executeOperation(address,uint256,uint256,bytes)"),
            convert(_token, bytes32),
            convert(_amount, bytes32),
            convert(fee, bytes32),
            _data,
        ),
    )

    self.reserves[_token] += fee
    self.flash_loan_active = False

# ═══════════════════════════════════════════════════════════════════
# REWARDS — send in loop, unchecked subtraction
# ═══════════════════════════════════════════════════════════════════

@external
def distribute_rewards(users: DynArray[address, 50], amounts: DynArray[uint256, 50]):
    # VULN: no access control, send in loop
    for i: uint256 in range(50):
        if i >= len(users):
            break
        send(users[i], amounts[i])
        self.user_rewards[users[i]] += amounts[i]
        self.total_reward_distributed += amounts[i]

@external
def claim_reward():
    # VULN: CEI violation, no event
    reward: uint256 = self.user_rewards[msg.sender]
    assert reward > 0, "Nothing"
    send(msg.sender, reward)
    self.user_rewards[msg.sender] = 0

# ═══════════════════════════════════════════════════════════════════
# GOVERNANCE — unprotected state, timestamp, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def create_proposal(_target: address, _value: uint256):
    # VULN: no access control, no event
    pid: uint256 = self.proposal_count
    self.proposal_targets[pid] = _target
    self.proposal_values[pid] = _value
    # VULN: timestamp dependence
    self.proposal_deadline[pid] = block.timestamp + 7 * 86400
    self.proposal_count = pid + 1

@external
def execute_proposal(pid: uint256):
    # VULN: no access control, timestamp, no event, unchecked raw_call
    assert not self.proposal_executed[pid], "Executed"
    assert block.timestamp >= self.proposal_deadline[pid], "Too early"

    target: address = self.proposal_targets[pid]
    value: uint256 = self.proposal_values[pid]

    raw_call(target, b"", value=value)
    self.proposal_executed[pid] = True

# ═══════════════════════════════════════════════════════════════════
# ADMIN — unprotected, selfdestruct, delegatecall
# ═══════════════════════════════════════════════════════════════════

@external
def set_guardian(_guardian: address):
    # VULN: no access control, no event
    self.guardian = _guardian

@external
def set_flash_loan_fee(_fee: uint256):
    # VULN: no access control, no event
    self.flash_loan_fee = _fee

@external
def pause():
    # VULN: no access control
    self.paused = True

@external
def unpause():
    # VULN: no access control
    self.paused = False

@external
def upgrade_impl(impl: address, data: Bytes[1024]):
    # VULN: no access control, dangerous delegatecall
    raw_call(impl, data, is_delegate_call=True)

@external
def emergency_withdraw(_token: address, _amount: uint256, _to: address):
    # VULN: no access control, unchecked raw_call, no event
    raw_call(
        _token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(_to, bytes32),
            convert(_amount, bytes32),
        ),
    )

@external
def nuke():
    # VULN: selfdestruct without access control
    selfdestruct(self.owner)
