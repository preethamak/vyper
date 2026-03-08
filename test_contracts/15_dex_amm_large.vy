# @version ^0.3.7
# ═══════════════════════════════════════════════════════════════════════
# StableSwap DEX / AMM  — Curve-style constant-sum/product hybrid
# This is a LARGE contract (~350 lines) for stress-testing vyper-guard
# Expected vulnerabilities: reentrancy, missing events, timestamp, CEI, raw_call
# ═══════════════════════════════════════════════════════════════════════

# Interfaces
interface ERC20:
    def balanceOf(account: address) -> uint256: view
    def transfer(to: address, amount: uint256) -> bool: nonpayable
    def transferFrom(sender: address, to: address, amount: uint256) -> bool: nonpayable
    def decimals() -> uint8: view

# ── Constants ────────────────────────────────────────────────────────
N_COINS: constant(uint256) = 3
FEE_DENOMINATOR: constant(uint256) = 10 ** 10
PRECISION: constant(uint256) = 10 ** 18
MAX_ADMIN_FEE: constant(uint256) = 10 ** 10
MAX_FEE: constant(uint256) = 5 * 10 ** 9
MAX_A: constant(uint256) = 10 ** 6
A_PRECISION: constant(uint256) = 100

# ── State Variables ──────────────────────────────────────────────────
owner: public(address)
future_owner: public(address)
coins: public(address[N_COINS])
balances_pool: public(uint256[N_COINS])
fee: public(uint256)
admin_fee: public(uint256)
lp_token: public(address)
total_lp: public(uint256)
lp_balances: public(HashMap[address, uint256])

initial_A: public(uint256)
future_A: public(uint256)
initial_A_time: public(uint256)
future_A_time: public(uint256)

admin_actions_deadline: public(uint256)
transfer_ownership_deadline: public(uint256)
future_fee: public(uint256)
future_admin_fee: public(uint256)

is_killed: public(bool)
kill_deadline: public(uint256)
KILL_DEADLINE_DT: constant(uint256) = 2 * 30 * 86400

volume_24h: public(uint256)
last_trade_time: public(uint256)
trade_count: public(uint256)
trader_volume: public(HashMap[address, uint256])
rewards_pool: public(uint256)
claimed_rewards: public(HashMap[address, uint256])

# ── Constructor ──────────────────────────────────────────────────────
@external
def __init__(
    _coins: address[N_COINS],
    _A: uint256,
    _fee: uint256,
    _admin_fee: uint256,
):
    self.owner = msg.sender
    for i: uint256 in range(N_COINS):
        assert _coins[i] != empty(address)
        self.coins[i] = _coins[i]

    self.initial_A = _A * A_PRECISION
    self.future_A = _A * A_PRECISION
    self.fee = _fee
    self.admin_fee = _admin_fee
    self.kill_deadline = block.timestamp + KILL_DEADLINE_DT
    self.is_killed = False

# ═══════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════

@internal
@view
def _A() -> uint256:
    # VULN: timestamp dependence in ramp logic
    t1: uint256 = self.future_A_time
    A1: uint256 = self.future_A
    if block.timestamp < t1:
        A0: uint256 = self.initial_A
        t0: uint256 = self.initial_A_time
        if A1 > A0:
            return A0 + (A1 - A0) * (block.timestamp - t0) / (t1 - t0)
        else:
            return A0 - (A0 - A1) * (block.timestamp - t0) / (t1 - t0)
    return A1

@internal
@view
def _xp() -> uint256[N_COINS]:
    result: uint256[N_COINS] = empty(uint256[N_COINS])
    for i: uint256 in range(N_COINS):
        result[i] = self.balances_pool[i] * PRECISION
    return result

@internal
@view
def _get_D(xp: uint256[N_COINS], amp: uint256) -> uint256:
    S: uint256 = 0
    for x: uint256 in xp:
        S += x
    if S == 0:
        return 0

    Dprev: uint256 = 0
    D: uint256 = S
    Ann: uint256 = amp * N_COINS
    for _i: uint256 in range(255):
        D_P: uint256 = D
        for x: uint256 in xp:
            D_P = D_P * D / (x * N_COINS)
        Dprev = D
        D = (Ann * S / A_PRECISION + D_P * N_COINS) * D / (
            (Ann - A_PRECISION) * D / A_PRECISION + (N_COINS + 1) * D_P
        )
        if D > Dprev:
            if D - Dprev <= 1:
                return D
        else:
            if Dprev - D <= 1:
                return D
    return D

@internal
@view
def _get_y(i: uint256, j: uint256, x: uint256, xp: uint256[N_COINS]) -> uint256:
    amp: uint256 = self._A()
    D: uint256 = self._get_D(xp, amp)
    Ann: uint256 = amp * N_COINS
    c: uint256 = D
    S_: uint256 = 0
    _x: uint256 = 0

    for _i: uint256 in range(N_COINS):
        if _i == i:
            _x = x
        elif _i != j:
            _x = xp[_i]
        else:
            continue
        S_ += _x
        c = c * D / (_x * N_COINS)

    c = c * D * A_PRECISION / (Ann * N_COINS)
    b: uint256 = S_ + D * A_PRECISION / Ann
    y_prev: uint256 = 0
    y: uint256 = D
    for _i: uint256 in range(255):
        y_prev = y
        y = (y * y + c) / (2 * y + b - D)
        if y > y_prev:
            if y - y_prev <= 1:
                return y
        else:
            if y_prev - y <= 1:
                return y
    return y

# ═══════════════════════════════════════════════════════════════════
# PUBLIC — EXCHANGE (VULN: missing @nonreentrant, missing events)
# ═══════════════════════════════════════════════════════════════════

@external
def exchange(i: uint256, j: uint256, dx: uint256, min_dy: uint256) -> uint256:
    # VULN: missing @nonreentrant
    # VULN: no event emission for trade
    assert not self.is_killed, "Pool killed"
    assert i != j, "Same coin"
    assert i < N_COINS and j < N_COINS, "Bad index"

    xp: uint256[N_COINS] = self._xp()
    x: uint256 = xp[i] + dx * PRECISION
    y: uint256 = self._get_y(i, j, x, xp)
    dy: uint256 = (xp[j] - y - 1) / PRECISION
    dy_fee: uint256 = dy * self.fee / FEE_DENOMINATOR
    dy_admin_fee: uint256 = dy_fee * self.admin_fee / FEE_DENOMINATOR
    dy = dy - dy_fee

    assert dy >= min_dy, "Slippage"

    self.balances_pool[i] += dx
    self.balances_pool[j] -= (dy + dy_admin_fee)

    # VULN: unchecked raw_call for token transfer
    raw_call(
        self.coins[i],
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(msg.sender, bytes32),
            convert(self, bytes32),
            convert(dx, bytes32),
        ),
    )
    raw_call(
        self.coins[j],
        concat(
            method_id("transfer(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(dy, bytes32),
        ),
    )

    self.volume_24h += dx
    self.trade_count += 1
    self.trader_volume[msg.sender] += dx
    self.last_trade_time = block.timestamp

    return dy

# ═══════════════════════════════════════════════════════════════════
# ADD / REMOVE LIQUIDITY
# ═══════════════════════════════════════════════════════════════════

@external
def add_liquidity(amounts: uint256[N_COINS], min_mint: uint256) -> uint256:
    # VULN: missing @nonreentrant
    # VULN: missing event
    assert not self.is_killed, "Pool killed"
    amp: uint256 = self._A()
    old_balances: uint256[N_COINS] = self.balances_pool
    D0: uint256 = self._get_D(self._xp(), amp)

    new_balances: uint256[N_COINS] = old_balances
    for i: uint256 in range(N_COINS):
        if self.total_lp == 0:
            assert amounts[i] > 0
        new_balances[i] = old_balances[i] + amounts[i]

    new_xp: uint256[N_COINS] = empty(uint256[N_COINS])
    for i: uint256 in range(N_COINS):
        new_xp[i] = new_balances[i] * PRECISION
    D1: uint256 = self._get_D(new_xp, amp)
    assert D1 > D0, "D decreased"

    mint_amount: uint256 = 0
    if self.total_lp == 0:
        mint_amount = D1
    else:
        mint_amount = self.total_lp * (D1 - D0) / D0

    assert mint_amount >= min_mint, "Slippage"

    for i: uint256 in range(N_COINS):
        if amounts[i] > 0:
            # VULN: unchecked raw_call
            raw_call(
                self.coins[i],
                concat(
                    method_id("transferFrom(address,address,uint256)"),
                    convert(msg.sender, bytes32),
                    convert(self, bytes32),
                    convert(amounts[i], bytes32),
                ),
            )
        self.balances_pool[i] = new_balances[i]

    self.total_lp += mint_amount
    self.lp_balances[msg.sender] += mint_amount

    return mint_amount

@external
def remove_liquidity(amount: uint256, min_amounts: uint256[N_COINS]):
    # VULN: missing @nonreentrant, missing events
    assert amount <= self.lp_balances[msg.sender], "Insufficient LP"

    for i: uint256 in range(N_COINS):
        value: uint256 = self.balances_pool[i] * amount / self.total_lp
        assert value >= min_amounts[i], "Slippage"
        self.balances_pool[i] -= value
        # VULN: CEI — external call before LP state update
        raw_call(
            self.coins[i],
            concat(
                method_id("transfer(address,uint256)"),
                convert(msg.sender, bytes32),
                convert(value, bytes32),
            ),
        )

    # state update after external calls
    self.lp_balances[msg.sender] -= amount
    self.total_lp -= amount

# ═══════════════════════════════════════════════════════════════════
# REWARDS — send in loop, missing events, unchecked subtraction
# ═══════════════════════════════════════════════════════════════════

@external
def claim_trading_reward():
    # VULN: missing event, CEI violation
    vol: uint256 = self.trader_volume[msg.sender]
    reward: uint256 = vol * self.fee / FEE_DENOMINATOR
    # VULN: unchecked subtraction
    self.rewards_pool -= reward
    send(msg.sender, reward)
    self.trader_volume[msg.sender] = 0

# ═══════════════════════════════════════════════════════════════════
# ADMIN — unprotected state, timestamp, selfdestruct
# ═══════════════════════════════════════════════════════════════════

@external
def ramp_A(_future_A: uint256, _future_time: uint256):
    # VULN: timestamp dependence
    assert block.timestamp >= self.initial_A_time + 86400, "Too soon"
    assert _future_time >= block.timestamp + 86400, "Ramp too fast"
    # VULN: missing event
    self.initial_A = self._A()
    self.future_A = _future_A * A_PRECISION
    self.initial_A_time = block.timestamp
    self.future_A_time = _future_time

@external
def commit_new_fee(_new_fee: uint256, _new_admin_fee: uint256):
    # VULN: no access control, no event
    assert self.admin_actions_deadline == 0, "Active action"
    self.admin_actions_deadline = block.timestamp + 3 * 86400
    self.future_fee = _new_fee
    self.future_admin_fee = _new_admin_fee

@external
def apply_new_fee():
    # VULN: timestamp dependence in assert, no access control, no event
    assert block.timestamp >= self.admin_actions_deadline, "Too early"
    assert self.admin_actions_deadline != 0, "No pending"
    self.fee = self.future_fee
    self.admin_fee = self.future_admin_fee
    self.admin_actions_deadline = 0

@external
def commit_transfer_ownership(_owner: address):
    # VULN: no access control, no event
    self.transfer_ownership_deadline = block.timestamp + 3 * 86400
    self.future_owner = _owner

@external
def apply_transfer_ownership():
    # VULN: no access control, no event, timestamp dependence
    assert block.timestamp >= self.transfer_ownership_deadline, "Too early"
    self.owner = self.future_owner

@external
def kill_pool():
    # VULN: no access control — anyone can kill
    # VULN: timestamp dependence
    assert block.timestamp < self.kill_deadline, "Deadline passed"
    self.is_killed = True

@external
def unkill_pool():
    # VULN: no access control
    self.is_killed = False

@external
def withdraw_admin_fees():
    # VULN: no access control, unchecked raw_call in loop
    for i: uint256 in range(N_COINS):
        balance: uint256 = self.balances_pool[i]
        raw_call(
            self.coins[i],
            concat(
                method_id("transfer(address,uint256)"),
                convert(msg.sender, bytes32),
                convert(balance, bytes32),
            ),
        )

@external
def emergency_destroy():
    # VULN: selfdestruct without access control
    selfdestruct(msg.sender)
