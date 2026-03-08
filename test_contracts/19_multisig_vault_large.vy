# @version ^0.3.7
# ═══════════════════════════════════════════════════════════════════════
# MultiSigVault — Multi-signature wallet with batched execution
# Large contract (~350 lines) for stress-testing vyper-guard
# Expected vulnerabilities: reentrancy, missing events, timestamp,
#   unprotected state, CEI, raw_call, send in loop, delegatecall
# ═══════════════════════════════════════════════════════════════════════

interface ERC20:
    def balanceOf(account: address) -> uint256: view
    def transfer(to: address, amount: uint256) -> bool: nonpayable

# ── Constants ────────────────────────────────────────────────────────
MAX_SIGNERS: constant(uint256) = 20
MAX_TXN_PER_BATCH: constant(uint256) = 25
CONFIRMATION_TIMEOUT: constant(uint256) = 7 * 86400  # 1 week

# ── State ────────────────────────────────────────────────────────────
signers: public(DynArray[address, MAX_SIGNERS])
is_signer: public(HashMap[address, bool])
signer_count: public(uint256)
threshold: public(uint256)

# Transaction data
txn_count: public(uint256)
txn_to: public(HashMap[uint256, address])
txn_value: public(HashMap[uint256, uint256])
txn_data: public(HashMap[uint256, Bytes[1024]])
txn_executed: public(HashMap[uint256, bool])
txn_canceled: public(HashMap[uint256, bool])
txn_confirmation_count: public(HashMap[uint256, uint256])
txn_created_at: public(HashMap[uint256, uint256])
txn_is_delegate: public(HashMap[uint256, bool])
txn_confirmed_by: public(HashMap[uint256, HashMap[address, bool]])

# Batch operations
batch_count: public(uint256)
batch_txn_ids: public(HashMap[uint256, DynArray[uint256, MAX_TXN_PER_BATCH]])
batch_executed: public(HashMap[uint256, bool])

# Daily spending limit
daily_limit: public(uint256)
spent_today: public(uint256)
last_day: public(uint256)

# Whitelist
whitelisted: public(HashMap[address, bool])
whitelist_count: public(uint256)

# Recovery
recovery_address: public(address)
recovery_deadline: public(uint256)
recovery_initiated: public(bool)

# ERC20 token tracking
tracked_tokens: public(DynArray[address, 50])
is_tracked: public(HashMap[address, bool])

# Nonces for replay protection
nonces: public(HashMap[address, uint256])

@external
def __init__(_signers: DynArray[address, MAX_SIGNERS], _threshold: uint256):
    assert len(_signers) >= _threshold, "Bad threshold"
    assert _threshold > 0, "Zero threshold"

    for s: address in _signers:
        assert s != empty(address), "Zero address"
        assert not self.is_signer[s], "Duplicate"
        self.is_signer[s] = True
        self.signers.append(s)

    self.signer_count = len(_signers)
    self.threshold = _threshold
    self.daily_limit = 100 * 10 ** 18

@external
@payable
def __default__():
    # Accept ETH — no event emitted (VULN)
    pass

# ═══════════════════════════════════════════════════════════════════
# SUBMIT TRANSACTION — missing events
# ═══════════════════════════════════════════════════════════════════

@external
def submit_transaction(
    _to: address,
    _value: uint256,
    _data: Bytes[1024],
    _is_delegate: bool,
) -> uint256:
    # VULN: no event emission
    assert self.is_signer[msg.sender], "Not signer"

    tid: uint256 = self.txn_count
    self.txn_to[tid] = _to
    self.txn_value[tid] = _value
    self.txn_data[tid] = _data
    self.txn_is_delegate[tid] = _is_delegate
    self.txn_executed[tid] = False
    self.txn_canceled[tid] = False
    # VULN: timestamp dependence
    self.txn_created_at[tid] = block.timestamp
    self.txn_count = tid + 1

    # Auto-confirm by submitter
    self.txn_confirmed_by[tid][msg.sender] = True
    self.txn_confirmation_count[tid] = 1

    return tid

@external
def confirm_transaction(tid: uint256):
    # VULN: no event
    assert self.is_signer[msg.sender], "Not signer"
    assert not self.txn_executed[tid], "Executed"
    assert not self.txn_canceled[tid], "Canceled"
    assert not self.txn_confirmed_by[tid][msg.sender], "Already confirmed"
    # VULN: timestamp dependence
    assert block.timestamp <= self.txn_created_at[tid] + CONFIRMATION_TIMEOUT, "Expired"

    self.txn_confirmed_by[tid][msg.sender] = True
    self.txn_confirmation_count[tid] += 1

@external
def revoke_confirmation(tid: uint256):
    # VULN: no event
    assert self.is_signer[msg.sender], "Not signer"
    assert not self.txn_executed[tid], "Executed"
    assert self.txn_confirmed_by[tid][msg.sender], "Not confirmed"

    self.txn_confirmed_by[tid][msg.sender] = False
    # VULN: unchecked subtraction
    self.txn_confirmation_count[tid] -= 1

# ═══════════════════════════════════════════════════════════════════
# EXECUTE — CEI violation, raw_call, delegatecall, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def execute_transaction(tid: uint256):
    # VULN: missing @nonreentrant, no event
    assert self.is_signer[msg.sender], "Not signer"
    assert not self.txn_executed[tid], "Executed"
    assert not self.txn_canceled[tid], "Canceled"
    assert self.txn_confirmation_count[tid] >= self.threshold, "Not enough"

    target: address = self.txn_to[tid]
    value: uint256 = self.txn_value[tid]
    data: Bytes[1024] = self.txn_data[tid]

    if self.txn_is_delegate[tid]:
        # VULN: dangerous delegatecall
        raw_call(target, data, is_delegate_call=True)
    else:
        # VULN: unchecked raw_call, CEI violation
        raw_call(target, data, value=value)

    # State update after external call
    self.txn_executed[tid] = True
    self._update_spending(value)

@external
def cancel_transaction(tid: uint256):
    # VULN: no access control among signers, no event
    assert not self.txn_executed[tid], "Executed"
    self.txn_canceled[tid] = True

# ═══════════════════════════════════════════════════════════════════
# BATCH EXECUTION — raw_call in loop, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def create_batch(txn_ids: DynArray[uint256, MAX_TXN_PER_BATCH]) -> uint256:
    # VULN: no event
    bid: uint256 = self.batch_count
    self.batch_txn_ids[bid] = txn_ids
    self.batch_count = bid + 1
    return bid

@external
def execute_batch(bid: uint256):
    # VULN: missing @nonreentrant, no event, raw_call in loop
    assert not self.batch_executed[bid], "Executed"

    for tid: uint256 in self.batch_txn_ids[bid]:
        if not self.txn_executed[tid] and not self.txn_canceled[tid]:
            if self.txn_confirmation_count[tid] >= self.threshold:
                target: address = self.txn_to[tid]
                value: uint256 = self.txn_value[tid]
                data: Bytes[1024] = self.txn_data[tid]

                if self.txn_is_delegate[tid]:
                    # VULN: delegatecall in loop
                    raw_call(target, data, is_delegate_call=True)
                else:
                    # VULN: raw_call in loop
                    raw_call(target, data, value=value)

                self.txn_executed[tid] = True

    self.batch_executed[bid] = True

# ═══════════════════════════════════════════════════════════════════
# DAILY SPENDING — timestamp, unprotected
# ═══════════════════════════════════════════════════════════════════

@internal
def _update_spending(_amount: uint256):
    # VULN: timestamp dependence
    today: uint256 = block.timestamp / 86400
    if today > self.last_day:
        self.spent_today = 0
        self.last_day = today
    self.spent_today += _amount

@external
def set_daily_limit(_limit: uint256):
    # VULN: no access control (should require multisig), no event
    self.daily_limit = _limit

# ═══════════════════════════════════════════════════════════════════
# SIGNER MANAGEMENT — unprotected state, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def add_signer(_signer: address):
    # VULN: no access control, no event
    assert not self.is_signer[_signer], "Already signer"
    self.is_signer[_signer] = True
    self.signers.append(_signer)
    self.signer_count += 1

@external
def remove_signer(_signer: address):
    # VULN: no access control, no event
    assert self.is_signer[_signer], "Not signer"
    self.is_signer[_signer] = False
    self.signer_count -= 1

@external
def change_threshold(_threshold: uint256):
    # VULN: no access control, no event
    assert _threshold > 0, "Zero"
    assert _threshold <= self.signer_count, "Too high"
    self.threshold = _threshold

# ═══════════════════════════════════════════════════════════════════
# WHITELIST — unprotected state, missing events
# ═══════════════════════════════════════════════════════════════════

@external
def add_to_whitelist(_addr: address):
    # VULN: no access control, no event
    self.whitelisted[_addr] = True
    self.whitelist_count += 1

@external
def remove_from_whitelist(_addr: address):
    # VULN: no access control, no event
    self.whitelisted[_addr] = False
    # VULN: unchecked subtraction
    self.whitelist_count -= 1

# ═══════════════════════════════════════════════════════════════════
# TOKEN MANAGEMENT — raw_call, send in loop
# ═══════════════════════════════════════════════════════════════════

@external
def track_token(_token: address):
    # VULN: no access control, no event
    self.tracked_tokens.append(_token)
    self.is_tracked[_token] = True

@external
def sweep_token(_token: address, _to: address):
    # VULN: no access control, unchecked raw_call, no event
    raw_call(
        _token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(_to, bytes32),
            convert(max_value(uint256), bytes32),
        ),
    )

@external
def sweep_all_tokens(_to: address):
    # VULN: no access control, raw_call in loop, no event
    for token: address in self.tracked_tokens:
        raw_call(
            token,
            concat(
                method_id("transfer(address,uint256)"),
                convert(_to, bytes32),
                convert(max_value(uint256), bytes32),
            ),
        )

@external
def distribute_eth(recipients: DynArray[address, 50], amounts: DynArray[uint256, 50]):
    # VULN: no access control, send in loop, no event
    for i: uint256 in range(50):
        if i >= len(recipients):
            break
        send(recipients[i], amounts[i])

# ═══════════════════════════════════════════════════════════════════
# RECOVERY — timestamp, unprotected, selfdestruct
# ═══════════════════════════════════════════════════════════════════

@external
def initiate_recovery(_recovery: address):
    # VULN: no access control, timestamp, no event
    self.recovery_address = _recovery
    self.recovery_deadline = block.timestamp + 30 * 86400
    self.recovery_initiated = True

@external
def execute_recovery():
    # VULN: no access control, timestamp, no event
    assert self.recovery_initiated, "Not initiated"
    assert block.timestamp >= self.recovery_deadline, "Too early"
    self.is_signer[self.recovery_address] = True
    self.signers.append(self.recovery_address)
    self.signer_count += 1
    self.recovery_initiated = False

@external
def cancel_recovery():
    # VULN: no access control, no event
    self.recovery_initiated = False
    self.recovery_address = empty(address)

@external
def emergency_destroy():
    # VULN: selfdestruct without access control
    selfdestruct(msg.sender)
