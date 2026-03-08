# Detectors

Vyper Guard ships with **12 context-aware detectors** specifically designed for Vyper smart contracts. Each detector operates on source-level parsing — no Vyper compiler required.

All detectors include **smart false-positive suppression** to avoid flagging well-known safe patterns used in production DeFi contracts.

## Overview

| # | Detector | Severity | Category | Smart Suppression | Auto-Fix |
|---|----------|----------|----------|-------------------|----------|
| 1 | `missing_nonreentrant` | CRITICAL/MEDIUM | Reentrancy | ✅ Access control | ✅ |
| 2 | `unsafe_raw_call` | HIGH | External Call | ✅ safeTransfer | ✅ |
| 3 | `missing_event_emission` | MEDIUM | Code Quality | — | ✅ |
| 4 | `timestamp_dependence` | MEDIUM | Timestamp | ✅ Timelocks | ✅ |
| 5 | `integer_overflow` | HIGH | Arithmetic | ✅ Built-in protection | ✅ |
| 6 | `unprotected_selfdestruct` | CRITICAL | Self-Destruct | — | ✅ |
| 7 | `dangerous_delegatecall` | HIGH/CRITICAL | Delegate Call | — | ✅ |
| 8 | `unprotected_state_change` | HIGH | Access Control | — | ✅ |
| 9 | `send_in_loop` | HIGH | Denial of Service | ✅ Bounded loops | ✅ |
| 10 | `unchecked_subtraction` | HIGH | Input Validation | — | ✅ |
| 11 | `cei_violation` | HIGH | Reentrancy | — | ✅ |
| 12 | `compiler_version_check` | CRITICAL/HIGH/INFO | Compiler Bug | ✅ Pattern check | ✅ |

---

## 1. Missing `@nonreentrant` — Reentrancy

**Severity:** CRITICAL (no access control) / MEDIUM (with access control)  
**Confidence:** HIGH / MEDIUM

Detects `@external` functions that perform value transfers (`send`, `raw_call`) or external calls but do not use the `@nonreentrant` decorator. This is the #1 cause of exploits in DeFi.

**Smart suppression:** If the function has access control (`assert msg.sender == self.owner`), the severity is automatically downgraded from CRITICAL to MEDIUM — owner-only functions have a much smaller attack surface.

**Example (vulnerable):**
```vyper
@external
def withdraw(amount: uint256):
    send(msg.sender, amount)                   # ← no @nonreentrant!
    self.balances[msg.sender] -= amount
```

**Example (downgraded to MEDIUM):**
```vyper
@external
def withdraw_admin_fees():
    assert msg.sender == self.owner            # ← access control detected
    send(msg.sender, self.admin_fees)          # → MEDIUM, not CRITICAL
```

**Fix:** Adds `@nonreentrant` decorator above the function.

**Skips:** `__init__` (constructor), `__default__` (fallback), `@view`, `@pure`, `@deploy`.

---

## 2. Unsafe `raw_call` — External Call

**Severity:** HIGH  
**Confidence:** MEDIUM

Detects `raw_call()` whose return value is not checked via `assert` or a success variable.

**Smart suppression:** Recognizes the standard **safeTransfer pattern** used throughout DeFi:
```vyper
_response: Bytes[32] = raw_call(
    _coin,
    concat(method_id("transfer(address,uint256)"), ...),
    max_outsize=32,
)
if len(_response) > 0:
    assert convert(_response, bool)
```
This pattern captures the return value and checks it — no false positive. Also skips any `raw_call` where the result is captured into a variable with `max_outsize` (multi-line calls are fully joined for analysis).

**Example (vulnerable):**
```vyper
raw_call(target, data)           # ← return value silently ignored
```

**Fix:** Wraps the call in `assert raw_call(...)`.

---

## 3. Missing Event Emission — Code Quality

**Severity:** MEDIUM  
**Confidence:** MEDIUM

Detects `@external` functions that modify state (`self.x = ...`) but do not emit an event (`log`). Events are essential for off-chain indexing and transparency.

**Example (vulnerable):**
```vyper
@external
def set_owner(new_owner: address):
    self.owner = new_owner             # ← no log statement
```

**Fix:** Adds an `event` definition and a `log` statement.

---

## 4. Timestamp Dependence

**Severity:** MEDIUM  
**Confidence:** MEDIUM

Detects usage of `block.timestamp` in conditional logic (`assert`, `if`). Miners can manipulate the timestamp by ~15 seconds.

**Smart suppression:** Skips findings in **timelock contexts** where 15-second manipulation is irrelevant:
- Variable names suggesting timelocks: `deadline`, `delay`, `lock_time`, `ramp_time`, `ADMIN_ACTIONS_DELAY`, etc.
- Large numeric constants on the line (≥ 3600 seconds = 1 hour)
- State variables with timelock-related names: `self.*_deadline`, `self.*_delay`, `self.*_timelock`

**Example (flagged):**
```vyper
if block.timestamp > 100:              # ← short window, flagged
    self.price = new_price
```

**Example (suppressed):**
```vyper
assert block.timestamp >= self.admin_actions_deadline    # ← timelock, safe
```

**Fix:** Adds a `NOTE` comment about the manipulation window.

---

## 5. Integer Overflow — Unsafe Arithmetic

**Severity:** HIGH  
**Confidence:** HIGH

Detects usage of `unsafe_add`, `unsafe_sub`, `unsafe_mul`, and `unsafe_div` operations that intentionally bypass Vyper's built-in overflow protection.

> **Note:** Vyper has had built-in overflow/underflow protection since its earliest versions (v0.1.x). This was a core language design goal. Unlike Solidity (which only got `checked` arithmetic in 0.8.0), Vyper **always** reverts on overflow. The `unsafe_*` operations were introduced in Vyper 0.4.0+ as an explicit opt-out for gas optimization.

**Example (flagged):**
```vyper
@external
def fast_add(a: uint256, b: uint256) -> uint256:
    return unsafe_add(a, b)            # ← bypasses overflow check
```

**Example (safe — NOT flagged):**
```vyper
@external
def safe_add(a: uint256, b: uint256) -> uint256:
    return a + b                       # ← Vyper checks overflow automatically
```

**Fix:** Replace `unsafe_*` with the safe operator or add input validation.

---

## 6. Unprotected `selfdestruct`

**Severity:** CRITICAL  
**Confidence:** HIGH

Detects `selfdestruct()` calls in functions without a `msg.sender` check. Anyone can destroy the contract.

**Fix:** Adds `assert msg.sender == self.owner` before the call.

---

## 7. Dangerous `delegatecall`

**Severity:** CRITICAL (no access control) / HIGH (with access control)  
**Confidence:** HIGH / MEDIUM

Detects `raw_call()` with `is_delegate_call=True`. Delegatecall executes arbitrary code in the contract's storage context.

**Fix:** Adds access-control guard if missing.

---

## 8. Unprotected State Change — Access Control

**Severity:** HIGH  
**Confidence:** HIGH

Detects `@external` functions that write to sensitive state variables (`owner`, `admin`, `paused`, `total_supply`, `minter`, etc.) without checking `msg.sender`.

**Sensitive variables monitored:**
`owner`, `admin`, `governance`, `paused`, `is_paused`, `pending_owner`, `fee_recipient`, `minter`, `operator`, `controller`, `guardian`, `total_supply`, `supply`, `total_shares`, `total_staked`, `total_deposited`.

**Fix:** Adds `assert msg.sender == self.owner` (using the actual admin variable found in the contract).

---

## 9. Send in Loop — Denial of Service

**Severity:** HIGH  
**Confidence:** HIGH

Detects `send()` or `raw_call()` inside a `for` loop. If any single recipient reverts, the entire transaction fails — a classic DoS vector.

**Smart suppression:** Skips **small constant-bounded loops** that are not a DoS risk:
- Numeric literals: `for i in range(3)` — always safe
- Well-known DeFi constants: `N_COINS`, `MAX_COINS`, `N_TOKENS`, `POOL_SIZE`, etc.
- Contract constants with known small values: `N_COINS: constant(int128) = 2`

**Example (flagged):**
```vyper
for addr: address in self.recipients:       # ← unbounded DynArray
    send(addr, self.amounts[addr])           # one revert kills everything
```

**Example (suppressed):**
```vyper
for i in range(N_COINS):                    # ← N_COINS = 2, bounded
    raw_call(self.coins[i], data)            # → NOT flagged
```

**Fix:** Adds a `FIXME` comment recommending the pull-based withdrawal pattern.

**Handles:** Nested loops correctly (uses indent-stack tracking with per-loop size tracking).

---

## 10. Unchecked Subtraction — Input Validation

**Severity:** HIGH  
**Confidence:** MEDIUM

Detects `self.x -= amount` without a preceding `assert self.x >= amount` check.

**Smart suppression:** Recognizes indirect guards:
- Related-mapping guards (e.g. `assert self.shares[user] >= amount` covers `self.total_shares -= amount`)
- Bounded-fraction derivation (when the subtracted value was computed as `... * self.x / ...`)

**Example (vulnerable):**
```vyper
self.balances[msg.sender] -= amount     # ← no balance check
```

**Fix:** Inserts `assert self.balances[msg.sender] >= amount, "Insufficient balance"` before the subtraction.

---

## 11. CEI Violation — Reentrancy

**Severity:** HIGH  
**Confidence:** HIGH

Detects functions where an external call (`send` / `raw_call`) occurs **before** a state update (`self.x = …`), violating the Checks-Effects-Interactions pattern.

**Example (vulnerable):**
```vyper
def withdraw(amount: uint256):
    send(msg.sender, amount)                    # ← Interaction first
    self.balances[msg.sender] -= amount         # ← Effect second (BAD)
```

**Fix:** Adds a `FIXME` comment (automatic reordering is too risky).

---

## 12. Compiler Version Check

**Severity:** CRITICAL / HIGH / INFO  
**Confidence:** HIGH

Checks the contract's pragma version against known vulnerable Vyper compiler releases:

| Advisory | Affected | Issue | Pattern Check |
|----------|----------|-------|---------------|
| GHSA-5824-2926-9c37 | <0.3.10 | Malfunctioning reentrancy guard (wrong storage slot) | Always flagged |
| GHSA-vxmm-c4qg-qc4v | <0.3.8 | Storage corruption with dynamic arrays as mapping values | Only if `HashMap[..., DynArray[...]]` found |

**Smart suppression (v0.2.0):** GHSA-vxmm is only flagged if the contract actually uses `DynArray` as a `HashMap` value type. Most contracts don't use this pattern, so the advisory is irrelevant for them.

Also flags missing pragma (INFO severity).

**Fix:** Upgrades pragma to `# pragma version ^0.4.0`.

---

## Scoring

Each finding deducts from a base score of 100:

| Severity | Points |
|----------|--------|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -8 |
| LOW | -3 |
| INFO | 0 |

**Grades:**

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A+ | Production Ready |
| 75-89 | A | Minor fixes needed |
| 60-74 | B | Review required |
| 45-59 | C | Risky — major fixes needed |
| 0-44 | F | Do not deploy |

---

## Real-World Accuracy

Tested against **Curve StableSwap** (mainnet, 891 lines, `^0.2.8`, target of the $70M July 2023 exploit):

- **v0.1.0:** 26 findings, ~20 false positives (77% FP rate)
- **v0.2.0:** 8 findings, 0 false positives (0% FP rate)
- Correctly identifies **GHSA-5824** — the exact bug exploited in the real attack
