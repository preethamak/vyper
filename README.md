# Vyper Guard

**Vyper Guard** is a lightweight static security analyzer for **Vyper smart contracts**.
It scans `.vy` files and highlights insecure patterns, logic risks, and best-practice violations before deployment.

The goal is to give developers **quick feedback directly from the terminal** while writing contracts.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/vyper-guard)](https://pypi.org/project/vyper-guard/)

---

## Installation

Install the CLI globally using pip:

```bash
pip install vyper-guard
```

Verify installation:

```bash
vyper-guard --help
```

If installed correctly, the CLI help menu will appear.

---

## Basic Usage

Analyze a single contract:

```bash
vyper-guard analyze contract.vy
```

Example:

```bash
vyper-guard analyze vault.vy
```

---

## Analyze a Folder

Scan all Vyper contracts inside a directory:

```bash
vyper-guard analyze contracts/
```

The tool will recursively scan all `.vy` files.

---

## Output Formats

```bash
# Rich terminal output (default)
vyper-guard analyze contract.vy

# JSON report
vyper-guard analyze contract.vy --format json --output report.json

# Markdown report
vyper-guard analyze contract.vy --format markdown --output report.md
```

---

## Example Output

```
========================================
VYPER GUARD SECURITY REPORT
========================================

File: vault.vy

Security Score: 14 / 100
Risk Level: CRITICAL
Recommendation: DO NOT DEPLOY

----------------------------------------
Severity Breakdown
----------------------------------------

CRITICAL : 2
HIGH     : 3
MEDIUM   : 2
LOW      : 1

----------------------------------------
Findings
----------------------------------------

[CRITICAL] Reentrancy vulnerability
Line: 42
Issue:
External call happens before state update.

Fix:
Follow Checks-Effects-Interactions pattern
or use @nonreentrant.

----------------------------------------

[HIGH] Unsafe raw_call usage
Line: 42
Issue:
raw_call used without proper checks.

Fix:
Validate return value or avoid raw_call.
```

---

## What Vyper Guard Detects

### Security Issues

- Reentrancy risks
- Unsafe `raw_call`
- Delegatecall misuse
- Unprotected selfdestruct
- Unprotected state modification
- Unchecked subtraction / integer overflow

### Logic & Best Practices

- Checks-Effects-Interactions violations
- Timestamp dependence
- Value transfers inside loops
- Missing reentrancy guards
- Missing event emission
- Known compiler version bugs

---

## Detectors

| # | Detector | Severity | What It Finds |
|---|----------|----------|---------------|
| 1 | `missing_nonreentrant` | CRITICAL | External functions with value transfers but no `@nonreentrant` |
| 2 | `unsafe_raw_call` | HIGH | `raw_call()` without return value checks |
| 3 | `missing_event_emission` | LOW | State-changing functions that emit no event |
| 4 | `timestamp_dependence` | LOW | `block.timestamp` used in conditional logic |
| 5 | `integer_overflow` | HIGH | `unsafe_add`, `unsafe_sub`, `unsafe_mul`, `unsafe_div` usage |
| 6 | `unprotected_selfdestruct` | CRITICAL | `selfdestruct()` without access control |
| 7 | `dangerous_delegatecall` | HIGH | `raw_call()` with `is_delegate_call=True` |
| 8 | `unprotected_state_change` | HIGH | Writes to sensitive state without `msg.sender` check |
| 9 | `send_in_loop` | HIGH | `send()` / `raw_call()` inside `for` loops |
| 10 | `unchecked_subtraction` | HIGH | `self.x -= amount` without overflow guard |
| 11 | `cei_violation` | HIGH | External call before state update |
| 12 | `compiler_version_check` | HIGH / INFO | Known Vyper compiler CVEs (GHSA-5824, GHSA-vxmm) |

---

## Security Score

Each contract receives a **0-100 security score**.

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A+ | Production ready |
| 75-89 | A | Minor fixes needed |
| 60-74 | B | Review required |
| 45-59 | C | Risky - major fixes needed |
| < 45 | F | Do not deploy |

The score decreases based on detected vulnerability severity:

| Severity | Penalty per finding |
|----------|-------------------|
| CRITICAL | -40 |
| HIGH | -20 |
| MEDIUM | -8 |
| LOW | -3 |
| INFO | -1 |

Each severity tier is capped to prevent a single category from dominating the score.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `vyper-guard analyze <file>` | Scan a contract for vulnerabilities |
| `vyper-guard analyze <file> --fix` | Scan and auto-fix vulnerabilities |
| `vyper-guard stats <file>` | Show contract structure and complexity |
| `vyper-guard diff <file1> <file2>` | Compare security posture of two contracts |
| `vyper-guard detectors` | List all available detectors |
| `vyper-guard init` | Create a `.guardianrc` config file |
| `vyper-guard monitor <address>` | Live-monitor a deployed contract |
| `vyper-guard baseline <address>` | Build normal-behaviour baseline |
| `vyper-guard version` | Show version and environment info |

---

## What To Do After a Scan

After running Vyper Guard:

1. Review all **CRITICAL** issues first.
2. Fix **HIGH severity** vulnerabilities before deployment.
3. Improve **MEDIUM and LOW** issues to increase security score.
4. Re-run the scan until the contract reaches a safe score.

Recommended minimum score for production: **80+**

---

## Typical Workflow

```
1. Write Vyper contract
2. Run vyper-guard analyze contract.vy
3. Fix reported vulnerabilities
4. Re-run scan
5. Deploy when score is acceptable
```

---

## Auto-Remediation

```bash
vyper-guard analyze contract.vy --fix
```

This will:
1. Run all detectors
2. Generate fixes (decorators, guards, events, pragmas)
3. Show a unified diff for each fix
4. Write patched code to `contract.fixed.vy`
5. Prompt before overwriting the original

---

## Live Monitoring

```bash
# Monitor a deployed contract
vyper-guard monitor 0xAddr --rpc https://mainnet.infura.io/v3/KEY

# Build a baseline first
vyper-guard baseline 0xAddr --rpc https://rpc.url --duration 300

# Monitor with Slack alerts
vyper-guard monitor 0xAddr --rpc https://rpc.url \
  --alert-webhook https://hooks.slack.com/...
```

Requires: `pip install vyper-guard[monitor]`

---

## CI Mode

```bash
vyper-guard analyze contract.vy --ci --severity-threshold HIGH
```

Exit code 1 if any findings match or exceed the threshold - use in GitHub Actions or any CI pipeline.

---

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/preethamak/vyper
    rev: v0.3.0
    hooks:
      - id: vyper-guard
```

Every commit touching `.vy` files will be scanned automatically.

---

## Example Vulnerability Fix

Bad pattern:

```vyper
raw_call(msg.sender, b"", value=balance)
self.balances[msg.sender] = 0
```

Safer pattern:

```vyper
self.balances[msg.sender] = 0
raw_call(msg.sender, b"", value=balance)
```

Or use a reentrancy guard:

```vyper
@nonreentrant("lock")
```

---

## Limitations

Vyper Guard performs **pattern-based static analysis**.

This means:

- It detects known risky patterns
- It does not compile or execute contracts
- Some complex vulnerabilities may require manual review

---

## Disclaimer

Vyper Guard helps identify common vulnerabilities but **does not guarantee contract security**.

Always combine automated scanning with **manual audits** before deploying smart contracts.

---

## License

MIT
