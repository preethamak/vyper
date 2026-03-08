<div align="center">

# 🛡️ Vyper Guard

**Lightweight Static Security Analyzer for Vyper Smart Contracts**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/vyper-guard)](https://pypi.org/project/vyper-guard/)

Scan `.vy` files for vulnerabilities and get instant feedback from your terminal.

[Installation](#installation) • [Usage](#usage) • [Detectors](#detectors) • [Examples](#examples)

</div>

---

## What is Vyper Guard?

Vyper Guard is a **fast, accurate static analyzer** built specifically for Vyper smart contracts. It detects security vulnerabilities, logic risks, and best-practice violations before deployment.

**Key Features:**
-  Lightning-fast analysis (scan in milliseconds)
-  Vyper-native (understands decorators, built-in safety)
-  12+ specialized security detectors
-  Auto-fix detected vulnerabilities
-  Clear security scoring (0-100)
-  Multiple output formats (CLI, JSON, Markdown)

---

## Installation

```bash
pip install vyper-guard
```

Verify installation:

```bash
vyper-guard --version
```

---

## Quick Start

### Analyze a Single Contract

```bash
vyper-guard analyze vault.vy
```

### Analyze a Folder

```bash
vyper-guard analyze contracts/
```

### Generate JSON Report

```bash
vyper-guard analyze vault.vy --format json --output report.json
```

### Auto-Fix Vulnerabilities

```bash
vyper-guard analyze vault.vy --fix
```

---

## Example Output

```
╔════════════════════════════════════════════════════════════════╗
║            VYPER GUARD SECURITY REPORT                         ║
╚════════════════════════════════════════════════════════════════╝

📄 File: vault.vy

┌────────────────────────────────────────────────────────────────┐
│ SECURITY SCORE: 34 / 100                                       │
│ Grade: F  |  Risk: 🔴 CRITICAL                                 │
│ ⚠️  DO NOT DEPLOY                                              │
└────────────────────────────────────────────────────────────────┘

SEVERITY BREAKDOWN
  🔴 CRITICAL ..... 2 issues
  🟠 HIGH ......... 3 issues
  🟡 MEDIUM ....... 1 issue
  🔵 LOW .......... 2 issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL: Reentrancy Vulnerability (Line 42)

  Issue: External call before state update
  
  Vulnerable Code:
    42 │   raw_call(msg.sender, b"", value=balance)
    43 │   self.balances[msg.sender] = 0

  ✅ Fix: Update state BEFORE external call
    42 │   self.balances[msg.sender] = 0
    43 │   raw_call(msg.sender, b"", value=balance)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Next Steps:
  1. Fix all CRITICAL issues immediately
  2. Address HIGH severity vulnerabilities
  3. Re-run: vyper-guard analyze vault.vy
```

---

## Detectors

Vyper Guard includes **12 specialized detectors** for Vyper contracts:

### 🔴 Critical Vulnerabilities

| Detector | Description |
|----------|-------------|
| `cei_violation` | External calls before state updates (reentrancy) |
| `unprotected_selfdestruct` | Selfdestruct without access control |
| `missing_nonreentrant` | Value transfers without `@nonreentrant` |

### 🟠 High Severity

| Detector | Description |
|----------|-------------|
| `unsafe_raw_call` | `raw_call()` without return value checks |
| `dangerous_delegatecall` | Delegatecall with untrusted data |
| `unprotected_state_change` | State changes without authorization |
| `integer_overflow` | Unsafe arithmetic operations |
| `send_in_loop` | Value transfers in loops (DoS risk) |
| `unchecked_subtraction` | Subtraction without underflow check |

### 🟡 Medium & 🔵 Low

| Detector | Severity | Description |
|----------|----------|-------------|
| `compiler_version_check` | MEDIUM | Known vulnerable compiler versions |
| `missing_event_emission` | LOW | State changes without events |
| `timestamp_dependence` | LOW | Logic depends on `block.timestamp` |

---

## Security Scoring

Each contract receives a **0-100 security score**:

```
Base Score: 100

Deductions:
  CRITICAL: -40 points (capped at -80)
  HIGH:     -20 points (capped at -60)
  MEDIUM:   -8 points  (capped at -24)
  LOW:      -3 points  (capped at -9)
```

### Grade Scale

| Score | Grade | Risk | Recommendation |
|-------|-------|------|----------------|
| 90-100 | A+ | ✅ Minimal | Production ready |
| 75-89 | A | 🟢 Low | Minor fixes |
| 60-74 | B | 🟡 Moderate | Review required |
| 45-59 | C | 🟠 High | Major fixes needed |
| 0-44 | F | 🔴 Critical | **DO NOT DEPLOY** |

**Recommended minimum for production: 80+**

---

## CLI Commands

```bash
# Analyze
vyper-guard analyze <file_or_directory>

# With options
vyper-guard analyze vault.vy --format json --output report.json
vyper-guard analyze vault.vy --severity HIGH
vyper-guard analyze vault.vy --fix

# Other commands
vyper-guard stats vault.vy              # Show contract stats
vyper-guard diff v1.vy v2.vy           # Compare contracts
vyper-guard detectors                   # List all detectors
vyper-guard version                     # Show version
```

### Options

```
--format TEXT       Output: cli, json, markdown [default: cli]
--output PATH       Save report to file
--fix              Auto-fix vulnerabilities
--severity TEXT    Filter by: LOW, MEDIUM, HIGH, CRITICAL
--detectors TEXT   Comma-separated detector list
--exclude TEXT     Exclude patterns
--verbose          Enable verbose logging
--config PATH      Configuration file path
```

---

## Configuration

Create `.guardianrc` in your project root:

```yaml
# Analysis Settings
analysis:
  enabled_detectors:
    - cei_violation
    - unsafe_raw_call
    - missing_nonreentrant
  
  severity_threshold: MEDIUM
  
  exclude_patterns:
    - "*/test/*"
    - "*/mock/*"

# Reporting
reporting:
  default_format: cli
  output_directory: "./reports"
  include_fix_suggestions: true

# Auto-Fix
remediation:
  auto_apply: false
  backup_original: true
```

---

## Examples

### Example 1: Reentrancy

**❌ Vulnerable:**
```vyper
@external
def withdraw():
    balance: uint256 = self.balances[msg.sender]
    raw_call(msg.sender, b"", value=balance)  # External call first
    self.balances[msg.sender] = 0             # State update after
```

**✅ Fixed:**
```vyper
@external
@nonreentrant("lock")
def withdraw():
    balance: uint256 = self.balances[msg.sender]
    self.balances[msg.sender] = 0             # State update first
    raw_call(msg.sender, b"", value=balance)  # External call after
```

### Example 2: Unsafe raw_call

**❌ Vulnerable:**
```vyper
@external
def transfer(recipient: address, amount: uint256):
    raw_call(recipient, b"", value=amount)  # No check
```

**✅ Fixed:**
```vyper
@external
def transfer(recipient: address, amount: uint256):
    success: bool = raw_call(recipient, b"", value=amount)[0]
    assert success, "Transfer failed"
```

### Example 3: Missing Events

**❌ Vulnerable:**
```vyper
@external
def updateOwner(new_owner: address):
    self.owner = new_owner  # No event
```

**✅ Fixed:**
```vyper
event OwnerUpdated:
    old_owner: indexed(address)
    new_owner: indexed(address)

@external
def updateOwner(new_owner: address):
    old_owner: address = self.owner
    self.owner = new_owner
    log OwnerUpdated(old_owner, new_owner)
```

---

## Development Workflow

```
1. Write Vyper contract
2. Run: vyper-guard analyze contract.vy
3. Fix CRITICAL and HIGH issues
4. Run: vyper-guard analyze contract.vy --fix
5. Re-scan until score ≥ 80
6. Test thoroughly
7. Deploy
```

---

## Security Checklist

Before deploying:

- [ ] Security score ≥ 80
- [ ] Zero CRITICAL vulnerabilities
- [ ] Zero HIGH vulnerabilities
- [ ] All external calls use reentrancy guards
- [ ] Access control on sensitive functions
- [ ] Events emitted for state changes
- [ ] Using latest stable Vyper version
- [ ] Test coverage ≥ 90%

---

## Contributing

Contributions welcome! Here's how:

- 🐛 Report bugs via [GitHub Issues](https://github.com/preethamak/vyper-guard/issues)
- 💡 Suggest features or new detectors
- 📝 Improve documentation
- 🔧 Submit pull requests

### Development Setup

```bash
git clone https://github.com/preethamak/vyper-guard.git
cd vyper-guard
pip install -e ".[dev]"
pytest
```

---

## Resources

- [Vyper Documentation](https://docs.vyperlang.org/)
- [Vyper GitHub](https://github.com/vyperlang/vyper)

---

## Disclaimer

**Important:** Vyper Guard is a static analysis tool that helps identify common vulnerabilities. It **does not guarantee complete security**.

**Recommendations:**
- Combine automated scanning with manual audits
- Test thoroughly on testnets before mainnet
- Consider professional audits for high-value contracts

Vyper Guard is provided "as is" without warranty.

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments

Built with ❤️ by [Preetham AK](https://github.com/preethamak)

Special thanks to the [Vyper](https://github.com/vyperlang/vyper) team.

---

## Contact

- **GitHub Issues:** [Report bugs](https://github.com/preethamak/vyper-guard/issues)
- **GitHub:** [@preethamak](https://github.com/preethamak)

---

<div align="center">

**⭐ Star us on GitHub!**

Made with 🛡️ for secure smart contract development

</div>
