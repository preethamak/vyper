<div align="center">

# 🛡️ Vyper Guard

**Lightweight Static Security Analyzer for Vyper Smart Contracts**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/vyper-guard)](https://pypi.org/project/vyper-guard/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/vyper-guard?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=ORANGE&left_text=downloads)](https://pepy.tech/projects/vyper-guard)

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

---

## Output Formats

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

| # | Detector | Severity | What It Finds |
|---|----------|----------|---------------|
| 1 | `missing_nonreentrant` | CRITICAL | External functions with value transfers but no `@nonreentrant` |
| 2 | `unsafe_raw_call` | HIGH | `raw_call()` without return value checks |
| 3 | `missing_event_emission` | LOW | State-changing functions that emit no event |
| 4 | `timestamp_dependence` | LOW | `block.timestamp` used in short-window conditional logic |
| 5 | `integer_overflow` | HIGH | `unsafe_add`, `unsafe_sub`, `unsafe_mul`, `unsafe_div` usage |
| 6 | `unprotected_selfdestruct` | CRITICAL | `selfdestruct()` without access control |
| 7 | `dangerous_delegatecall` | HIGH | `raw_call()` with `is_delegate_call=True` |
| 8 | `unprotected_state_change` | HIGH | Writes to sensitive state without `msg.sender` check |
| 9 | `send_in_loop` | HIGH | `send()` / `raw_call()` inside `for` loops |
| 10 | `unchecked_subtraction` | HIGH | `self.x -= amount` without overflow guard |
| 11 | `cei_violation` | HIGH | External call before state update |
| 12 | `compiler_version_check` | HIGH / INFO | Known Vyper compiler CVEs (GHSA-5824, GHSA-vxmm) |

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

> Note: `analyze` currently accepts a single `.vy` file path, not a directory path.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `vyper-guard analyze <file>` | Scan a contract for vulnerabilities |
| `vyper-guard analyze <file> --fix` | Scan and auto-fix vulnerabilities |
| `vyper-guard stats <file>` | Show contract structure and complexity |
| `vyper-guard diff <file1> <file2>` | Compare security posture of two contracts |
| `vyper-guard benchmark [dir]` | Run lightweight detector quality benchmark on a corpus |
| `vyper-guard detectors` | List all available detectors |
| `vyper-guard init` | Create a `.guardianrc` config file |
| `vyper-guard monitor <address>` | Live-monitor a deployed contract |
| `vyper-guard baseline <address>` | Build normal-behaviour baseline |
| `vyper-guard version` | Show version and environment info |

---

## Recent 0.3.x Highlights

- Explorer-first workflow (`explorer`, `analyze-address`) for verified source analysis.
- AI advisory triage with deterministic fallback (`--ai-triage`).
- LLM agent mode with memory/sandbox support (`agent`, `agent memory`).
- Improved `stats --graph` HTML dashboard with clearer function-call/control-flow visuals.

### Documentation Map

- Full CLI usage and examples: [docs/USAGE.md](docs/USAGE.md)
- Detector catalog and rationale: [docs/DETECTORS.md](docs/DETECTORS.md)
- Installation and maintainer publishing flow: [docs/INSTALLATION.md](docs/INSTALLATION.md)
- Release notes: [docs/CHANGELOG.md](docs/CHANGELOG.md)

### Feature Quick Pointers

- AI triage: `analyze --ai-triage` (+ `--ai-triage-mode llm` when configured)
- AI config helper: `ai config set/show`
- Graph exports: `stats <file> --graph` (`--graph-json`, `--graph-html`)
- Explorer + verified-source analysis: `explorer`, `analyze-address`
- Auto-remediation: `analyze --fix`, `--fix-dry-run`, `--fix-report`

---

## Maintainer Release Notes (PyPI)

Use explicit artifacts (avoid `dist/*` when old versions exist):

```bash
rm -rf dist build
python -m build
python -m twine check dist/*
python -m twine upload dist/vyper_guard-<VERSION>-py3-none-any.whl dist/vyper_guard-<VERSION>.tar.gz
```

Rules:

1. Bump version in both `pyproject.toml` and `src/guardian/__init__.py` first.
2. Never re-upload an already published version.
3. For token auth, set `TWINE_USERNAME=__token__` and use full `pypi-...` token as password.

---

## What To Do After a Scan

1. Fix **CRITICAL** issues first.
2. Resolve **HIGH** severity before deployment.
3. Improve **MEDIUM/LOW** findings for audit quality.
4. Re-run scans until security posture is stable.

Recommended minimum score for production: **80+**

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

-  Report bugs via [GitHub Issues](https://github.com/preethamak/vyper-guard/issues)
-  Suggest features or new detectors
-  Improve documentation
-  Submit pull requests

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

Made with 🛡️ for secure smart contract development

</div>
