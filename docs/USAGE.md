# Usage Guide

## Static Analysis

### Basic Scan

```bash
# Scan a contract (Rich terminal output)
vyper-guard analyze path/to/contract.vy

# Absolute paths work too
vyper-guard analyze /home/user/projects/my_vault.vy
```

### Output Formats

```bash
# JSON output (pipe to jq, use in CI)
vyper-guard analyze contract.vy --format json

# Save JSON to file
vyper-guard analyze contract.vy --format json --output report.json

# Markdown report
vyper-guard analyze contract.vy --format markdown --output report.md
```

### Filtering

```bash
# Only HIGH and CRITICAL findings
vyper-guard analyze contract.vy --severity-threshold HIGH

# Run specific detectors only
vyper-guard analyze contract.vy --detectors missing_nonreentrant,unsafe_raw_call

# Verbose debug output
vyper-guard analyze contract.vy --verbose
```

### CI Mode

```bash
# Exit code 1 if any findings exist (for CI pipelines)
vyper-guard analyze contract.vy --ci

# CI mode with threshold
vyper-guard analyze contract.vy --ci --severity-threshold HIGH
```

## Auto-Remediation (`--fix`)

The `--fix` flag generates and applies fixes for detected vulnerabilities:

```bash
vyper-guard analyze contract.vy --fix
```

**What happens:**

1. The contract is analyzed normally (findings displayed)
2. For each finding, an auto-fix is generated (if possible)
3. Each fix is shown with a unified diff preview
4. A patched file is written to `contract.fixed.vy`
5. You're prompted whether to overwrite the original

**Example output:**

```
╭──────────────────────────────────────────────╮
│ 🔧  Auto-Remediation  —  4 fix(es) generated │
╰──────────────────────────────────────────────╯

  Fix 1/4: Added @nonreentrant decorator to withdraw().
    Severity: CRITICAL  |  Detector: missing_nonreentrant

  --- a/vault.vy
  +++ b/vault.vy
  @@ -5,6 +5,7 @@
  +@nonreentrant
   @external
   def withdraw(amount: uint256):

  ✅  Patched contract written to: vault.fixed.vy
  Overwrite original file (vault.vy)? [y/N]:
```

**Fix types:**

| Detector | Fix Applied |
|----------|-------------|
| `missing_nonreentrant` | Inserts `@nonreentrant` decorator |
| `unsafe_raw_call` | Wraps in `assert raw_call(...)` |
| `missing_event_emission` | Adds `event` definition + `log` statement |
| `unprotected_state_change` | Adds `assert msg.sender == self.owner` |
| `unprotected_selfdestruct` | Adds access-control guard |
| `unchecked_subtraction` | Adds `assert balance >= amount` guard |
| `integer_overflow` | Replaces `unsafe_*` ops with safe operators or adds validation |
| `compiler_version_check` | Upgrades pragma to `^0.4.0` |
| `cei_violation` | Adds `FIXME` comment (manual reorder needed) |
| `send_in_loop` | Adds `FIXME` comment (pull-pattern refactor needed) |
| `timestamp_dependence` | Adds `NOTE` about miner manipulation |
| `dangerous_delegatecall` | Adds access-control if missing |

## Smart False-Positive Suppression (v0.2.0)

Vyper Guard v0.2.0 includes context-aware analysis that suppresses false positives by recognizing well-known safe patterns found in production DeFi contracts:

| Detector | Suppression Logic |
|----------|-------------------|
| `missing_nonreentrant` | Downgrades CRITICAL → MEDIUM when access control (`assert msg.sender == self.owner`) is present |
| `unsafe_raw_call` | Skips the safeTransfer pattern (captured return + `convert(_response, bool)` check) |
| `timestamp_dependence` | Skips timelocks — deadline/delay variables, large constants (≥3600s) |
| `send_in_loop` | Skips small constant-bounded loops (`range(3)`, `N_COINS`, etc.) |
| `integer_overflow` | Only flags `unsafe_add/sub/mul/div` — Vyper has built-in overflow protection |
| `compiler_version_check` | GHSA-vxmm only flagged when contract uses `DynArray` inside `HashMap` values |

These suppression rules reduced false positives from **77% to 0%** when tested against the real **Curve StableSwap** mainnet contract (891 lines, target of the $70M July 2023 exploit).

## List All Detectors

```bash
vyper-guard detectors
```

## Live Monitoring

> Requires: `pip install -e ".[monitor]"` (web3 dependency)

### Monitor a Deployed Contract

```bash
# Basic monitoring
vyper-guard monitor 0xYourContractAddress --rpc https://mainnet.infura.io/v3/KEY

# With Slack/Discord alerts
vyper-guard monitor 0xAddr --rpc https://rpc.url --alert-webhook https://hooks.slack.com/...

# With anomaly detection baseline
vyper-guard monitor 0xAddr --rpc https://rpc.url --baseline baseline.json
```

### Build a Baseline Profile

Record normal contract behavior to enable anomaly detection:

```bash
# Observe for 5 minutes, save baseline
vyper-guard baseline 0xAddr --rpc https://rpc.url --duration 300 --output baseline.json
```

### Anomaly Detection Rules

The monitor detects:

- **Gas spikes** — usage significantly above normal (>3σ)
- **Rapid balance drains** — large ETH outflows in short windows
- **Failed transaction clusters** — repeated reverts (attack attempts)
- **Unusual function calls** — selectors never seen during baseline
- **Reentrancy indicators** — repeated calls to the same function within one block

## Configuration File

Create a `.guardianrc` (YAML) in your project root:

```yaml
analysis:
  enabled_detectors:
    - all
  disabled_detectors:
    - timestamp_dependence   # intentional in our contract
  severity_threshold: LOW

reporting:
  default_format: cli
  show_source_snippets: true
  show_fix_suggestions: true

performance:
  max_file_size_mb: 10
  cache_enabled: true
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GUARDIAN_DEFAULT_FORMAT` | Default output format (`cli`, `json`, `markdown`) |
| `GUARDIAN_SEVERITY_THRESHOLD` | Default minimum severity |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (no findings, or findings below threshold) |
| `1` | Findings found (in `--ci` mode) |
| `2` | Error (file not found, invalid arguments, analysis failure) |
