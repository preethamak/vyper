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

# If --format is omitted, the default comes from .guardianrc (reporting.default_format)
```

Security notes:

- Config auto-discovery trusts only the current working directory by default.
- To allow parent-directory config discovery, set `GUARDIAN_TRUST_PARENT_CONFIG=true`.
- Invalid environment overrides for constrained fields are ignored and safe defaults are kept.

### Explainability Fields (JSON)

JSON findings include explainability metadata when available:

- `why_flagged`
- `evidence`
- `why_not_suppressed`
- `semantic_context`

### AI-Assisted Triage (Optional)

AI triage is an advisory post-processor. It does **not** change detector verdicts.

```bash
# Enable triage metadata in output
vyper-guard analyze contract.vy --format json --ai-triage

# Disable triage explicitly (overrides config)
vyper-guard analyze contract.vy --no-ai-triage

# Triage policy controls
vyper-guard analyze contract.vy --format json --ai-triage \
  --ai-triage-min-severity HIGH --ai-triage-max-items 10

# LLM-backed triage mode (OpenAI-compatible endpoint)
export GUARDIAN_LLM_API_KEY="<your_key>"
vyper-guard analyze contract.vy --format json --ai-triage \
  --ai-triage-mode llm --ai-llm-model gpt-5

# Explicitly allow deterministic fallback when LLM triage is unavailable
vyper-guard analyze contract.vy --format json --ai-triage \
  --ai-triage-mode llm --allow-ai-fallback
```

JSON triage entries include deterministic scoring rationale fields:

- `confidence`
- `scoring_rationale.version`
- `scoring_rationale.severity_base`
- `scoring_rationale.evidence_bonus`
- `scoring_rationale.final_confidence`

When triage is enabled, JSON output also includes a top-level policy contract:

- `ai_triage_policy.policy_version`
- `ai_triage_policy.status`
- `ai_triage_policy.deterministic`
- `ai_triage_policy.can_override_verdict` (always `false`)
- `ai_triage_policy.deprecation.announced`
- `ai_triage_policy.deprecation.sunset_after`

LLM mode notes:

- LLM triage is advisory only and **cannot** override detector findings.
- By default, LLM triage failures return a non-zero exit.
- Use `--allow-ai-fallback` to explicitly allow deterministic fallback output.
- LLM calls use an OpenAI-compatible `chat/completions` API.

### AI Config Commands (Terminal-first)

```bash
# Configure AI provider/model without editing files
vyper-guard ai config set provider openai
vyper-guard ai config set model gpt-5.3-codex

# Store API key (interactive hidden prompt)
vyper-guard ai config set api-key

# Or pass API key directly
vyper-guard ai config set api-key <your_key>

# Show effective AI config (API key redacted)
vyper-guard ai config show
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

# If --severity-threshold is omitted, the default comes from .guardianrc (analysis.severity_threshold)
```

## Auto-Remediation (`--fix`)

The `--fix` flag generates and applies fixes for detected vulnerabilities:

```bash
vyper-guard analyze contract.vy --fix

# Only auto-apply low/moderate-risk fixes (skip Tier C)
vyper-guard analyze contract.vy --fix --max-auto-fix-tier B

# Preview remediation without writing contract.fixed.vy
vyper-guard analyze contract.vy --fix --fix-dry-run

# Export remediation planning/execution report as JSON
vyper-guard analyze contract.vy --fix-dry-run --fix-report remediation-report.json
```

Risk tiers:

- `A` — low-risk mechanical edits (safest auto-apply)
- `B` — moderate-risk edits (review recommended)
- `C` — advisory/manual refactor prompts

**What happens:**

1. The contract is analyzed normally (findings displayed)
2. For each finding, an auto-fix is generated (if possible)
3. Each fix is shown with a unified diff preview
4. You are prompted before writing `contract.fixed.vy` (default: No)
5. If written, you are prompted before overwriting the original (default: No)
6. On overwrite, a backup is always created first (`.bak`, then `.bak.N` if needed)

If `--fix-dry-run` is used, steps 4-5 are skipped and no files are modified.

If `--fix-report <path>` is used, Vyper Guard writes a deterministic remediation JSON artifact
containing plan totals, eligible/skipped counts, generated fixes, and not-applied fixes.

## Contract Stats + Graph Export

Generate structural contract metrics in terminal:

```bash
vyper-guard stats contract.vy
```

Export graph artifacts for dashboards/CI attachments:

```bash
# Writes contract.stats.json + contract.stats.html beside the file
vyper-guard stats contract.vy --graph

# Custom artifact paths
vyper-guard stats contract.vy \
  --graph-json artifacts/contract-stats.json \
  --graph-html artifacts/contract-stats.html
```

## Block Explorer Lookup

Fetch verified metadata (source, ABI, functions) from explorer APIs:

```bash
# API credentials (recommended via environment)
export GUARDIAN_EXPLORER_API_KEY="<explorer_key>"
export GUARDIAN_LLM_API_KEY="<llm_key>"
```

```bash
# Uses defaults from .guardianrc / env
vyper-guard explorer 0xYourContractAddress

# Auto fallback provider chain (default): etherscan -> blockscout -> sourcify
vyper-guard explorer 0xYourContractAddress --provider auto

# JSON output + save artifacts
vyper-guard explorer 0xYourContractAddress --format json \
  --save-json contract-meta.json \
  --save-source contract.vy \
  --save-abi contract.abi.json

# Override provider/network/api key
vyper-guard explorer 0xYourContractAddress \
  --provider etherscan --network ethereum --api-key <explorer_key>

# Explicit fallback order (comma-separated)
vyper-guard explorer 0xYourContractAddress \
  --provider etherscan,blockscout,sourcify --network ethereum
```

Analyze directly from explorer-verified source:

```bash
vyper-guard analyze-address 0xYourContractAddress --format json

# Save fetched source and also emit report file
vyper-guard analyze-address 0xYourContractAddress \
  --save-source fetched.vy --format markdown --output report.md

# If LLM triage is enabled, fallback is opt-in
vyper-guard analyze-address 0xYourContractAddress \
  --ai-triage --ai-triage-mode llm --allow-ai-fallback

# Configure explorer defaults in ~/.guardianrc
vyper-guard explorer config set provider auto
vyper-guard explorer config set network sepolia
vyper-guard explorer config set api-key
vyper-guard explorer config show
```

## LLM Agent Mode (Memory + Sandbox)

Run an LLM-backed security assistant with optional file/address context:

```bash
export GUARDIAN_LLM_API_KEY="<your_key>"

# Ask with local contract context
vyper-guard agent "What are the top 3 security risks and fixes?" --file contract.vy

# Ask with explorer address context
vyper-guard agent "Summarize ABI attack surface" --address 0xYourContractAddress

# Fallback output is opt-in when explorer/LLM calls fail
vyper-guard agent "Summarize ABI attack surface" \
  --address 0xYourContractAddress --allow-fallback

# Use persistent memory + optional sandbox helper script
vyper-guard agent "Validate this patch plan" \
  --file contract.vy \
  --memory-file .guardian_agent_memory.jsonl \
  --sandbox-script tools/check_patch.py \
  --save-output agent-answer.md

# Save assembled tool context for debugging/audit
vyper-guard agent "Review this contract" \
  --file contract.vy \
  --save-context agent-context.json

# Override explorer settings for address context
vyper-guard agent "Summarize ABI attack surface" \
  --address 0xYourContractAddress \
  --explorer-provider etherscan \
  --explorer-network sepolia \
  --explorer-api-key <explorer_key>

# Manage agent memory
vyper-guard agent-memory stats --memory-file .guardian_agent_memory.jsonl
vyper-guard agent-memory tail --memory-file .guardian_agent_memory.jsonl --limit 5
vyper-guard agent-memory clear --memory-file .guardian_agent_memory.jsonl
```

Agent mode notes:

- `agent` is strict by default: explorer/LLM failures return a non-zero exit.
- Use `--allow-fallback` only when you explicitly want deterministic fallback output.

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

## Benchmark Detector Quality

```bash
# Benchmark default corpus directory (test_contracts)
vyper-guard benchmark

# Benchmark custom corpus and print JSON metrics
vyper-guard benchmark ./contracts --format json

# Benchmark using explicit labels (override filename heuristics)
vyper-guard benchmark ./contracts --format json --labels-file labels.json

# Quality gates (fails with exit code 1 when not met)
vyper-guard benchmark ./contracts --format json --min-f1 0.70
vyper-guard benchmark ./contracts --format json --min-precision 0.80 --min-recall 0.75
vyper-guard benchmark ./contracts --format json --min-detector-f1 0.60 --min-detector-support 3
```

The benchmark output includes overall metrics and per-detector metrics
(`tp`, `fp`, `fn`, `precision`, `recall`, `f1`, `support`).

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

# Bound per-poll catch-up work and in-memory history
vyper-guard monitor 0xAddr --rpc https://rpc.url \
  --max-backfill-blocks 200 --max-history-records 20000
```

Webhook security defaults:

- Only `https://` webhook URLs are accepted.
- Local/private destinations (`localhost`, private IP ranges, `.local`, `.internal`) are blocked.

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

ai_triage:
  enabled: false
  min_severity: LOW
  max_items: 50
  policy_status: stable
  deprecation_announced: false
  deprecation_sunset_after: null
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GUARDIAN_DEFAULT_FORMAT` | Default output format (`cli`, `json`, `markdown`) |
| `GUARDIAN_SEVERITY_THRESHOLD` | Default minimum severity |
| `GUARDIAN_MAX_AUTO_FIX_TIER` | Default auto-remediation tier ceiling (`A`, `B`, `C`) |
| `GUARDIAN_TRUST_PARENT_CONFIG` | Allow `.guardianrc` auto-discovery in parent directories (`true/false`) |
| `GUARDIAN_AI_TRIAGE` | Enable AI triage by default (`true/false`) |
| `GUARDIAN_AI_TRIAGE_MIN_SEVERITY` | Minimum triage severity (`INFO..CRITICAL`) |
| `GUARDIAN_AI_TRIAGE_MAX_ITEMS` | Maximum triage rows |
| `GUARDIAN_AI_TRIAGE_POLICY_STATUS` | Triage policy status (`stable/experimental/deprecated`) |
| `GUARDIAN_AI_TRIAGE_DEPRECATION_ANNOUNCED` | Deprecation announcement flag (`true/false`) |
| `GUARDIAN_AI_TRIAGE_DEPRECATION_SUNSET_AFTER` | Policy deprecation sunset date string |
| `GUARDIAN_LLM_MEMORY_MAX_ENTRIES` | Cap persisted agent memory entries |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (no findings, or findings below threshold) |
| `1` | Findings found (in `--ci` mode) |
| `2` | Error (file not found, invalid arguments, analysis failure) |
