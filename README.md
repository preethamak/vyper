# Vyper Guard

Vyper Guard is a static security analyzer built specifically for Vyper contracts. It parses .vy source, runs a curated detector suite, and emits structured reports for engineers and CI. The default path is offline and fast, with opt-in compiler-backed semantics when needed.

## Highlights

- Native Vyper-focused static analysis
- 12 built-in detectors across reentrancy, access control, external call safety, and arithmetic risks
- Always-on compiler version advisories (reported as `compiler_version_check`)
- Multiple report formats: CLI, JSON, Markdown, SARIF, and HTML
- Optional baseline suppression and baseline-diff workflows for CI stability
- Optional remediation mode with tiered auto-fix controls
- Optional compiler-backed semantic mode (requires `vyper` extra)
- Project-wide graph for directory scans (imports, interfaces, call/state maps)
- Explorer and on-chain analysis workflows (`explorer`, `analyze-address`)
- AI advisory triage support with explicit fallback control (`--allow-ai-fallback`)

## What is New in v0.4.2

- Added verification commands (`verify`, `test`, `fuzz`) with unified reporting.
- Added command manual guidance for when to use each CLI flow.
- Python 3.10-safe HTML verification table rendering.

## Installation

```bash
pip install vyper-guard
```

Verify:

```bash
vyper-guard --version
```

Optional compiler-backed semantic mode:

```bash
pip install vyper-guard[vyper]
```

## Quick Start

Analyze a contract:

```bash
vyper-guard analyze contract.vy
```

Verify static analysis plus tests (unit/fuzz):

```bash
vyper-guard verify contract.vy --unit-cmd "pytest -q"
```

Generate a machine-readable report:

```bash
vyper-guard analyze contract.vy --format json --output report.json
```

Generate a SARIF report for code scanning:

```bash
vyper-guard analyze contract.vy --format sarif --output report.sarif
```

Generate an HTML report:

```bash
vyper-guard analyze contract.vy --format html --output report.html
```

## Command Guide (When to Use)

Full manual: [docs/USAGE.md](docs/USAGE.md)

| Command | When to use |
|---|---|
| `analyze <file|dir>` | Static security scan for local contracts (single file or folder). |
| `verify <file|dir>` | One report that includes static analysis + unit/fuzz test results. |
| `test <file|dir>` | Run unit tests only and report verification status. |
| `fuzz <file|dir>` | Run fuzz tests only (Echidna/Foundry or custom harness). |
| `analyze-address <addr>` | Analyze verified on-chain source from a block explorer. |
| `explorer <addr>` | Fetch explorer metadata (ABI, source, verification info). |
| `diff <before> <after>` | Compare security posture between revisions. |
| `stats <file|dir>` | Engineering metrics, graph artifacts, and structure summaries. |
| `baseline` / `monitor` | Production monitoring flows for deployed contracts. |

## Core Commands

| Command | Purpose |
|---|---|
| `analyze <file>` | Analyze a single contract |
| `scan <file>` | Alias for `analyze` |
| `verify <file>` | Static analysis + unit/fuzz verification in one report |
| `test <file>` | Run unit tests and emit verification report |
| `fuzz <file>` | Run fuzz tests and emit verification report |
| `ast <file>` | Structural AST-oriented contract output |
| `flow <file>` | Function/call-flow visualization data |
| `fix <file>` | Remediation workflow |
| `stats <file>` | Contract metrics and graph artifacts |
| `diff <before> <after>` | Compare security posture between revisions |
| `explorer <address>` | Fetch verified source and ABI metadata |
| `analyze-address <address>` | Analyze explorer-fetched contract source |
| `detectors` | List detector catalog with severity/category |
| `benchmark [dir]` | Detector quality benchmark run |
| `baseline <address>` | Build monitor baseline profile |
| `monitor <address>` | Runtime monitoring and alerts |
| `help` | Full command catalog and usage hints |

## Security Scoring

Each run produces a score from 0 to 100 and a grade.

Base score is 100 with severity-based deductions:

- CRITICAL: -40 points (capped at -50)
- HIGH: -20 points (capped at -40)
- MEDIUM: -8 points (capped at -20)
- LOW: -3 points (capped at -10)
- INFO: -1 point (capped at -5)

Additional trust penalty:

- Detector runtime failures: -10 each (capped at -30)

## Detector Catalog

1. `missing_nonreentrant`
2. `unsafe_raw_call`
3. `unchecked_send`
4. `missing_event_emission`
5. `timestamp_dependence`
6. `integer_overflow`
7. `unprotected_selfdestruct`
8. `dangerous_delegatecall`
9. `unprotected_state_change`
10. `send_in_loop`
11. `unchecked_subtraction`
12. `cei_violation`

Compiler advisories are always evaluated and reported as `compiler_version_check` findings.

## Remediation

Use remediation mode for guided fixes:

```bash
vyper-guard analyze contract.vy --fix
```

Limit remediation scope by risk tier:

```bash
vyper-guard analyze contract.vy --fix --max-auto-fix-tier B
```

Dry-run remediation:

```bash
vyper-guard analyze contract.vy --fix-dry-run --fix-report remediation-report.json
```

## License

MIT. See LICENSE.

## Disclaimer

Vyper Guard is a static analysis aid and does not guarantee absence of vulnerabilities. Use it together with manual review, testnet validation, and professional audits for high-value deployments.
