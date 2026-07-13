# Vyper Guard

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/vyper-guard?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=ORANGE&left_text=downloads)](https://pepy.tech/projects/vyper-guard)
[![Socket Badge](https://badge.socket.dev/pypi/package/vyper-guard/0.6.0?artifact_id=tar-gz)](https://badge.socket.dev/pypi/package/vyper-guard/0.6.0?artifact_id=tar-gz)

**Static security analyzer for Vyper smart contracts.**

Vyper Guard scans .vy sources, runs a focused detector suite, and emits structured security reports for auditors, developers, and security teams. It is designed for fast local analysis with optional compiler-backed semantics and verification workflows.

Website: https://vyper-web.vercel.app

## What's new in 0.6.0

Vyper Guard 0.6.0 is a precision and trust release for professional security workflows:

- **Lower-noise analysis:** improved call-target, mutability, timestamp, arithmetic, access-control,
  and legacy Vyper reasoning reduces avoidable findings on production contracts.
- **Clearer trust signals:** reports now identify semantic-engine provenance, detector maturity,
  degraded analysis, protocol assumptions, and reviewed audit attribution.
- **Safer remediation:** compiler-backed validation blocks writes when a generated patch does not
  validate, while governed baseline acceptances require ownership and rationale.
- **Audit-focused output:** concise terminal triage highlights actionable candidates while JSON,
  Markdown, SARIF, and HTML retain the full evidence set.
- **Reproducible quality evidence:** pinned production-contract corpora, detector quality gates,
  and an [evidence-backed Curve DAO benchmark](https://github.com/preethamak/vyper/blob/main/benchmarks/results/curve-dao-trail-of-bits-2020.md)
  make current coverage and limitations explicit.
- **CI-ready distribution:** a reusable GitHub Action generates SARIF for code-scanning and
  regression workflows.

See the [changelog](https://github.com/preethamak/vyper/blob/main/docs/CHANGELOG.md) for the
complete release notes.

## Who it is for

- Auditors and auditing companies
- Protocol and dApp developers
- Security and engineering teams

## Primary use cases

- Pre-audit security scans
- CI security gates and regression checks
- Learning and reviewing Vyper security patterns

## Features

- Vyper-focused static analysis for .vy contracts
- 22 built-in detectors with explicit supported, beta, and experimental maturity labels
- Always-on compiler advisories (`compiler_version_check`)
- Multiple report formats: CLI, JSON, Markdown, SARIF, HTML
- Verification workflows for unit and fuzz tests (`verify`, `test`, `fuzz`)
- Baseline suppression and baseline-diff for CI stability
- Optional remediation mode with tiered auto-fix controls
- Optional compiler-backed semantic mode (install `vyper` extra)
- Compiler semantics can also use a `vyper` executable on PATH, with engine, version, and fallback provenance in reports
- CFG-aware CEI analysis plus cyclomatic complexity metrics in reports and `stats`
- Project-wide graph for directory scans (imports, interfaces, call/state maps)
- Explorer and on-chain analysis workflows (`explorer`, `analyze-address`)
- Deterministic priority scoring with governance notes and explicit fallback controls (`--allow-ai-fallback`)

## Installation

Python 3.10+ is required.

```bash
pip install vyper-guard
```

Optional extras:

```bash
pip install vyper-guard[vyper]       # compiler-backed semantics
pip install vyper-guard[monitor]     # on-chain monitoring (web3 + aiohttp)
pip install vyper-guard[remediation] # GitHub remediation support
pip install vyper-guard[all]         # all optional features
```

Verify:

```bash
vyper-guard --version
```

## Quickstart

Analyze a contract:

```bash
vyper-guard analyze contract.vy
```

For the lower-noise supported and beta profile:

```bash
vyper-guard analyze contract.vy --detectors recommended
```

`--detectors all` preserves the complete legacy detector set, including
experimental rules. Detector maturity describes validation evidence, not issue
severity.

Verify static analysis plus tests:

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

## Command guide (when to use)

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

## Core commands

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

## Verification (unit + fuzz)

Use `verify` for a single report that includes static findings plus unit/fuzz results. Use `test` or `fuzz` to run them independently.

```bash
vyper-guard verify contract.vy --unit-cmd "pytest -q"
vyper-guard fuzz contract.vy --fuzz-cmd "your-fuzz-command"
```

You can also set defaults via environment variables:

```bash
export GUARDIAN_UNIT_CMD="pytest -q"
export GUARDIAN_FUZZ_CMD="your-fuzz-command"
```

## Configuration

Configuration is loaded in this order:
1. CLI flags
2. Environment variables
3. `.guardianrc` in the current directory (or `.guardianrc.yaml`, `.guardianrc.yml`)
4. `~/.guardianrc`

Create a starter config:

```bash
vyper-guard init
```

Example verification config:

```yaml
verification:
  unit_command: ["pytest", "-q"]
  fuzz_command: ["your-fuzz-command"]
  timeout_seconds: 600
  max_output_chars: 20000
```

Explorer and LLM keys are read from environment variables:

```bash
export GUARDIAN_EXPLORER_API_KEY="..."
export GUARDIAN_LLM_API_KEY="..."
```

## Output formats

Use `--format` and `--output` for structured reports:

```bash
vyper-guard analyze contract.vy --format json --output report.json
vyper-guard analyze contract.vy --format sarif --output report.sarif
vyper-guard analyze contract.vy --format html --output report.html
```

Supported formats: `cli`, `json`, `markdown`, `sarif`, `html`.

## Security scoring

Each run produces a backward-compatible heuristic risk indicator from 0 to 100
and a grade. It measures detected heuristic risk, not contract safety or
deployment readiness. Structured reports also include `analysis_trust` with
compiler coverage, detector maturity, degradation reasons, and limitations.

Base score is 100 with severity-based deductions:

- CRITICAL: -40 points (capped at -50)
- HIGH: -20 points (capped at -40)
- MEDIUM: -8 points (capped at -20)
- LOW: -3 points (capped at -10)
- INFO: -1 point (capped at -5)

Additional trust penalty:

- Detector runtime failures: -10 each (capped at -30)

## Detector catalog

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
13. `tx_origin_auth`
14. `missing_zero_address_check`
15. `weak_randomness`
16. `locked_ether`
17. `shadowed_state_variable`
18. `missing_input_validation`
19. `unsafe_assembly`
20. `missing_return_value`
21. `division_before_multiplication`
22. `incorrect_erc20_return`

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
