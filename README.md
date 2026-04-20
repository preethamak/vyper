# Vyper Guard

Vyper Guard is a static security analyzer for Vyper smart contracts. It helps teams detect common vulnerability patterns, review security posture before deployment, and generate structured reports for engineering and CI workflows.

## Highlights

- Native Vyper-focused static analysis
- 12 built-in detectors across reentrancy, access control, external call safety, arithmetic risks, and compiler advisories
- Multiple report formats: CLI, JSON, Markdown, SARIF, and HTML
- Optional baseline suppression and baseline-diff workflows for CI stability
- Optional remediation mode with tiered auto-fix controls
- Explorer and on-chain analysis workflows (`explorer`, `analyze-address`)
- AI advisory triage support with explicit fallback control (`--allow-ai-fallback`)

## Installation

```bash
pip install vyper-guard
```

Verify:

```bash
vyper-guard --version
```

## Quick Start

Analyze a contract:

```bash
vyper-guard analyze contract.vy
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

## Core Commands

| Command | Purpose |
|---|---|
| `analyze <file_or_dir>` | Analyze a single contract or directory of contracts |
| `scan <file_or_dir>` | Alias for `analyze` |
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
3. `missing_event_emission`
4. `timestamp_dependence`
5. `integer_overflow`
6. `unprotected_selfdestruct`
7. `dangerous_delegatecall`
8. `unprotected_state_change`
9. `send_in_loop`
10. `unchecked_subtraction`
11. `cei_violation`
12. `compiler_version_check`

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
