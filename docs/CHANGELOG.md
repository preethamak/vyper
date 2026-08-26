# Changelog

All notable changes to Vyper Guard are documented in this file.

## 2026-08-26 — v0.7.0

### Added

- Added `oracle_price_manipulation` detector (beta): flags spot-price oracle reads (AMM reserves,
  instantaneous prices, exchange rates) in state-changing functions with no staleness or TWAP guard.
- Added `missing_slippage_protection` detector (beta): flags swap/exchange calls without minimum-output
  or deadline protection (sandwich-attack exposure).
- Added `signature_replay` detector (beta): flags `ecrecover` verification lacking nonce, deadline,
  chain-id, or consumed-signature replay binding.
- Added the July-2023 reentrancy compiler advisory (`vyper-2023-07-reentrancy`) for Vyper
  0.2.15–0.3.0, gated on contracts that combine external calls with state writes — the defect class
  exploited in the Curve/stableswap incidents.
- Added new vulnerability categories `oracle_manipulation` and `front_running`.

### Fixed

- Fixed config-load test isolation: invalid-env-override tests no longer read the developer's local
  `.guardianrc`, so the suite passes from any working directory.

### Release

- Version bump to `0.7.0`. Detector count: 25 built-in detectors plus the always-on compiler advisory check.

## 2026-07-13 — v0.6.0

### Added

- Added detector maturity metadata and the `recommended` supported+beta detector profile.
- Added governed v2 baseline acceptances with required owner, reason, and optional expiry.
- Added compiler-backed remediation validation evidence and write blocking on validation failure.
- Added a pinned, SHA-256 verified production-contract calibration corpus and fetch script.
- Added a reusable composite GitHub Action for SARIF generation.
- Added a subprocess-backed Vyper JSON AST semantic engine with bounded caching and explicit
  compiler engine, version, and fallback provenance.
- Added reviewed-audit attribution (`known_issue_rediscovered`, `known_false_positive`,
  `new_candidate`) and grouped deterministic triage summaries.

### Improved

- Collapse applicable compiler advisories into one exposure summary per contract.
- Replace invalid/misattributed advisory identifiers with reviewed Vyper advisories and
  feature gates for nonreentrant locks, extremely large arrays, and multiple internal defaults.
- Resolve interface mutability, built-in ERC-20 methods, address aliases, constructor-pinned
  targets, governance-configured targets, and caller-controlled targets.
- Exclude `view` and `pure` calls from CEI and loop-call findings.
- Classify timestamp usage as accounting, protocol scheduling, authorization windows,
  state transitions, or randomness.
- Record Curve-style scheduled-slope invariants as explicit protocol assumptions.
- Limit terminal detail to a concise grouped candidate set while retaining all raw findings
  in structured reports.

### Fixed

- Kept analysis warnings on stderr so compiler fallbacks cannot corrupt JSON or other
  machine-readable output.
- Redacted API keys from LLM transport exception URLs.
- Fixed cumulative remediation patch composition and invalid decorator placement.
- Fixed generated `.guardianrc` indentation and monitor-extra rendering.
- Reduced false positives for intentional zero-address clearing, immutable initialization, and
  consumed or void interface return values.
- Reduced reentrancy false positives for stateless external calls and role-enforced setters, and
  suppressed directly guarded `unsafe_sub` operations.
- Report the actual source semantic mode when compiler mode is unavailable.

## 2026-07-07 — v0.5.1

### Added

- Added first-pass CEI/reentrancy exploit verification metadata. CEI findings now include a
  structured proof path, attacker-control hints, patch strategy, and regression-test skeleton in
  JSON output and terminal details.

### Release

- Version bump to `0.5.1`.

## 2026-06-28 — v0.5.0

### Added

- Added 10 v0.5 detectors, expanding the default detector catalog from 12 to 22.
- Added CFG-aware CEI validation for reachable external-call-before-state-write paths.
- Added cyclomatic complexity metrics to analysis context and stats graph payloads.

### Release

- Version bump to `0.5.0`.

## 2026-05-24 — v0.4.2

### Added

- Added `verify`, `test`, and `fuzz` commands to run unit/fuzz suites and emit verification reports.
- Added verification metadata to JSON/Markdown/HTML/SARIF outputs.
- Added a command manual with "what to use and when" guidance in README and docs.

### Fixed

- Fixed HTML verification table generation to remain Python 3.10 compatible.

## 2026-05-19 — v0.4.1

### Added

- Added unresolved import and interface mismatch tables to project Markdown/HTML reports.

### Release

- Version bump to 0.4.1.

## 2026-05-09 — v0.4.0

### Added

- Added project-wide analysis graph for directory scans with `--project-graph` / `analysis.project_graph`.
- Added import resolution, interface discovery, interface mismatch checks, and internal call/state maps in project graph output.
- Added project graph summaries to JSON, SARIF, Markdown, and HTML project reports.
- Added project graph findings to per-file results with severity threshold filtering.

## 2026-05-04 — v0.3.9

### Added

- Added semantic mode selection (`--semantic-mode` / `analysis.semantic_mode`) with `source` (default) and `compiler` options.
- Added optional compiler-backed semantic extraction using the Vyper AST when available, with safe fallback to source mode.
- Added semantic mode config support in `.guardianrc` and env override (`GUARDIAN_SEMANTIC_MODE`).

## 2026-04-19 — Post v0.3.6 Enhancements

### Added

- Added first-class `--format html` support for `analyze` (single-file and directory modes).
- Added `--format html` support for `analyze-address`.
- Added presentation-first HTML security reports with:
	- severity distribution bars,
	- vulnerability-type mapping matrix,
	- findings overview table,
	- detailed issue cards with explanation/evidence/remediation sections.

### Improved

- Upgraded stats graph HTML styling with a broader color palette (not purple-dominant).
- Added tabular interaction mapping in stats HTML to complement graph edges and improve readability.

## 2026-04-18 — v0.3.6

### Release

- Structured explorer and address-scan JSON output for cleaner downstream use.
- `analyze-address` now reports real explorer metadata, ABI stats, and source-language classification.
- Package version bumped for the next PyPI publication.

## 2026-04-06 — v0.3.5

### Release

- Prepared release after hardening + quality-gate pass.
- Lint/test/package checks validated for publish flow.
- Version bump to `0.3.5`.

## 2026-04-06 — Security Hardening Wave

### Security

- Detector failure transparency added end-to-end (tracked failures, explicit CRITICAL finding, degraded score trust).
- Unified scoring behavior and aligned docs with implemented tier caps + detector-failure trust penalty.
- Webhook hardening: HTTPS-only enforcement and private/local host blocking by default.
- Monitor/baseline input validation tightened for contract addresses and RPC schemes.
- Auto-remediation write flow hardened: explicit artifact-write consent + backup-before-overwrite.
- Export path hardening for JSON/Markdown outputs (symlink/non-file target refusal).
- Fingerprint hardening: full SHA-256 and line-independent normalization for better baseline stability.
- Config trust boundary tightened: parent directory config discovery now opt-in via `GUARDIAN_TRUST_PARENT_CONFIG=1`.

### Detection / Analysis

- Improved parser resilience for long multiline function signatures.
- Added support for single-quote triple-docstring block skipping.
- Strengthened external-call recognition for interface-call patterns.
- CEI detector now reports all qualifying violations, not only first-hit cases.
- Tightened access-control regex semantics to avoid negation/tautology bypasses.
- Timestamp heuristic refined to avoid broad numeric suppression.
- Unchecked subtraction heuristic tightened to reduce false-negative suppression.
- Compiler checker expanded with additional historical vulnerable exact versions.

### Monitoring Reliability

- Added bounded transaction-history retention in analyzer path.
- Added capped per-poll backfill block processing to avoid RPC flood when lagging.
- Exposed monitor/baseline CLI controls for max backfill and max history records.

### Docs

- Added hardening guide: `docs/SECURITY_HARDENING.md`.
- Updated usage guidance for secure defaults and monitor resource controls.
- Added docs index: `docs/README.md`.
- Corrected installation/development clone paths and CI examples for single-file `analyze` execution.

## 2026-03-24 — v0.3.4

### Documentation

- Expanded README with a documentation map for AI triage, agent mode, graph exports, explorer flows, and remediation paths.
- Clarified maintainer release workflow references and feature entry points.

### Release

- Version bump to `0.3.4` for publishing updated documentation alongside current AI + graph feature set.

## 2026-03-24 — v0.3.3

### Added

- Published `v0.3.3` to PyPI.
- Explorer + `analyze-address` workflow documentation and tests.
- LLM agent command family (`agent`, `agent-memory`) with optional memory/sandbox context.
- Contract `stats --graph` export improvements with richer function-flow visuals.
- Function-level behavior analytics in stats payload (control flow, internal/external calls, state read/write summaries).

### Improved

- Graph readability improvements (layered rendering, reduced connector/text overlap).
- Multi-color graph semantics for control-flow and interaction surfaces.
- CLI and test/docs consistency across AI triage, stats graphing, explorer, and remediation flows.

### Fixed

- Release/lint pipeline cleanup for current tree.
- Packaging checks validated for wheel + sdist (`twine check` pass).

## 2026-03-22

### Added

- Phase 4 AI-assisted triage kickoff with deterministic advisory metadata (`--ai-triage`).
- Triage policy controls (`min_severity`, `max_items`) with CLI/config/env support.
- Triage governance contract metadata (`ai_triage_policy`) including version/status/deprecation fields.
- CLI/Markdown triage rendering with policy and warning visibility.
- Golden output contracts for triage JSON/Markdown sections, including deprecated-policy variants.

### Guardrails

- AI triage cannot override deterministic detector verdicts.
- Triage provenance includes deterministic mode and policy version markers.
