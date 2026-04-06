# Changelog

All notable changes to Vyper Guard are documented in this file.

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
