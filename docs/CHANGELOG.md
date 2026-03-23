# Changelog

All notable changes to Vyper Guard are documented in this file.

## 2026-03-24 — v0.3.3

### Added

- Published `v0.3.3` to PyPI.
- Explorer + `analyze-address` workflow documentation and tests.
- LLM agent command family (`agent`, `agent memory`) with optional memory/sandbox context.
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
