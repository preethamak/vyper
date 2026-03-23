# Vyper Guard — Master Implementation Phases (Research + Execution Plan)

Date: 2026-03-22
Owner: Project Maintainer
Mode: Active implementation (phase-gated)

## Current Status

- Active phase: Phase 5 — Remediation Safety + Validation (kickoff)
- State: In progress
- Completed in this tranche:
  - Lightweight metadata loading checks added for bundled JSON files
  - Added a lightweight `benchmark` command and corpus benchmark runner for quality tracking
  - Added benchmark JSON contract test for output schema and metrics fields
  - Added explainability payload fields on findings (`why_flagged`, `evidence`, `why_not_suppressed`)
  - Wired explainability fields into JSON and Markdown reporting
  - Added explainability tests for analyzer + JSON export
  - Added deterministic detector confidence calibration policy in analysis pipeline
  - Added confidence policy tests (compiler/info and high-signal detector floors)
  - Added per-detector benchmark metrics (`tp`, `fp`, `fn`, `precision`, `recall`, `f1`, `support`)
  - Wired per-detector benchmark metrics into CLI and JSON benchmark outputs
  - Added external labels adapter (`--labels-file`) for benchmark expected outcomes
  - Added benchmark labels-file tests and docs
  - Added benchmark quality gate thresholds (`--min-precision`, `--min-recall`, `--min-f1`, `--min-detector-f1`)
  - Added benchmark gate-based exit behavior (exit code 1 on unmet configured gates)
  - Full suite validation completed after changes (`200+ passed`)
  - Added initial semantic summary extractor (function reads/writes, external calls, delegatecall/event signals)
  - Added semantic extractor tests
  - Wired semantic summary into findings as `semantic_context`
  - Exposed `semantic_context` in JSON and Markdown reporting
  - Added semantic context pipeline/export tests
  - Migrated initial high-impact detectors to semantic-first gating:
    - `cei_violation`
    - `dangerous_delegatecall`
    - `unprotected_state_change`
    - `missing_nonreentrant`
    - `unsafe_raw_call`
  - Migrated storage-sensitive compiler advisory pattern gating to semantic summary (`uses_dynarray_in_mapping`)
  - Added multiline `HashMap[..., DynArray[...]]` detection coverage for GHSA-vxmm checks
  - Refined CEI call/order reasoning to scan interaction→effect windows across full function flow
  - Added CEI regression coverage for mixed multi-interaction ordering
  - Added semantic signal for external calls inside loops (`external_calls_in_loop`)
  - Migrated `send_in_loop` detector to semantic-first gating with existing bounded-loop suppression preserved
  - Migrated `missing_event_emission` detector to semantic-first gating (state-write + event signals)
  - Kept source-order checks as secondary pass for precise line-local findings
  - Phase 4 kickoff: added optional deterministic AI-assisted triage post-processor (`--ai-triage`)
  - Added triage provenance guardrails (`deterministic`, `model=None`, `can_override_verdict=False`)
  - Added AI triage tests ensuring detector findings are not mutated
  - Added markdown triage rendering section (advisory guardrail + ranked triage table)
  - Added rich CLI triage rendering section for `analyze --ai-triage`
  - Added renderer tests for markdown and CLI triage visibility
  - Added triage policy controls (`min_severity`, `max_items`) in post-processor
  - Added CLI policy flags (`--ai-triage-min-severity`, `--ai-triage-max-items`) and explicit enable/disable switch
  - Added config + env policy surface (`ai_triage.*`, `GUARDIAN_AI_TRIAGE_*`)
  - Added policy/config tests for AI triage behavior and precedence
  - Added deterministic triage scoring rationale payload (`triage_scoring_v1`, base/bonus/final factors)
  - Added CLI/Markdown triage scoring visibility for policy transparency
  - Added scoring rationale tests and docs updates
  - Added AI triage export contracts (JSON payload + markdown section golden fixtures)
  - Added golden tests for triage export stability and schema surface
  - Added triage policy contract metadata (`policy_version`, `status`, deprecation block)
  - Added policy version provenance on each triage item
  - Exposed policy contract in JSON report (`ai_triage_policy`) and markdown/CLI triage headers
  - Added governance assertions in analyzer and golden reporter tests
  - Added executable spec/CI contract checks for triage governance invariants (version/status/determinism/deprecation schema)
  - Updated usage docs with triage policy deprecation lifecycle fields
  - Added policy status transition controls (`stable/experimental/deprecated`) and deprecation date handling
  - Surfaced policy warnings in CLI and markdown triage output
  - Added transition/deprecation warning tests (processor + config-driven CLI path)
  - Added deprecated-policy golden contracts for `ai_triage_policy` JSON and markdown triage section
  - Added exporter golden tests for deprecation policy contract stability
  - Added `docs/CHANGELOG.md` with latest Phase 4 triage governance release notes
  - Added executable changelog validation checks in spec contracts test suite
  - Phase 5 kickoff prep: added remediation risk tiers (A/B/C) in fix generation pipeline
  - Added risk-tier labeling in `--fix` CLI output
  - Added remediation tests validating risk-tier assignment for representative detectors
  - Added `--max-auto-fix-tier` gating for auto-remediation scope control
  - Added fix-mode policy behavior for skipping higher-risk tiers with explicit CLI reporting
  - Added CLI remediation tests for tier filtering and invalid tier input handling
  - Added remediation policy contract metadata (`policy_version`, tier set, detector-tier map)
  - Added executable policy validation checks (handler/tier mapping integrity)
  - Added remediation governance assertions in reporting spec tests
  - Added remediation config policy surface (`remediation.max_auto_fix_tier`) in `.guardianrc`
  - Added env override for remediation auto-fix tier (`GUARDIAN_MAX_AUTO_FIX_TIER`)
  - Added CLI precedence wiring so `--max-auto-fix-tier` falls back to config/env defaults
  - Added remediation CLI tests for config default + explicit CLI override precedence
  - Added remediation tier guardrail contract (`tier_rules`, planning contract metadata)
  - Added deterministic remediation planning contract (`eligible_by_tier`, `skipped_by_tier`, totals)
  - Added fix-result tier validation checks to enforce advisory/manual semantics for tier C
  - Added CLI fix-mode plan visibility (tier-cap eligible/skipped summary)
  - Added remediation/spec tests for tier rules, planning contract, and result validation
  - Hardened `analyze` runtime behavior with structured fallback reporting for unexpected analyzer exceptions
  - Added CLI contract test to guarantee JSON fallback output contract (`analyzer_runtime_error`) instead of hard failure
  - Added remediation dry-run mode (`--fix-dry-run`) so users can preview diffs without writing patched files
  - Added CLI remediation tests validating dry-run no-write behavior and implicit fix-mode activation
  - Added remediation report export (`--fix-report`) with deterministic planning/execution JSON artifact
  - Added CLI remediation tests for fix-report contract and option validation behavior
  - Added optional LLM triage mode for `analyze` (`--ai-triage-mode llm`) with OpenAI-compatible API calls
  - Added deterministic fallback to built-in triage when LLM is unavailable/misconfigured
  - Added explorer lookup command (`vyper-guard explorer`) for contract metadata, ABI, functions, and source export
  - Added explorer-source scanning command (`vyper-guard analyze-address`) to analyze verified on-chain contracts directly by address
  - Added agent command (`vyper-guard agent`) with memory file support and optional Python sandbox helper execution
  - Added configuration surface for LLM and explorer providers/keys via config and env
  - Integrated API setup defaults into generated `.guardianrc` template for LLM and explorer workflows
  - Added LLM API integration tests for successful call path and env-driven key loading
  - Added tests for LLM-mode fallback behavior, explorer client/CLI contracts, and analyze-address flow
  - Enhanced `vyper-guard agent` with explorer override flags and context export (`--save-context`)
  - Added `vyper-guard agent-memory` command (`tail`, `stats`, `clear`) for persistent memory management
  - Added agent CLI tests for context export, explorer-context path, and memory lifecycle operations
  - Added user-facing `--ai` alias on `analyze` while preserving legacy `--ai-triage*` compatibility flags
  - Added new `ast` command with `cli/json/markdown/mermaid` structural output modes
  - Added new `flow` command with `cli/json/markdown/mermaid` function-flow output modes
  - Added dedicated `fix` command wrapper preserving existing tier-gated remediation behavior
  - Added CLI unification tests for `--ai`, `ast`, `flow`, and `fix` command paths
  - Added `vyper-guard ai config` command group (`set`, `show`) for terminal-first provider/model/key setup
  - Added AI config tests for set/show roundtrip, interactive api-key prompt, and invalid key handling
  - Updated help/docs with AI config command usage examples
  - Added explorer provider fallback chain (`auto`: etherscan → blockscout → sourcify) with resolved provider surfaced in CLI output
  - Added explorer fallback tests for provider failover and unknown provider validation
  - Added `stats --graph` export mode with JSON + HTML artifact generation (`--graph-json`, `--graph-html` overrides)
  - Added stats graph CLI tests for default and custom artifact paths
  - Added `explorer config set/show` terminal UX (`provider`, `network`, `api-key`) with hidden API key prompt + redacted show output
  - Added explorer config CLI tests for set/show roundtrip and unknown-key validation
  - Executed final verification runbook command matrix and refreshed CLI audit artifact (`docs/.cli_audit_results.json`)
  - Verified explorer + analyze-address runbook commands using a live verified address with `--provider blockscout --network ethereum`
  - Hardened detector regex matching (delegatecall boolean variants, `raw_call` safety signals, timestamp-condition matching, comment-safe parsing)
  - Added detector regressions for `revert_on_failure=True` and lowercase delegatecall booleans
  - Full suite validation completed after changes (`272 passed`)
- Next phase candidate: Release packaging and distribution cutover

### Release Notes (Latest)

- Added AI triage policy transition controls (`stable`, `experimental`, `deprecated`).
- Added deprecation lifecycle metadata (`announced`, `sunset_after`) and surfaced warnings in CLI/Markdown triage views.
- Added governance contract assertions and policy/version stability checks in executable specs.
- Added golden contracts for deprecated-policy JSON/Markdown triage outputs.

---

## 1) Executive Take

Your current project is **strong for a V1 pattern-based scanner**, but not yet enough for broad “trust at scale” adoption like Slither/Mythril.

The core issue is not effort or intent — it is **analysis depth + consistency + ecosystem readiness**.

Right now, the engine is mostly regex/source-pattern based. That is useful, fast, and developer-friendly, but in real-world contracts it will eventually hit limits:

- path-sensitive logic
- inter-function/inter-contract dataflow
- upgradeability/storage-collision classes
- protocol-specific invariants
- low-noise triage in large repos

**Conclusion:** keep the current engine, but evolve to a **hybrid architecture**:

1. Fast deterministic rule layer (what you already have)
2. Semantic/IR/AST layer for precise reasoning
3. Optional deeper symbolic / execution-assisted layer
4. AI-assisted triage/fix explanation layer with strict guardrails

This gives speed + precision + explainability.

---

## 2) What Was Audited

Reviewed repository areas:

- Core package under src/guardian
- CLI and entry points
- Analyzer / remediation / monitor / reporting / utils
- JSON DB/rule/template files
- Docs and examples
- Tests and fixture contracts
- Test corpus in test_contracts
- Packaging and CI configuration

Primary reference files:

- README.md
- pyproject.toml
- Dockerfile
- docs/USAGE.md
- docs/DETECTORS.md
- docs/INSTALLATION.md
- src/guardian/cli.py
- src/guardian/analyzer/*
- src/guardian/remediation/*
- src/guardian/monitor/*
- src/guardian/reporting/*
- src/guardian/db/*
- tests/*

---

## 3) Reality Check: Will Regex-Heavy Analysis Work in Real World?

### Short answer
**Partially yes** (quick wins, obvious anti-patterns), but **not sufficient alone** for institutional-grade security confidence.

### Why it still helps
- Fast feedback in CI
- Very low setup friction
- Good for common anti-pattern families
- Good educational tooling for teams new to Vyper security

### Where it breaks
- Context-sensitive checks spanning functions/modules
- Path-dependent authorization/invariant logic
- Alias/dataflow ambiguity (`self` state touched indirectly)
- Complex safe patterns causing false positives
- Hidden exploitability requiring execution traces

### Industry baseline insight
- Slither’s differentiator is IR + detector ecosystem + mature integrations.
- Mythril’s differentiator is symbolic execution depth.
- Semgrep’s differentiator is scalable rule ops + triage workflows + policy controls.

**Your path to be “more than that”:** combine Vyper-native semantic depth + remediation + runtime monitoring feedback loops.

---

## 4) CLI Surface Audit (Executed)

Commands tested against local environment:

| Command | Status | Exit | Notes |
|---|---:|---:|---|
| `vyper-guard` | ✅ | 0 | Branded help screen works |
| `vyper-guard --version` | ✅ | 0 | Prints version |
| `vyper-guard version` | ✅ | 0 | Works |
| `vyper-guard detectors` | ✅ | 0 | Lists detectors |
| `vyper-guard analyze <file>` | ✅ | 0 | Works |
| `vyper-guard analyze <file> --format json` | ✅ | 0 | Works |
| `vyper-guard analyze <file> --format markdown` | ✅ | 0 | Works |
| `vyper-guard analyze <file> --ci -s HIGH` | ✅ | 1 | Correct CI-fail behavior |
| `vyper-guard scan <file>` | ✅ | 0 | Alias works |
| `vyper-guard stats <file>` | ✅ | 0 | Works |
| `vyper-guard diff <a> <b>` | ✅ | 0 | Works |
| `vyper-guard init` | ⚠️ | 1 | Fails if `.guardianrc` exists (expected) |
| `vyper-guard init --force` | ✅ | 0 | Works |
| `vyper-guard monitor ...` | ⚠️ | 2 | Fails due missing `web3` extra (expected in this env) |
| `vyper-guard baseline ...` | ⚠️ | 2 | Fails due missing `web3` extra (expected in this env) |
| `vyper-guard analyze <file> --fix` | ✅ | 0 | Works; interactive prompt appears |

### CLI issues found
1. Rich markup strips bracketed extras in error hints (`vyper-guard[monitor]` appears as plain `vyper-guard`).
2. Docs claim folder scan (`analyze contracts/`), but CLI rejects directories (expects `.vy` file).
3. Config fields exist but some are not applied in CLI flow (see risk list below).

---

## 5) Key Strengths

1. **Good modular separation**: analyzer/remediation/monitor/reporting boundaries are clean.
2. **Developer UX**: Typer + Rich experience is polished.
3. **Practical remediation flow**: fix previews + patch output are useful.
4. **Good baseline testing volume** across detector and remediation behavior.
5. **Optional monitoring architecture** already present (good future differentiator).
6. **Simple packaging and CI** with uv + multi-python matrix.

---

## 6) Critical Risks / Gaps To Fix First

### Product correctness
1. **Doc/implementation drift**:
   - Detector severities differ across docs/code/JSON.
   - Scoring formulas differ between docs and code.
2. **Config drift**:
   - `analysis.severity_threshold` and reporting defaults are not fully honored in analyze path.
3. **Rule metadata drift**:
   - DB JSON states don’t fully match detector logic (stale semantics).

### Analysis depth
4. Pattern-only detector layer will struggle with precision/recall on complex protocols.
5. No compiler-backed semantic layer by default.
6. No path-sensitive dataflow engine.

### Trust/adoption
7. Missing public benchmark harness against known datasets + comparable tools.
8. No SARIF output for first-class code scanning workflows.
9. Limited test guarantees for CLI/reporting parity; test_reporting has no source tests.

### Engineering hygiene
10. Some dead/stale artifacts and drift hints (pycache references to removed tests, stale docs assumptions).

---

## 7) Master Phase Plan (Do Not Implement Until Requested)

## Phase 0 — Spec Freeze & Truth Alignment (2–3 days)

Goal: make one source of truth for behavior.

Deliverables:
- Detector catalog contract (name, severity policy, confidence policy, rationale).
- Score model contract (single formula).
- CLI contract (commands/flags/exit codes/stdout-stderr policy).
- Config contract (every key wired or removed).

Gate to pass:
- Docs, code, and JSON metadata are mathematically consistent.

---

## Phase 1 — Reliability Hardening (4–7 days)

Goal: stabilize behavior before adding complexity.

Work items:
- Fix config application gaps in analyze path.
- Fix monitor extras install hint escaping in Rich output.
- Add lightweight readability checks for DB JSON files in tests.
- Add missing tests for reporting module and CLI edge cases.
- Add golden-output tests for JSON/Markdown/CLI exports.

Gate to pass:
- All tests green + no known behavior drift between docs and runtime.

---

## Phase 2 — Detector Quality Upgrade (1–2 weeks)

Goal: materially reduce false positives/negatives.

Work items:
- Introduce detector quality metrics (precision, recall, FPR) per detector.
- Build benchmark runner using curated corpus (`test_contracts` + external known vulnerable/safe sets).
- Add explainability payload per finding (`why_flagged`, `evidence`, `why_not_suppressed`).
- Add detector confidence calibration policy.

Gate to pass:
- Published benchmark report and quality thresholds per release.

---

## Phase 3 — Semantic Analysis Layer (2–4 weeks)

Goal: move beyond regex-only logic.

Work items:
- Add optional compiler-assisted parsing/semantic extraction for supported Vyper versions.
- Build intermediate semantic model (CFG-lite + state write/read sets + call edges).
- Migrate high-impact detectors to semantic engine first:
  - reentrancy/CEI
  - access control
  - unsafe external call handling
  - storage-sensitive compiler bug patterns

Gate to pass:
- Semantic mode improves benchmark quality without unacceptable runtime regressions.

---

## Phase 4 — AI-Assisted Analysis/Triage (1–2 weeks)

Goal: use AI where it adds value, not where deterministic logic is mandatory.

Work items:
- Add AI as optional post-processor only:
  - triage suggestion
  - exploitability ranking
  - remediation explanation
  - fix rationale generation
- Keep detector verdict deterministic; AI cannot silently alter detector truth.
- Add strict prompt and output schema + provenance fields.

Guardrails:
- AI outputs must include confidence and evidence references.
- No auto-apply from AI without deterministic validator pass.

Gate to pass:
- AI improves triage throughput while keeping false action risk bounded.

---

## Phase 5 — Advanced Remediation Engine (2–4 weeks)

Goal: safer and higher-confidence autofix.

Work items:
- Multi-pass patch planner with conflict resolution.
- Function-level rewrite safety checks.
- Optional compile/lint validation gate post-fix.
- Risk tiering:
  - Tier A: safe auto-apply
  - Tier B: suggested patch only
  - Tier C: explanation-only

Gate to pass:
- Auto-fix success and non-regression metrics are published.

---

## Phase 6 — Ecosystem Integrations (1–2 weeks)

Goal: adoption and platform fit.

Work items:
- SARIF exporter.
- GitHub Action + reusable workflow templates.
- pre-commit hook validation docs aligned with release tags.
- Baseline + differential scan mode for PRs.

Gate to pass:
- One-command CI onboarding in under 10 minutes.

---

## Phase 7 — Community-Grade Release Program (ongoing)

Goal: become dependable for the broader Vyper ecosystem.

Work items:
- Versioned detector policy and deprecation policy.
- Security disclosure and response process.
- Public roadmap + issue labels + contribution guide improvements.
- Comparative benchmark page vs Slither/Mythril on Vyper scenarios.

Gate to pass:
- External contributors can add detector/fix safely with clear standards.

---

## 8) “Beyond Slither/Mythril” Differentiation Plan

You should not try to beat them by copying feature count only.

Unique value to build:
1. **Vyper-first semantics and advisories** (compiler-version-aware, idiom-aware).
2. **Integrated auto-remediation** with validation tiers.
3. **Static + runtime loop** (monitor anomalies feeding static detector priorities).
4. **Contract lifecycle UX**: write → scan → fix → baseline → monitor → verify.
5. **Human-readable + machine-actionable parity** (CLI + JSON + Markdown + SARIF).

---

## 9) Backlog of Concrete Fixes (Priority Order)

P0 (immediate):
1. Align scoring formulas across code/docs/DB.
2. Align detector severity definitions across code/docs/DB.
3. Wire config keys actually used (or remove dead keys).
4. Fix monitor extras install hint rendering.
5. Correct docs claiming folder scan support.

P1:
6. Add test_reporting source tests.
7. Add command contract tests for every CLI command/flag.
8. Add schema tests for JSON db files.
9. Add benchmark harness and baseline metrics.

P2:
10. Build semantic model and migrate top detectors.
11. Add SARIF output and GitHub code scanning path.
12. Add differential scan mode for PRs.

P3:
13. AI triage/copilot mode with guardrails.
14. Advanced remediation planner and conflict handling.
15. Runtime-monitor feedback integration into static risk scoring.

---

## 10) Phase Execution Protocol (for future instructions)

When you say “move to next phase”, implementation should follow this strict cycle:

1. Phase kickoff checklist
2. File-level design proposal
3. Targeted implementation
4. Tests + command verification
5. Phase report (done/not-done/known-risk)
6. Wait for your approval before the next phase

No cross-phase scope creep unless explicitly approved.

---

## 11) Final Recommendation

Yes — this project can absolutely become community-grade and widely used.

But success depends on sequencing:

- First: **consistency and trust**
- Then: **analysis depth**
- Then: **ecosystem and scale**
- Then: **AI acceleration with guardrails**

If executed in this order, you can build a Vyper-native security toolchain that is not only comparable to existing tools, but differentiated by remediation + runtime feedback + developer workflow quality.

## 12) Locked Command Matrix (Must Exist, Must Work)

This is the final command contract for public release.  
No command here should be missed during implementation.

### A. Core analysis
- `vyper-guard analyze <contract.vy>`
  - Full deterministic scan: regex + semantic/AST + compiler advisories.
- `vyper-guard analyze <contract.vy> --ai`
  - AI-assisted audit orchestration over deterministic findings.

### B. Structural inspection
- `vyper-guard ast <contract.vy> [--format json|markdown|mermaid]`
  - AST/semantic structure view.
- `vyper-guard flow <contract.vy> [--format json|markdown|mermaid]`
  - Function/call-flow summary and ordering context.

### C. Remediation
- `vyper-guard fix <contract.vy> [--ai] [--fix-dry-run] [--max-auto-fix-tier A|B|C] [--fix-report <path.json>]`
  - Safe remediation pipeline with tier gates and report export.

### D. Metrics / Stats (explicitly required)
- `vyper-guard stats <contract.vy>`
  - Terminal analytics summary.
- `vyper-guard stats <contract.vy> --graph`
  - Export metrics + graph artifacts (JSON + HTML).

### E. Explorer + on-chain source analysis
- `vyper-guard explorer <address>`
  - Contract metadata, ABI, functions, source (if verified).
- `vyper-guard analyze-address <address>`
  - Fetch verified source from explorer providers and run analysis pipeline.

### F. AI configuration (terminal-first for pip users)
- `vyper-guard ai config set provider <provider>`
- `vyper-guard ai config set model <model>`
- `vyper-guard ai config set api-key` (hidden prompt)
- `vyper-guard ai config show`

### G. Explorer configuration
- `vyper-guard explorer config set provider <provider>`
- `vyper-guard explorer config set api-key` (hidden prompt)
- `vyper-guard explorer config show`

### H. Existing utility/ops commands (keep working)
- `vyper-guard detectors`
- `vyper-guard diff <before.vy> <after.vy>`
- `vyper-guard benchmark <corpus_dir>`
- `vyper-guard monitor ...`
- `vyper-guard baseline ...`
- `vyper-guard init`
- `vyper-guard version` / `vyper-guard --version`

### I. Backward compatibility aliases (must not break now)
- `vyper-guard scan <contract.vy>` (alias of analyze)
- `--ai-triage`, `--ai-triage-mode` (legacy aliases under `analyze --ai` flow)

---

## 13) Final Verification Runbook (Execute Before Release)

Run all commands below at end of implementation and record pass/fail.

1. Version/help:
- `vyper-guard --version`
- `vyper-guard -h`

2. Core:
- `vyper-guard analyze test_contracts/01_reentrancy_vault.vy`
- `vyper-guard analyze test_contracts/01_reentrancy_vault.vy --ai`
- `vyper-guard analyze test_contracts/01_reentrancy_vault.vy --format json`
- `vyper-guard analyze test_contracts/01_reentrancy_vault.vy --format markdown`

3. AST/Flow:
- `vyper-guard ast test_contracts/01_reentrancy_vault.vy --format json`
- `vyper-guard flow test_contracts/01_reentrancy_vault.vy --format mermaid`

4. Fix:
- `vyper-guard fix test_contracts/01_reentrancy_vault.vy --fix-dry-run --max-auto-fix-tier B`
- `vyper-guard fix test_contracts/01_reentrancy_vault.vy --ai --fix-dry-run --fix-report /tmp/fix-report.json`

5. Stats:
- `vyper-guard stats test_contracts/01_reentrancy_vault.vy`
- `vyper-guard stats test_contracts/01_reentrancy_vault.vy --graph`

6. Explorer:
- `vyper-guard explorer <verified_address> --provider blockscout --network ethereum --format json`
- `vyper-guard analyze-address <verified_address> --provider blockscout --network ethereum --format json`

7. Backward compatibility:
- `vyper-guard scan test_contracts/01_reentrancy_vault.vy`
- `vyper-guard analyze test_contracts/01_reentrancy_vault.vy --ai-triage`

8. Regression:
- `python -m pytest -q`

Release gate: all above must pass, no regressions, docs match behavior.
