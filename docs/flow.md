<!-- ...existing code... -->

---

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


## 14) Implementation Tracker (Do Not Skip)

| Area | Task | Status | Tests Added | Verified Command |
|---|---|---|---|---|
| CLI unification | `--ai`, `ast`, `flow`, `fix` | Done | Yes | Yes |
| AI config | `ai config set/show` | Done | Yes | Yes |
| Explorer fallback | Etherscan→Blockscout→Sourcify | Done | Yes | Yes |
| Explorer config | `explorer config set/show` | Done | Yes | Yes |
| Stats graph | `stats --graph` JSON+HTML | Done | Yes | Yes |
| Regex hardening | Safer detector regex + semantic alignment | Done | Yes | Yes |

---

## 15) Backward Compatibility Checklist

- [x] `scan` alias still works
- [x] `--ai-triage` still works as alias
- [x] `--ai-triage-mode` still works as alias
- [x] Existing JSON output fields unchanged (additive only)
- [x] Existing markdown output remains compatible

---

## 16) Release Blockers (Must Pass)

- [x] All commands in Section 12 pass
- [x] Final Verification Runbook (Section 13) fully green
- [x] Full test suite green (`272 passed`)
- [x] Docs match exact runtime behavior
- [x] No crash paths on invalid input or missing API keys

---

## 17) Decision Log (Anti-Drift)

- Keep user-facing AI switch as `--ai` only.
- Keep legacy AI flags as hidden compatibility aliases.
- Prefer terminal-first config for pip users.
- No removals in this release cycle; deprecate first, remove later.

## 18) Locked Follow-up Scope (Post-Release, Do Not Forget)

### A) Confirmed implementation status
- Sections 12–17 are the release contract and are complete.
- Keep this contract stable for v1 release.

### B) OpenAI-only policy (current)
- AI provider scope for now: **OpenAI only**.
- `--ai` remains the user-facing switch.
- Native multi-provider SDK adapters are deferred to a later phase.

### C) Detector quality direction (critical)
- Regex/decorator matching is **not sufficient alone** for real-world coverage.
- Continue moving high-impact detections to semantic/AST-confirmed logic.
- Regex remains prefilter/candidate signal, semantic checks remain confirmation layer.
- Latest hardening pass completed: improved `raw_call` safety detection, delegatecall boolean matching, timestamp conditional matching, and comment-safe line parsing.

### D) Next implementation phase (Phase 6 candidate)
1. Detector hardening:
   - Cross-function state-flow checks
   - Auth-path reasoning
   - Call-order and reentrancy-window depth
2. AI quality hardening:
   - Better grounding/provenance in `--ai` output
   - Strong schema validation and fallback behavior
3. Remediation reliability:
   - Validator gates before apply
   - Stronger fix confidence reporting
4. Packaging/public readiness:
   - Install smoke tests from clean environment
   - Support matrix docs (OS/Python/deps)

### E) Non-breaking policy (must keep)
- No removals of existing commands/flags in this cycle.
- Legacy aliases remain functional.
- Output schema changes must be additive only.

### F) Final release reminder
Before publish, re-run Section 13 commands and full regression:
- `python -m pytest -q`
- All release blockers in Section 16 must remain green.

<!-- ...existing code... -->