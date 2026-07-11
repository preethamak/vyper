# Vyper Guard Commercial Product Boundary

## Product statement

Vyper Guard is a compiler-aware security regression and policy system for
Vyper teams. It does not claim to replace a professional audit.

## Open core

The local CLI remains useful without an account:

- Source and compiler-backed analysis.
- Supported, beta, and experimental detector profiles.
- JSON, SARIF, Markdown, and HTML exports.
- Local baselines and reviewed risk acceptances.
- Public GitHub Action integration.
- Public detector specifications and quality measurements.

## Paid product

Teams pay for workflow and maintained security knowledge:

- Private-repository GitHub App installation.
- Pull-request annotations and new-finding-only review.
- Finding ownership, comments, status, reason, and expiry.
- Organization policy packs and protocol-specific rules.
- Historical posture, rule performance, and audit evidence.
- Supported onboarding, rule tuning, and response SLAs.
- Dedicated or self-hosted deployment for enterprise customers.

The paid boundary must not hide whether a deterministic rule ran, failed, or
was unsupported. AI metadata remains advisory.

## First paid offer

Sell a Vyper CI Hardening Pilot before building a general SaaS dashboard:

1. Integrate SARIF into one private repository.
2. Manually triage and baseline current findings.
3. Add five protocol-specific checks or invariants.
4. Configure release policy for new supported findings.
5. Deliver a regression report and 30 days of rule tuning.

Suggested pilot pricing is USD 300-750 for small teams and USD 1,000-3,000 for
funded protocols. Describe it as security engineering and CI hardening, not a
complete audit.

## Control-plane architecture

```text
GitHub App / CI runner
  -> signed scan upload (SARIF + Vyper Guard JSON)
  -> tenant/repository authorization
  -> immutable scan record
  -> fingerprint correlation and baseline policy
  -> PR check + GitHub annotation
  -> dashboard/API for findings, ownership, and evidence
```

Minimum hosted entities:

- `Organization`: tenant, plan, retention, data region.
- `Repository`: installation ID, default branch, policy ID.
- `Policy`: detector profile, severity gate, compiler requirement.
- `Scan`: commit SHA, tool version, config digest, status, failures.
- `Finding`: fingerprint, rule, location, evidence, first/last seen.
- `Acceptance`: finding, owner, reason, expiry, approval, audit timestamps.
- `RulePack`: version, protocol, supported compiler range, quality evidence.

Security requirements:

- GitHub installation tokens are encrypted and short-lived.
- Scan uploads are authenticated, size-limited, and bound to commit SHA.
- Source retention is opt-in; reports should work without storing source.
- Every status and acceptance mutation is audit logged.
- Cross-tenant identifiers are never accepted without authorization checks.
- Webhooks are signature-verified and replay-protected.
- Rule and policy versions are immutable once referenced by a scan.

## Release gates for supported detectors

A detector cannot be labeled supported until it has:

- A documented threat model and explicit non-goals.
- Compiler-backed semantics for the relevant language feature.
- At least 30 confirmed positive examples.
- At least 100 safe or adversarial counterexamples.
- Precision and recall reported independently per compiler family.
- No known crash on the pinned production corpus.
- Stable finding fingerprints and SARIF behavior.
- A maintainer and regression response policy.

## Delivery order

1. Precision and compiler semantics.
2. Reproducible corpus and detector quality gates.
3. SARIF action, reviewed baselines, and policy configuration.
4. Three paid pilots operated manually.
5. Extract repeated pilot work into the hosted API and GitHub App.
6. Add organization dashboards only when customers need cross-repository views.

Do not prioritize autonomous issue creation, general AI chat, or live-chain
monitoring until the pull-request security workflow retains paying users.
