## 🤖 AI-Assisted Triage

> Policy: `v1.0.0` (`deprecated`) — deterministic advisory metadata only.
> Policy warnings: AI triage policy is deprecated and should be migrated soon.; AI triage policy deprecation announced; sunset after 2026-12-31.
> Guardrail: triage is advisory only and cannot override deterministic detector verdicts.
> Confidence uses deterministic scoring (`severity_base + evidence_bonus`, capped at `0.98`).

| Rank | Bucket | Detector | Severity | Confidence | Scoring | Next Step |
|-----:|--------|----------|----------|-----------:|---------|-----------|
| 1 | review_now | `unsafe_raw_call` | HIGH | 0.86 | triage_scoring_v1 / base=0.86 + bonus=0.0 | Assert/capture raw_call success and add failure handling. |
| 2 | review_later | `timestamp_dependence` | LOW | 0.64 | triage_scoring_v1 / base=0.64 + bonus=0.0 | Review finding context and apply the provided deterministic fix suggestion. |
