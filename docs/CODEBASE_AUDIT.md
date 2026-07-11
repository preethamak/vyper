# Vyper Guard Codebase Map and Product Audit

Audit date: 2026-07-11

## Executive verdict

Vyper Guard 0.5.0 is a useful Vyper-focused review assistant, report generator,
and regression harness. It is not yet reliable enough to be presented as an
auditor, a vulnerability verdict engine, or a blocking CI security gate.

Recommended use today:

- Run it before manual review to build a checklist and locate risky syntax.
- Export JSON or SARIF for review workflows, but require human triage.
- Use `ast`, `flow`, `stats`, compiler advisories, and baselines as supporting
  evidence.
- Do not use the score, grade, AI output, or auto-fix result as proof of safety.
- Do not report scanner findings to third-party projects until an auditor has
  reproduced and manually validated impact.

## Repository map

```text
CLI / integrations
  pyproject.toml                 package metadata, dependencies, entry point
  src/guardian/cli.py            Typer command surface and orchestration
  src/guardian/__main__.py       python -m guardian entry point
  vyper_guard_lsp.py             deprecated compatibility entry point
  vscode-extension/              SARIF diagnostics and report export commands

Analysis pipeline
  utils/helpers.py               source loading and optional compiler discovery
  analyzer/ast_parser.py         source-level Vyper parser
  analyzer/semantic.py           source/compiler semantic summaries
  analyzer/cfg.py                basic blocks and CFG construction
  analyzer/project_graph.py      imports, interfaces, calls, state maps
  analyzer/vyper_detector.py     22 registered detectors
  analyzer/compiler_check.py     version advisory matching
  analyzer/confidence.py         finding confidence calibration
  analyzer/exploit_verifier.py  deterministic CEI evidence bundles
  analyzer/metrics.py            cyclomatic complexity
  analyzer/static.py             detector orchestration, failures, scoring
  analyzer/benchmark.py          labeled-corpus precision/recall/F1

Output and policy
  models.py                      Pydantic public data contracts
  reporting/formatter.py         Rich terminal report
  reporting/json_exporter.py     JSON schema v1 and fingerprints
  reporting/markdown_exporter.py Markdown report
  reporting/sarif_exporter.py    SARIF 2.1.0 output
  reporting/html_exporter.py     standalone HTML report
  reporting/score.py             score helpers and deduplication
  analyzer/ai_triage.py          deterministic priority triage
  agents/llm_triage.py           optional LLM finding triage
  agents/adk.py                  optional interactive agent and JSONL memory

Remediation and verification
  remediation/fix_generator.py   detector-to-patch handlers and risk tiers
  remediation/ast_manipulator.py source-line patch composition
  remediation/validator.py       lightweight structural validation
  testing/runner.py              subprocess-backed unit/fuzz execution

External and runtime features
  explorer/client.py             Etherscan, Blockscout, Sourcify fetches
  monitor/chain_watcher.py       Web3 polling
  monitor/tx_analyzer.py         transaction statistics
  monitor/pattern_matcher.py     baseline anomaly rules
  monitor/alerting.py            console/webhook alerts and URL controls
  monitor/baseline.py            baseline persistence

Data and validation
  db/*.json                      advisories, detector rules, fix templates
  test_contracts/                synthetic and historical Curve corpus
  tests/                         392 pre-audit tests; 415 after current reliability work
  dist/                          previously built 0.5.1 artifacts
```

## Dependency map

Required runtime dependencies are Typer, Rich, Pydantic, PyYAML,
python-dotenv, and Requests. Optional boundaries are sensible:

- `vyper`: compiler-backed AST semantics.
- `web3` and `aiohttp`: monitoring.
- `PyGithub`: remediation integration.
- Ruff, mypy, pytest, coverage, and pre-commit: development gates.
- The VS Code extension uses TypeScript, VS Code APIs, and `execFile`; it does
  not embed analyzer logic and consumes SARIF from the Python CLI.

The lock file resolves substantially more packages because it includes all
optional and development groups. The core install remains relatively small.

## Live command validation

| Command/workflow | Result | Audit note |
|---|---|---|
| `--help`, `help`, `version`, `detectors` | Pass | Help is polished but visually heavy. |
| `analyze`, hidden `scan` alias | Pass | File and directory JSON worked. |
| JSON, Markdown, SARIF, HTML exporters | Pass | Files generated and schemas parsed. |
| `verify`, `test`, `fuzz` | Pass | Commands run real subprocesses; absolute commands are needed because cwd changes to the target directory. |
| `ast`, `flow`, `stats`, stats graph | Pass | Useful audit navigation aids. |
| `diff` | Pass | Content key is better than line-only comparison. |
| `fix --fix-dry-run` | Fixed | Audit found invalid decorator and overlapping edit composition defects. |
| `benchmark` | Pass, misleading corpus | Overall F1 0.92 hides poor detector-level precision. |
| `init` | Fixed | Previously wrote invalid YAML while exiting 0. |
| `ai config show` | Pass | Stored key is redacted. |
| `agent` fallback | Fixed | Requests exceptions previously exposed the full Gemini API key. |
| `explorer`, `analyze-address` | Degraded path only | Restricted DNS produced clear exit 2; live success not validated. |
| `monitor`, `baseline` | Optional dependency path | Correct exit 2 without Web3; install hint rendering fixed. |
| forced compiler semantics | Fixed fallback | Now reports `source` when Vyper is unavailable. |
| VS Code `npm run compile` | Pass | TypeScript compilation succeeded. |

Release checks executed:

- `ruff check`: passed after repairs.
- `ruff format --check`: passed after repairs.
- `mypy src`: passed.
- Full pytest before repairs: 392 passed.
- Focused new regression suites: passed.
- Package rebuild via `uv` was blocked because the sandbox could not download
  `hatchling`; existing virtualenv binaries were used instead.

## Confirmed product defects repaired

1. Auto-remediation placed `@nonreentrant` after some `def` lines, generating
   invalid Vyper.
2. Same-line patch coalescing deduplicated meaningful lines, dropping event
   fields and log insertions from cumulative fixes.
3. Structural validation did not reject detached decorators or empty named
   declaration blocks.
4. Gemini transport exceptions included API keys in query-string URLs and the
   CLI printed those exceptions verbatim.
5. Explicit compiler mode fell back to source semantics while metadata still
   claimed compiler semantics.
6. Monitor dependency hints lost `[monitor]` through Rich markup parsing.
7. `init` generated malformed YAML and nevertheless reported success.

The checked-in `dist/` artifacts identify themselves as 0.5.1 while
`pyproject.toml`, `guardian.__version__`, and the live CLI identify the source as
0.5.0. Twine validates the artifact structure but cannot detect this release
provenance mismatch. Rebuild or remove stale artifacts before the next release.

## Detector quality review

Bundled benchmark result over `test_contracts`:

- Overall precision: 0.8846
- Overall recall: 0.9583
- Overall F1: 0.92
- Confusion matrix: 23 TP, 3 FP, 1 TN, 1 FN

These aggregate values should not be used in marketing. Detector-level results
from the same run were much weaker:

- `compiler_version_check`: precision 0.0417
- `missing_event_emission`: precision 0.0526
- `missing_nonreentrant`: precision 0.1053
- `cei_violation`: precision 0.0833
- `integer_overflow`: recall 0.0
- `timestamp_dependence`: precision 0.1667, recall 0.5

The corpus infers labels largely from filenames/comments. It is not an
independent ground-truth vulnerability dataset, and several detectors have no
positive support. Add explicit per-file/per-detector labels and safe controls
before publishing any accuracy claim.

## Independent public-contract scan

Sources were downloaded from GitHub into `/tmp` and were not added to this
repository.

| Repository commit | Contract | Score/findings |
|---|---|---:|
| curvefi/stableswap-ng `2abe778f` | `ProxyAdmin.vy` | 0 / 8 |
| curvefi/scrvusd `95a12084` | `RewardsHandler.vy` | 84 / 2 |
| curvefi/scrvusd `95a12084` | `TWA.vy` | 100 / 0 |
| yearn/yearn-vaults-v3 `5b698f94` | `VaultFactory.vy` | 40 / 6 |
| yearn/yearn-vaults-v3 `5b698f94` | `VaultV3.vy` | 0 / 127 |

The production-corpus precision work reduced Vault V3 from 127 to 92 findings
by correcting address clearing, interface return use, immutable initialization,
stateless/role-gated reentrancy, and directly guarded unsafe subtraction.
The remaining count is still far too noisy for a gate. Because the pinned
contract requires Vyper 0.3.10 while the available compiler is 0.4.3, the report
correctly records source fallback and the exact version incompatibility.

Manual triage of representative hits found no responsible-disclosure-ready
vulnerability:

- `ProxyAdmin.execute`: `raw_call` reverts on failure by default; an assigned
  return value is not required. Admin gating also changes the reentrancy threat
  model substantially.
- Proxy admin state-clearing assignments to `ZERO_ADDRESS` were incorrectly
  reported as missing zero-address checks.
- scrvUSD immutable initialization was reported as local-variable shadowing.
- Yearn role-gated setters were reported as missing reentrancy guards despite
  having no external interaction in the function.
- Guarded `unsafe_sub` arithmetic was reported without recognizing the
  immediately preceding bound checks.
- Interface return values used directly in assignments, tuple assignments, and
  `return` statements were reported as ignored.
- Bounded strategy loops were categorized as `send_in_loop` even where the
  call was a required view/accounting operation rather than an Ether send.

This result is evidence against tagging maintainers with current output. It is
more valuable as a precision backlog and regression corpus.

## Output quality

JSON and SARIF are the strongest formats. They are structured, deterministic,
include fingerprints and evidence, and keep machine output usable. Markdown and
HTML contain useful detail but become very long on real protocols.

The terminal format is over-designed for an auditor workflow:

- Large repeated ASCII branding consumes the first viewport.
- Emoji-heavy labels and multiple panels slow scanning.
- Findings repeat description, rationale, evidence, snippet, and fix text.
- Ten-line snippets often include the next function and unrelated comments.
- Historical deployment-oriented score labels were too authoritative when most
  findings were untriaged heuristics. Labels now describe detected heuristic
  risk and structured output separates analysis trust from score.
- `verify` duplicates verification data under both `analysis_context` and the
  top-level `verification` field.
- AI fallback prose is generic and should not be presented as analysis when no
  findings were assembled.

Recommended terminal default: one-line summary, severity/detector/location
table, confidence, and a report path. Put evidence and remediation behind
`--verbose` or structured formats. The grade is now a heuristic risk indicator;
independent calibration remains required before it can be used as a quality gate.

## Would an auditor adopt it?

Yes, conditionally, as a non-blocking assistant. The strongest reasons are
Vyper-specific compiler advisories, fast local operation, useful structured
exports, explicit detector failure reporting, baselines, project graphs, and a
good foundation for regression tests.

No, not yet as an audit engine or recommended security gate. The major reasons
are high false-positive rates on audited production contracts, shallow
source-level semantics without the optional compiler, invalid auto-fixes found
during this audit, misleading score certainty, weak independent benchmark
labels, and optional workflows that are larger than their validation evidence.

## Commercial and licensing note

The repository currently contains an MIT `LICENSE`, and `pyproject.toml`
classifies it as an OSI-approved MIT project. That is open-source distribution
even if the business intends to charge for binaries, hosting, support, reports,
or enterprise features. If the intent is a proprietary codebase, resolve the
license and public repository history before further distribution. Commercial
open source is also viable: keep the scanner core open and monetize hosted CI,
curated rules, private baselines, team triage, support, and verified remediation.

## Recommended roadmap

### P0: trust and precision

1. Make compiler-backed parsing the supported audit mode; source mode should be
   explicitly labeled “heuristic.”
2. Replace regex-only decisions with use/def, dominance, call-result-use, ACL,
   and path-sensitive checks.
3. Fix detector classes exposed by the public corpus: ignored return values,
   zero-address writes versus inputs, immutable initialization, guarded unsafe
   math, role-aware reentrancy, and loop call classification.
4. Disable auto-apply by default until every emitted patch compiles with the
   declared Vyper version and focused tests pass.
5. Remove authoritative deployment labels from untriaged scores.

### P1: evidence

1. Create a versioned corpus manifest containing commit SHA, file hash, exact
   compiler, expected finding, safe counterexample, and audit reference.
2. Split synthetic, historical-vulnerability, and clean-production corpora.
3. Require minimum per-detector support and CI quality gates.
4. Compare against Vyper compiler diagnostics, Semgrep rules, Slither where
   applicable, and manual labels; publish raw results.

### P2: product focus

1. Make SARIF/JSON plus concise CLI the primary workflow.
2. Turn the VS Code extension into a triage surface with suppress/accept and
   baseline actions.
3. Keep AI advisory and feed it deterministic evidence; never let it create or
   suppress a verdict without an auditable rule.
4. Choose one paid wedge: hosted private-repo CI with reviewed Vyper rules is
   more credible than a general autonomous auditor.

### Responsible outreach

Do not open issues from raw scanner output. First reproduce against a pinned
commit and compiler, minimize the case, write an exploit or invariant test,
estimate real impact, check existing audits/issues, and use the project security
policy or private disclosure channel. Public tagging is appropriate only after
maintainer consent or coordinated disclosure.
