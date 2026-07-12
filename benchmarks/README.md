# Evidence-backed benchmarks

This directory contains reproducible benchmark records for exact commits reviewed by
independent security auditors. It is intentionally separate from `corpus/real_world`, which
is used for detector calibration and must not be presented as audit ground truth.

## Trust rules

- Scanner output never becomes a label without manual review.
- Every engagement identifies the repository, full commit, audit report, auditor, and source
  hashes.
- Unsupported audit findings remain visible. They are not removed from recall denominators
  by implication; reports show both total audit coverage and supported-case recall.
- A published audit finding may contain several concrete code locations. Reports distinguish
  audit findings from benchmark cases so one audit finding cannot be presented as many
  independent labels.
- Unreviewed scanner candidates are not false positives. Precision remains `null` until they
  have been reviewed.

## Reproduce

Fetch the source files listed by an engagement into a directory, verify their SHA-256 hashes,
then run:

```bash
uv run python scripts/run_audited_benchmark.py \
  benchmarks/engagements/curve-dao-trail-of-bits-2020.json \
  --source-dir /tmp/curve-dao-f1c8f43 \
  --reviews benchmarks/reviews/curve-dao-trail-of-bits-2020.json \
  --json-output benchmarks/results/curve-dao-trail-of-bits-2020.json \
  --markdown-output benchmarks/results/curve-dao-trail-of-bits-2020.md
```

Files under `results/` are stable handoff artifacts suitable for a website or another tool.
The JSON should be treated as the canonical representation.

Candidate reviews are stored separately from independent audit labels. Internal review can
measure preliminary precision, but it must remain marked `independent: false` until an
external reviewer or protocol team confirms the classifications.
