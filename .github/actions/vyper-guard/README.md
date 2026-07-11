# Vyper Guard GitHub Action

This composite action generates SARIF. Keep `fail-on-findings: false` until the
repository baseline has been manually reviewed. Uploading SARIF requires
`security-events: write`.

```yaml
name: Vyper security
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: your-org/vyper-guard/.github/actions/vyper-guard@main
        id: vyper-guard
        with:
          target: contracts
          detectors: recommended
          baseline-file: .vyper-guard-baseline.json
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.vyper-guard.outputs.sarif }}
```

Pin the action to a commit SHA in production. Enable `fail-on-findings` only
after accepted findings have been baselined and detector maturity is appropriate
for the policy.
