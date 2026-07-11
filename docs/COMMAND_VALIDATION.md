# Command validation

Run the maintained CLI smoke suite from the repository root:

```bash
uv run python scripts/smoke_cli.py
```

The suite executes analysis in every report format, verification with controlled unit and
fuzz subprocesses, AST and flow extraction, remediation dry-run, statistics, diff,
benchmarking, configuration initialization, memory inspection, and local configuration
commands. It also checks the help interface for every top-level command.

The following commands require external services and are interface-tested but not invoked
against production systems by the offline suite:

| Command | External prerequisite |
| --- | --- |
| `analyze-address` | Explorer endpoint and a verified deployed contract |
| `explorer <address>` | Explorer endpoint; some providers require an API key |
| `monitor` | RPC WebSocket endpoint and deployed contract |
| `baseline` | RPC endpoint and deployed contract history |
| `agent` | Configured LLM provider and credentials |
| `label-quality` | Independently reviewed `vyper-guard-labels/v2` corpus |

These paths have dedicated mocked tests. Release validation should additionally run them
against controlled staging services; a help-screen pass is not evidence of service-level
correctness.
