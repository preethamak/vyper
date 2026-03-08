# Installation

## Quick Install (recommended)

```bash
# Clone the repository
git clone https://github.com/preethamak/vyper.git
cd vyper-guard

# Install with uv (fastest)
uv sync

# Verify installation
vyper-guard --version
```

## Install with pip

```bash
pip install -e .
```

## Optional Features

Vyper Guard is modular. The core static analyzer has **zero heavy dependencies** — it works without the Vyper compiler.

| Feature | Install Command | What it adds |
|---------|----------------|--------------|
| **Core** | `pip install -e .` | Static analysis, 12 detectors, CLI, reporting |
| **Live Monitoring** | `pip install -e ".[monitor]"` | Real-time contract monitoring via RPC (requires `web3`) |
| **All Features** | `pip install -e ".[all]"` | Everything above + GitHub integration |

## Docker

```bash
# Build the image
docker build -t vyper-guard .

# Scan a contract (mount your project directory)
docker run --rm -v $(pwd):/code vyper-guard analyze /code/vault.vy

# With auto-fix
docker run --rm -v $(pwd):/code vyper-guard analyze /code/vault.vy --fix
```

## Development Setup

```bash
# Clone and install in dev mode
git clone https://github.com/preethamak/vyper.git
cd vyper-guard
uv sync --dev

# Run tests
uv run pytest tests/ -v

# Run linter
uv run ruff check src/ tests/

# Install pre-commit hooks
uv run pre-commit install
```

## Requirements

- **Python 3.10+** (3.11 or 3.12 recommended)
- No Vyper compiler needed for static analysis
- `web3` package needed only for live monitoring

## CI/CD Integration

### GitHub Actions

Add to your `.github/workflows/security.yml`:

```yaml
name: Vyper Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - run: uv pip install vyper-guard
      - run: vyper-guard analyze contracts/*.vy --ci --severity-threshold HIGH
```

### Pre-commit Hook

Add to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/preethamak/vyper
    rev: v0.1.0
    hooks:
      - id: vyper-guard
```

Then: `pre-commit install`

Every commit touching `.vy` files will be scanned automatically.
