# Example Contracts

This directory contains example Vyper contracts for testing Vyper Guard.

## Files

### `vulnerable_vault.vy`
A deliberately vulnerable vault contract that triggers **9 detectors**. Use this to see the full power of the scanner and `--fix` flag.

```bash
vyper-guard analyze docs/examples/vulnerable_vault.vy
vyper-guard analyze docs/examples/vulnerable_vault.vy --fix
```

`--fix` now asks before writing `.fixed.vy` and before overwriting the original file.

### `safe_vault.vy`
A well-written vault contract that passes all detectors with a score of **100/100 (A+)**. Shows Vyper best practices.

```bash
vyper-guard analyze docs/examples/safe_vault.vy
```

### `token.vy`
A simple ERC20 token with some medium-severity issues (missing events, unchecked subtraction).

```bash
vyper-guard analyze docs/examples/token.vy
```
