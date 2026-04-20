"""Compatibility module for legacy `python -m vyper_guard_lsp` usage.

This project now exposes the CLI via `python -m guardian`.
"""

from __future__ import annotations

import sys

from guardian.cli import app

if __name__ == "__main__":
    print(
        "[vyper-guard] `python -m vyper_guard_lsp` is deprecated; forwarding to `python -m guardian`.",
        file=sys.stderr,
    )
    app()
