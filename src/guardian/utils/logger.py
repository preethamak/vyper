"""Logging setup for Vyper Guard.

Uses Rich's logging handler for beautiful terminal output.
"""

from __future__ import annotations

import logging
import os

from rich.console import Console
from rich.logging import RichHandler

_CONFIGURED = False


def setup_logging(verbose: bool = False, log_level: str | None = None) -> None:
    """Configure the root ``guardian`` logger.

    Args:
        verbose: When *True*, set level to DEBUG; otherwise INFO.
        log_level: Optional explicit log level name (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR'). Overrides ``verbose``.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    # Determine log level: explicit param > env var > verbose flag
    if log_level:
        level = getattr(logging, log_level.upper(), logging.INFO)
    else:
        env_lvl = os.getenv("GUARD_LOG_LEVEL")
        if env_lvl:
            level = getattr(logging, env_lvl.upper(), logging.INFO)
        else:
            level = logging.DEBUG if verbose else logging.INFO

    handler = RichHandler(
        console=Console(stderr=True),
        level=level,
        show_time=True,
        show_path=verbose,
        rich_tracebacks=True,
        markup=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))

    root = logging.getLogger("guardian")
    root.setLevel(level)
    root.addHandler(handler)

    # Suppress noisy third-party loggers.
    for noisy in ("urllib3", "asyncio", "web3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``guardian`` namespace."""
    return logging.getLogger(f"guardian.{name}")
