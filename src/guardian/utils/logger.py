"""Logging setup for Vyper Guard.

Uses Rich's logging handler for beautiful terminal output.
"""

from __future__ import annotations

import logging

from rich.logging import RichHandler

_CONFIGURED = False


def setup_logging(verbose: bool = False) -> None:
    """Configure the root ``guardian`` logger.

    Args:
        verbose: When *True*, set level to DEBUG; otherwise INFO.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = logging.DEBUG if verbose else logging.INFO

    handler = RichHandler(
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
