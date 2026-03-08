"""Small helper utilities shared across the guardian package."""

from __future__ import annotations

from pathlib import Path

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


class GuardianError(Exception):
    """Base exception for all guardian errors."""


class FileLoadError(GuardianError):
    """Raised when a contract file cannot be loaded."""


class CompilationError(GuardianError):
    """Raised when the Vyper compiler rejects a file."""


class AnalysisError(GuardianError):
    """Raised when the analysis pipeline fails unexpectedly."""


def load_vyper_source(file_path: str | Path) -> str:
    """Safely load a ``.vy`` file from disk.

    Validates that the file exists, has the correct extension, and is not
    unreasonably large.

    Args:
        file_path: Path to the ``.vy`` file.

    Returns:
        The file contents as a string.

    Raises:
        FileLoadError: If validation fails or the file cannot be read.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileLoadError(f"File not found: {path}")
    if not path.is_file():
        raise FileLoadError(f"Not a file: {path}")
    if path.suffix != ".vy":
        raise FileLoadError(f"Expected a .vy file, got: {path.suffix}")

    size = path.stat().st_size
    if size > MAX_FILE_SIZE_BYTES:
        mb = size / (1024 * 1024)
        raise FileLoadError(f"File too large ({mb:.1f} MB). Max is 10 MB.")
    if size == 0:
        raise FileLoadError(f"File is empty: {path}")

    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise FileLoadError(f"Cannot decode file as UTF-8: {exc}") from exc


def truncate(text: str, max_len: int = 200) -> str:
    """Return *text* truncated to *max_len* characters with an ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def check_vyper_available() -> str | None:
    """Check whether the ``vyper`` package is importable.

    Returns:
        The vyper version string if available, or *None*.
    """
    try:
        import vyper  # type: ignore[import-untyped]

        return str(getattr(vyper, "__version__", "unknown"))
    except ImportError:
        return None
