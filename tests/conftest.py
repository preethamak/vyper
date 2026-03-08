"""Shared pytest fixtures for the guardian test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample_contracts"


@pytest.fixture()
def vulnerable_vault_path() -> Path:
    return FIXTURES_DIR / "vulnerable_vault.vy"


@pytest.fixture()
def reentrancy_example_path() -> Path:
    return FIXTURES_DIR / "reentrancy_example.vy"


@pytest.fixture()
def safe_token_path() -> Path:
    return FIXTURES_DIR / "safe_token.vy"


@pytest.fixture()
def complex_defi_path() -> Path:
    return FIXTURES_DIR / "complex_defi.vy"


@pytest.fixture()
def vulnerable_vault_source(vulnerable_vault_path: Path) -> str:
    return vulnerable_vault_path.read_text(encoding="utf-8")


@pytest.fixture()
def safe_token_source(safe_token_path: Path) -> str:
    return safe_token_path.read_text(encoding="utf-8")


@pytest.fixture()
def complex_defi_source(complex_defi_path: Path) -> str:
    return complex_defi_path.read_text(encoding="utf-8")
