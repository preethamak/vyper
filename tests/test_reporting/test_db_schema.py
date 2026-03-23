"""Schema validation tests for bundled DB metadata JSON files."""

from __future__ import annotations

from guardian.db.vulnerabilities import (
    load_detector_rules,
    load_fix_templates,
    load_known_issues,
    validate_bundled_databases,
)


def test_bundled_databases_validate_successfully() -> None:
    # Should not raise for bundled project metadata.
    validate_bundled_databases()


def test_bundled_metadata_lists_are_loadable() -> None:
    assert isinstance(load_known_issues(), list)
    assert isinstance(load_detector_rules(), list)
    assert isinstance(load_fix_templates(), list)
