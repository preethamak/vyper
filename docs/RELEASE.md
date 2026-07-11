# Release Process

1. Run `uv run python scripts/check_release.py`.
2. Run the complete test, lint, type, and command smoke suites.
3. Commit the release-ready tree.
4. Create and push an annotated tag such as `v0.6.0`.
5. GitHub Actions builds the wheel and source distribution, publishes to PyPI through
   trusted publishing, and attaches the artifacts to a GitHub release.

PyPI's `pypi` environment must be configured for trusted publishing before the first release.
Do not publish from a developer workstation.
