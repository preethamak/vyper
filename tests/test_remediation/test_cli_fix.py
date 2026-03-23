"""Integration tests for the --fix CLI flag."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from guardian.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Test contracts
# ---------------------------------------------------------------------------

VULNERABLE_SOURCE = """\
# pragma version ^0.3.10

balances: HashMap[address, uint256]

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
"""

SAFE_SOURCE = """\
# pragma version ^0.4.0

owner: public(address)

@external
@view
def get_owner() -> address:
    return self.owner
"""

TIER_C_ONLY_SOURCE = """\
# pragma version ^0.4.0

balances: HashMap[address, uint256]

event Withdrawn:
    user: address

@external
@nonreentrant
def withdraw(amount: uint256):
    send(msg.sender, amount)
    self.balances[msg.sender] = 0
    log Withdrawn(msg.sender)
"""


class TestFixCLI:
    """CLI --fix flag integration tests."""

    def test_fix_flag_exists(self) -> None:
        """--fix flag doesn't crash on a trivial run."""
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(SAFE_SOURCE)
            f.flush()
            result = runner.invoke(app, ["analyze", f.name, "--fix"])
        os.unlink(f.name)
        assert result.exit_code == 0

    def test_fix_creates_fixed_file(self) -> None:
        """--fix should create a .fixed.vy file for vulnerable contracts."""
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            # Pass 'n' to the overwrite prompt
            runner.invoke(app, ["analyze", tmp_path, "--fix"], input="n\n")
            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            assert fixed_path.exists(), f"Expected {fixed_path} to be created"
            fixed_content = fixed_path.read_text(encoding="utf-8")
            assert len(fixed_content) > 0
            # Clean up
            fixed_path.unlink()
        finally:
            os.unlink(tmp_path)

    def test_fix_patched_file_has_fixes(self) -> None:
        """The .fixed.vy file should contain actual fixes."""
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            runner.invoke(app, ["analyze", tmp_path, "--fix"], input="n\n")
            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            if fixed_path.exists():
                fixed_content = fixed_path.read_text(encoding="utf-8")
                # Should have either @nonreentrant, assert, or FIXME
                has_fix = (
                    "@nonreentrant" in fixed_content
                    or "assert" in fixed_content
                    or "FIXME" in fixed_content
                    or "NOTE" in fixed_content
                )
                assert has_fix, f"Expected fixes in patched file. Content:\n{fixed_content}"
                fixed_path.unlink()
        finally:
            os.unlink(tmp_path)

    def test_fix_no_findings_no_fixed_file(self) -> None:
        """When no findings, --fix should not create a .fixed.vy file."""
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(SAFE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            runner.invoke(app, ["analyze", tmp_path, "--fix"])
            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            assert not fixed_path.exists()
        finally:
            os.unlink(tmp_path)

    def test_fix_output_mentions_remediation(self) -> None:
        """The CLI output should mention auto-remediation when --fix is used."""
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(app, ["analyze", tmp_path, "--fix"], input="n\n")
            output = result.output
            # Should mention fixes or remediation
            has_fix_output = (
                "fix" in output.lower()
                or "remediation" in output.lower()
                or "patched" in output.lower()
                or "FIXME" in output
            )
            assert has_fix_output, f"Expected fix-related output. Got:\n{output}"
        finally:
            os.unlink(tmp_path)

    def test_fix_with_json_format(self) -> None:
        """--fix should work alongside --format json."""
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(
                app, ["analyze", tmp_path, "--fix", "--format", "json"], input="n\n"
            )
            # Should not crash
            assert result.exit_code == 0
            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            if fixed_path.exists():
                fixed_path.unlink()
        finally:
            os.unlink(tmp_path)

    def test_fix_respects_max_auto_fix_tier_and_skips_tier_c(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(TIER_C_ONLY_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(
                app,
                ["analyze", tmp_path, "--fix", "--max-auto-fix-tier", "B"],
                input="n\n",
            )
            assert result.exit_code == 0
            output = result.output.lower()
            assert "skipped by risk-tier policy" in output

            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            assert not fixed_path.exists(), "Tier-C-only fixes should not produce patched output at tier B"
        finally:
            os.unlink(tmp_path)

    def test_fix_invalid_max_auto_fix_tier_returns_exit_2(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(
                app,
                ["analyze", tmp_path, "--fix", "--max-auto-fix-tier", "Z"],
            )
            assert result.exit_code == 2
        finally:
            os.unlink(tmp_path)

        def test_fix_uses_config_default_max_auto_fix_tier(self) -> None:
                with tempfile.TemporaryDirectory() as tmpdir:
                        root = Path(tmpdir)
                        contract = root / "contract.vy"
                        contract.write_text(TIER_C_ONLY_SOURCE, encoding="utf-8")

                        (root / ".guardianrc").write_text(
                                """\
analysis:
    enabled_detectors:
        - all
    disabled_detectors: []
    severity_threshold: LOW

reporting:
    default_format: cli
    show_source_snippets: true
    show_fix_suggestions: true

remediation:
    max_auto_fix_tier: B
""",
                                encoding="utf-8",
                        )

                        result = runner.invoke(app, ["analyze", str(contract), "--fix"], input="n\n")
                        assert result.exit_code == 0
                        assert "skipped by risk-tier policy" in result.output.lower()

                        fixed_path = contract.with_suffix(".fixed.vy")
                        assert not fixed_path.exists()

        def test_fix_cli_tier_overrides_config_default(self) -> None:
                with tempfile.TemporaryDirectory() as tmpdir:
                        root = Path(tmpdir)
                        contract = root / "contract.vy"
                        contract.write_text(TIER_C_ONLY_SOURCE, encoding="utf-8")

                        (root / ".guardianrc").write_text(
                                """\
analysis:
    enabled_detectors:
        - all
    disabled_detectors: []
    severity_threshold: LOW

reporting:
    default_format: cli
    show_source_snippets: true
    show_fix_suggestions: true

remediation:
    max_auto_fix_tier: B
""",
                                encoding="utf-8",
                        )

                        result = runner.invoke(
                                app,
                                ["analyze", str(contract), "--fix", "--max-auto-fix-tier", "C"],
                                input="n\n",
                        )
                        assert result.exit_code == 0

                        fixed_path = contract.with_suffix(".fixed.vy")
                        assert fixed_path.exists()

    def test_fix_dry_run_does_not_write_patched_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(app, ["analyze", tmp_path, "--fix", "--fix-dry-run"])
            assert result.exit_code == 0
            assert "dry-run mode" in result.output.lower()

            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            assert not fixed_path.exists()
        finally:
            os.unlink(tmp_path)

    def test_fix_dry_run_implies_fix_mode(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(app, ["analyze", tmp_path, "--fix-dry-run"])
            assert result.exit_code == 0
            assert "auto-remediation" in result.output.lower()
            assert "dry-run mode" in result.output.lower()

            fixed_path = Path(tmp_path).with_suffix(".fixed.vy")
            assert not fixed_path.exists()
        finally:
            os.unlink(tmp_path)

    def test_fix_report_writes_json_artifact_in_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            contract = root / "contract.vy"
            contract.write_text(VULNERABLE_SOURCE, encoding="utf-8")
            fix_report = root / "remediation-report.json"

            result = runner.invoke(
                app,
                [
                    "analyze",
                    str(contract),
                    "--fix-dry-run",
                    "--fix-report",
                    str(fix_report),
                ],
            )
            assert result.exit_code == 0
            assert fix_report.exists()

            data = json.loads(fix_report.read_text(encoding="utf-8"))
            assert data["file_path"] == str(contract)
            assert data["dry_run"] is True
            assert "plan" in data
            assert "summary" in data
            assert isinstance(data["generated_fixes"], list)

    def test_fix_report_requires_fix_mode(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".vy", mode="w", delete=False) as f:
            f.write(VULNERABLE_SOURCE)
            f.flush()
            tmp_path = f.name

        try:
            result = runner.invoke(
                app,
                [
                    "analyze",
                    tmp_path,
                    "--fix-report",
                    str(Path(tmp_path).with_suffix(".remediation.json")),
                ],
            )
            assert result.exit_code == 2
            assert "--fix-report requires --fix or --fix-dry-run" in result.output
        finally:
            os.unlink(tmp_path)
