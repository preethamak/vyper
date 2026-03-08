"""Tests for the Vyper source-level parser (ast_parser) and compiler_check."""

from __future__ import annotations

from guardian.analyzer.ast_parser import parse_vyper_source
from guardian.analyzer.compiler_check import check_compiler_version

# -------------------------------------------------------------------------
# ast_parser tests
# -------------------------------------------------------------------------


class TestParseVyperSource:
    """Tests for parse_vyper_source()."""

    def test_extracts_pragma_version(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        assert contract.pragma_version is not None
        assert "0.3.9" in contract.pragma_version

    def test_extracts_functions(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        names = [f.name for f in contract.functions]
        assert "withdraw" in names
        assert "deposit" in names
        assert "set_owner" in names
        assert "get_balance" in names

    def test_function_decorators(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        withdraw = next(f for f in contract.functions if f.name == "withdraw")
        assert withdraw.is_external
        assert not withdraw.is_nonreentrant

        get_bal = next(f for f in contract.functions if f.name == "get_balance")
        assert get_bal.is_external
        assert get_bal.is_view

    def test_extracts_events(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        event_names = [e.name for e in contract.events]
        assert "Deposit" in event_names

    def test_extracts_state_variables(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        var_names = [v.name for v in contract.state_variables]
        assert "owner" in var_names
        assert "balances" in var_names

    def test_public_variable_flag(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        owner_var = next(v for v in contract.state_variables if v.name == "owner")
        assert owner_var.is_public

    def test_safe_contract_parsed_correctly(self, safe_token_source: str) -> None:
        contract = parse_vyper_source(safe_token_source)
        assert contract.pragma_version is not None
        assert "0.4.0" in contract.pragma_version
        assert len(contract.functions) >= 4
        assert len(contract.events) >= 2

    def test_nonreentrant_detected(self, safe_token_source: str) -> None:
        contract = parse_vyper_source(safe_token_source)
        transfer = next(f for f in contract.functions if f.name == "transfer")
        assert transfer.is_nonreentrant

    def test_empty_source_returns_empty_contract(self) -> None:
        # Minimal valid-ish source (just a comment)
        contract = parse_vyper_source("# empty contract")
        assert contract.functions == []
        assert contract.events == []
        assert contract.state_variables == []

    def test_function_body_lines_populated(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        withdraw = next(f for f in contract.functions if f.name == "withdraw")
        assert len(withdraw.body_lines) > 0
        # Body should contain the send() call
        body_text = withdraw.body_text
        assert "send(" in body_text


# -------------------------------------------------------------------------
# compiler_check tests
# -------------------------------------------------------------------------


class TestCompilerCheck:
    """Tests for check_compiler_version()."""

    def test_old_version_flags_vulnerabilities(self, vulnerable_vault_source: str) -> None:
        contract = parse_vyper_source(vulnerable_vault_source)
        # vulnerable_vault targets ^0.3.9 which is < 0.4.0
        results = check_compiler_version(contract)
        # Should have at least the overflow and the nonreentrant-lock advisories
        assert len(results) >= 1
        severities = [r.severity.value for r in results]
        assert "CRITICAL" in severities or "HIGH" in severities

    def test_safe_version_no_findings(self, safe_token_source: str) -> None:
        contract = parse_vyper_source(safe_token_source)
        # safe_token targets ^0.4.0
        results = check_compiler_version(contract)
        # Should have zero findings (no known issues for 0.4.0)
        assert len(results) == 0

    def test_no_pragma_reports_info(self) -> None:
        source = "owner: public(address)"
        contract = parse_vyper_source(source)
        results = check_compiler_version(contract)
        assert len(results) == 1
        assert results[0].severity.value == "INFO"
        assert "pragma" in results[0].title.lower()


class TestPragmaFormats:
    """Ensure all real-world Vyper pragma formats are detected."""

    def test_standard_pragma(self) -> None:
        source = "# pragma version ^0.4.0\nowner: address"
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "^0.4.0"

    def test_no_space_pragma(self) -> None:
        source = "#pragma version ^0.4.0\nowner: address"
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "^0.4.0"

    def test_at_pragma_format(self) -> None:
        """# @pragma version 0.4.1 — the format used by Vyper 0.4.x tooling."""
        source = "# @pragma version 0.4.1\n# @license MIT\nowner: address"
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "0.4.1"

    def test_legacy_at_version_format(self) -> None:
        """# @version ^0.3.9 — the older pre-0.4.0 format."""
        source = "# @version ^0.3.9\nowner: address"
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "^0.3.9"

    def test_at_version_with_pin(self) -> None:
        source = "# @version 0.3.10\nowner: address"
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "0.3.10"

    def test_at_pragma_without_version_keyword(self) -> None:
        """# @pragma 0.4.0 — no 'version' keyword (real-world Vyper 0.4.x)."""
        source = '# @pragma 0.4.0\n"""\n@license MIT\n"""\nowner: address'
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "0.4.0"

    def test_at_pragma_without_version_caret(self) -> None:
        """# @pragma ^0.4.0 — with caret but no 'version' keyword."""
        source = "# @pragma ^0.4.0\nowner: address"
        contract = parse_vyper_source(source)
        assert contract.pragma_version == "^0.4.0"

    def test_compiler_check_works_with_at_pragma(self) -> None:
        """End-to-end: # @pragma version 0.4.1 should NOT trigger 'missing pragma'."""
        source = "# @pragma version 0.4.1\nowner: address"
        contract = parse_vyper_source(source)
        results = check_compiler_version(contract)
        # No 'missing pragma' finding
        titles = [r.title.lower() for r in results]
        assert not any("missing" in t for t in titles)

    def test_compiler_check_works_with_at_pragma_no_version_kw(self) -> None:
        """End-to-end: # @pragma 0.4.0 should NOT trigger 'missing pragma'."""
        source = "# @pragma 0.4.0\nowner: address"
        contract = parse_vyper_source(source)
        results = check_compiler_version(contract)
        titles = [r.title.lower() for r in results]
        assert not any("missing" in t for t in titles)

    def test_compiler_check_works_with_legacy_version(self) -> None:
        """End-to-end: # @version ^0.3.9 should detect old version vulnerabilities."""
        source = "# @version ^0.3.9\nowner: address"
        contract = parse_vyper_source(source)
        results = check_compiler_version(contract)
        # Should flag old-version issues, NOT 'missing pragma'
        assert len(results) >= 1
        titles = [r.title.lower() for r in results]
        assert not any("missing" in t for t in titles)
