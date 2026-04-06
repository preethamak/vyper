"""Tests for the FixValidator module."""

from __future__ import annotations

from guardian.remediation.validator import FixValidator


class TestFixValidator:
    """Structural validation checks."""

    def setup_method(self) -> None:
        self.validator = FixValidator()

    def test_valid_source_no_warnings(self) -> None:
        lines = [
            "# pragma version ^0.4.0",
            "",
            "@external",
            "def withdraw(amount: uint256):",
            "    self.balances[msg.sender] -= amount",
            "    send(msg.sender, amount)",
        ]
        warnings = self.validator.validate(lines)
        assert warnings == []

    def test_unbalanced_parens(self) -> None:
        lines = [
            "def foo(x: uint256:",
            "    pass",
        ]
        warnings = self.validator.validate(lines)
        assert any("(" in w for w in warnings)

    def test_unbalanced_brackets(self) -> None:
        lines = [
            "    self.data[x = 1",
        ]
        warnings = self.validator.validate(lines)
        assert any("[" in w for w in warnings)

    def test_unbalanced_braces(self) -> None:
        lines = [
            "    x: HashMap[address, uint256 = {",
        ]
        warnings = self.validator.validate(lines)
        assert len(warnings) > 0

    def test_balanced_complex_source(self) -> None:
        lines = [
            "# pragma version ^0.4.0",
            "owner: public(address)",
            "balances: HashMap[address, uint256]",
            "",
            "event Transfer:",
            "    sender: indexed(address)",
            "    receiver: indexed(address)",
            "    amount: uint256",
            "",
            "@external",
            "def transfer(to: address, amount: uint256):",
            "    assert self.balances[msg.sender] >= amount",
            "    self.balances[msg.sender] -= amount",
            "    self.balances[to] += amount",
            "    log Transfer(msg.sender, to, amount)",
        ]
        warnings = self.validator.validate(lines)
        assert warnings == []

    def test_def_missing_colon(self) -> None:
        lines = [
            "@external",
            "def broken_function(x: uint256)",
            "    pass",
        ]
        warnings = self.validator.validate(lines)
        assert any(":" in w for w in warnings)

    def test_multiline_def_with_colon_ok(self) -> None:
        lines = [
            "@external",
            "def complex_fn(",
            "    x: uint256,",
            "    y: uint256",
            "):",
            "    pass",
        ]
        warnings = self.validator.validate(lines)
        # The multi-line def should NOT trigger a false positive
        assert not any("def statement" in w for w in warnings)

    def test_comments_ignored_for_bracket_check(self) -> None:
        lines = [
            "# This has unbalanced ( in a comment",
            "def foo():",
            "    pass",
        ]
        warnings = self.validator.validate(lines)
        assert warnings == []

    def test_empty_source(self) -> None:
        warnings = self.validator.validate([])
        assert warnings == []

    def test_only_comments(self) -> None:
        lines = [
            "# pragma version ^0.4.0",
            "# This is a comment",
            "# Another comment",
        ]
        warnings = self.validator.validate(lines)
        assert warnings == []

    def test_tab_indentation_warns(self) -> None:
        lines = [
            "@external",
            "def foo():",
            "\tself.x = 1",
        ]
        warnings = self.validator.validate(lines)
        assert any("tab indentation" in w for w in warnings)

    def test_malformed_decorator_warns(self) -> None:
        lines = [
            "@external(",
            "def foo():",
            "    pass",
        ]
        warnings = self.validator.validate(lines)
        assert any("malformed decorator" in w for w in warnings)
