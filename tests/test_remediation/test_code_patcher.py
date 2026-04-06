"""Tests for the CodePatcher (ast_manipulator) module."""

from __future__ import annotations

import pytest

from guardian.remediation.ast_manipulator import CodePatcher, Patch, generate_diff


class TestPatch:
    """Patch dataclass basics."""

    def test_patch_creation(self) -> None:
        p = Patch(start_line=1, end_line=3, new_lines=["a", "b"], description="test")
        assert p.start_line == 1
        assert p.end_line == 3
        assert p.new_lines == ["a", "b"]
        assert p.description == "test"

    def test_patch_is_frozen(self) -> None:
        p = Patch(start_line=1, end_line=1, new_lines=["x"])
        with pytest.raises(AttributeError):
            p.start_line = 5  # type: ignore[misc]


class TestCodePatcher:
    """CodePatcher apply/registration."""

    def _make_lines(self) -> list[str]:
        return [
            "@external",
            "def withdraw(amount: uint256):",
            "    raw_call(msg.sender, b'', value=amount)",
            "    self.balances[msg.sender] -= amount",
        ]

    def test_add_and_apply_single_patch(self) -> None:
        lines = self._make_lines()
        patcher = CodePatcher(lines)
        # Replace line 3 with a wrapped version
        patcher.add_patch(
            Patch(
                start_line=3,
                end_line=3,
                new_lines=["    assert raw_call(msg.sender, b'', value=amount)"],
                description="Wrap raw_call",
            )
        )
        result = patcher.apply()
        assert "assert raw_call" in result[2]

    def test_apply_preserves_unaffected_lines(self) -> None:
        lines = self._make_lines()
        patcher = CodePatcher(lines)
        patcher.add_patch(
            Patch(
                start_line=3,
                end_line=3,
                new_lines=["    assert raw_call(msg.sender, b'', value=amount)"],
            )
        )
        result = patcher.apply()
        assert result[0] == "@external"
        assert result[1] == "def withdraw(amount: uint256):"
        assert result[3] == "    self.balances[msg.sender] -= amount"

    def test_insert_decorator(self) -> None:
        lines = [
            "@external",
            "def withdraw(amount: uint256):",
            "    pass",
        ]
        patcher = CodePatcher(lines)
        patcher.insert_decorator(2, "@nonreentrant")
        result = patcher.apply()
        assert "@nonreentrant" in result[0]

    def test_insert_line_before(self) -> None:
        lines = [
            "    self.balances[msg.sender] -= amount",
            "    send(msg.sender, amount)",
        ]
        patcher = CodePatcher(lines)
        patcher.insert_line_before(1, "assert self.balances[msg.sender] >= amount")
        result = patcher.apply()
        assert "assert" in result[0]
        assert len(result) == 3

    def test_insert_line_after(self) -> None:
        lines = [
            "    send(msg.sender, amount)",
            "    self.balances[msg.sender] -= amount",
        ]
        patcher = CodePatcher(lines)
        patcher.insert_line_after(2, "# state updated")
        result = patcher.apply()
        assert len(result) == 3
        assert "# state updated" in result[2]

    def test_replace_lines(self) -> None:
        lines = ["line1", "line2", "line3", "line4"]
        patcher = CodePatcher(lines)
        patcher.replace_lines(2, 3, ["new2", "new3", "extra"])
        result = patcher.apply()
        assert result == ["line1", "new2", "new3", "extra", "line4"]

    def test_swap_lines(self) -> None:
        lines = ["alpha", "beta", "gamma"]
        patcher = CodePatcher(lines)
        patcher.swap_lines(1, 3)
        result = patcher.apply()
        assert result[0] == "gamma"
        assert result[2] == "alpha"

    def test_multiple_patches_bottom_to_top(self) -> None:
        lines = ["a", "b", "c", "d"]
        patcher = CodePatcher(lines)
        # Insert before line 4 and line 2
        patcher.add_patch(Patch(start_line=2, end_line=2, new_lines=["X", "b"]))
        patcher.add_patch(Patch(start_line=4, end_line=4, new_lines=["Y", "d"]))
        result = patcher.apply()
        assert "X" in result
        assert "Y" in result
        assert len(result) == 6

    def test_overlapping_patches_raise(self) -> None:
        lines = ["a", "b", "c", "d"]
        patcher = CodePatcher(lines)
        patcher.add_patch(Patch(start_line=2, end_line=3, new_lines=["x", "y"]))
        with pytest.raises(ValueError, match="Overlapping patches"):
            patcher.add_patch(Patch(start_line=3, end_line=4, new_lines=["u", "v"]))

    def test_identical_single_line_insert_patches_are_coalesced(self) -> None:
        lines = ["a", "target", "c"]
        patcher = CodePatcher(lines)
        patcher.add_patch(Patch(start_line=2, end_line=2, new_lines=["x", "target"]))
        patcher.add_patch(Patch(start_line=2, end_line=2, new_lines=["y", "target"]))

        result = patcher.apply()
        assert result == ["a", "x", "y", "target", "c"]

    def test_original_property(self) -> None:
        lines = ["one", "two"]
        patcher = CodePatcher(lines)
        patcher.add_patch(Patch(start_line=1, end_line=1, new_lines=["changed"]))
        result = patcher.apply()
        assert patcher.original == ["one", "two"]
        assert result[0] == "changed"


class TestGenerateDiff:
    """Unified diff generation."""

    def test_diff_nonempty(self) -> None:
        orig = ["line1", "line2", "line3"]
        patched = ["line1", "CHANGED", "line3"]
        diff = generate_diff(orig, patched, "test.vy")
        assert "---" in diff
        assert "+++" in diff
        assert "CHANGED" in diff

    def test_diff_empty_when_identical(self) -> None:
        lines = ["a", "b"]
        diff = generate_diff(lines, lines, "test.vy")
        assert diff == ""

    def test_diff_contains_filenames(self) -> None:
        diff = generate_diff(["x"], ["y"], "my_contract.vy")
        assert "a/my_contract.vy" in diff
        assert "b/my_contract.vy" in diff
