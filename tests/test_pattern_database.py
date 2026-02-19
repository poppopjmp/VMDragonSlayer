"""Tests for the pattern database."""

from pathlib import Path

import pytest

from dragonslayer.analysis.pattern_analysis.database import (
    Pattern,
    PatternDatabase,
)


class TestPattern:
    """Unit tests for the Pattern dataclass."""

    def test_create_pattern(self):
        p = Pattern(
            pattern_id="test_1",
            name="Test ADD",
            signature="48 01 C0",
            architecture="x64",
            handler_type="arithmetic",
            operation="add",
            confidence=0.9,
        )
        assert p.pattern_id == "test_1"
        assert p.confidence == 0.9

    def test_confidence_validation(self):
        with pytest.raises(ValueError, match="Confidence"):
            Pattern(
                pattern_id="bad",
                name="bad",
                signature="FF",
                architecture="x64",
                handler_type="arithmetic",
                operation="add",
                confidence=1.5,
            )

    def test_empty_id_rejected(self):
        with pytest.raises(ValueError, match="Pattern ID"):
            Pattern(
                pattern_id="",
                name="x",
                signature="FF",
                architecture="x64",
                handler_type="arithmetic",
                operation="add",
            )

    def test_round_trip(self):
        p = Pattern(
            pattern_id="rt",
            name="RoundTrip",
            signature="CC",
            architecture="x86",
            handler_type="memory",
            operation="nop",
        )
        d = p.to_dict()
        p2 = Pattern.from_dict(d)
        assert p2.pattern_id == p.pattern_id
        assert p2.signature == p.signature

    def test_signature_bytes_parsing(self):
        p = Pattern(
            pattern_id="sb",
            name="SigBytes",
            signature="48 01 ?? 48 89 ??",
            architecture="x64",
            handler_type="arithmetic",
            operation="add",
        )
        sig_bytes = p.get_signature_bytes()
        assert "48" in sig_bytes
        assert "??" in sig_bytes

    def test_matches_architecture(self):
        p = Pattern(
            pattern_id="ma",
            name="Arch",
            signature="CC",
            architecture="x64",
            handler_type="memory",
            operation="nop",
        )
        assert p.matches_architecture("x64")
        assert p.matches_architecture("X64")
        assert not p.matches_architecture("arm")


class TestPatternDatabase:
    """Integration tests using real JSON pattern files."""

    def test_load_vmprotect(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        assert len(db) > 0, "Should load at least one VMProtect pattern"

    def test_load_themida(self, themida_patterns_path: Path):
        db = PatternDatabase(themida_patterns_path)
        assert len(db) > 0, "Should load at least one Themida pattern"

    def test_search_by_architecture(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        x64 = db.search_by_architecture("x64")
        assert len(x64) >= 1, "VMProtect patterns should include x64"

    def test_search_by_handler_type(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        arith = db.search_by_type("arithmetic")
        assert len(arith) >= 1, "Should find arithmetic handlers"

    def test_search_by_operation(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        add_patterns = db.search_by_operation("add")
        assert len(add_patterns) >= 1

    def test_combined_search(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        results = db.search(architecture="x64", handler_type="arithmetic")
        assert len(results) >= 1

    def test_get_statistics(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        stats = db.get_statistics()
        assert stats["total_patterns"] == len(db)
        assert "avg_confidence" in stats

    def test_crud_add_get_delete(self):
        db = PatternDatabase()
        p = Pattern(
            pattern_id="crud_1",
            name="CRUD Test",
            signature="90",
            architecture="x86",
            handler_type="memory",
            operation="nop",
        )
        db.add_pattern(p)
        assert "crud_1" in db
        assert db.get_pattern("crud_1") is p
        db.delete_pattern("crud_1")
        assert "crud_1" not in db

    def test_duplicate_add_rejected(self):
        db = PatternDatabase()
        p = Pattern(
            pattern_id="dup",
            name="Dup",
            signature="CC",
            architecture="x86",
            handler_type="memory",
            operation="nop",
        )
        db.add_pattern(p)
        with pytest.raises(ValueError, match="already exists"):
            db.add_pattern(p)

    def test_save_and_reload(self, tmp_path: Path, vmprotect_patterns_path: Path):
        db1 = PatternDatabase(vmprotect_patterns_path)
        out = tmp_path / "saved.json"
        db1.save(out)
        db2 = PatternDatabase(out)
        assert len(db2) == len(db1)
