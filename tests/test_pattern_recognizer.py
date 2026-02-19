"""Tests for the pattern recogniser."""

from pathlib import Path

from dragonslayer.analysis.pattern_analysis.database import PatternDatabase
from dragonslayer.analysis.pattern_analysis.recognizer import (
    Match,
    PatternRecognizer,
    SequenceRecognizer,
)


class TestPatternRecognizer:
    """Smoke-test the wildcard/regex matching engine."""

    def test_recognise_vmp_add(self, vmprotect_patterns_path: Path):
        """The VMP ADD handler ``48 01 ?? 48 89 ??`` embedded in NOPs."""
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db)

        # Build a hex string: 128 NOPs + ADD signature + 128 NOPs
        nops = "90" * 128
        payload = "4801C04889C1"   # 48 01 C0 48 89 C1 (matches 48 01 ?? 48 89 ??)
        hex_input = nops + payload + nops

        matches = rec.recognize(hex_input, min_confidence=0.5, architecture="x64")
        assert len(matches) >= 1, "Should match at least the ADD handler"

        best = matches[0]
        assert isinstance(best, Match)
        assert best.pattern.operation == "add"
        assert best.confidence > 0.5

    def test_no_match_on_zeroes(self, vmprotect_patterns_path: Path):
        """An all-zeroes buffer shouldn't match any VMProtect handler."""
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db)
        matches = rec.recognize("00" * 256, min_confidence=0.7)
        assert len(matches) == 0

    def test_recognize_single(self, vmprotect_patterns_path: Path):
        """``recognize_single`` returns the best match or None."""
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db)
        result = rec.recognize_single("90" * 64, min_confidence=0.9)
        assert result is None  # NOPs shouldn't match anything

    def test_statistics(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db)
        stats = rec.get_statistics()
        assert stats["total_patterns"] > 0


class TestSequenceRecognizer:
    """Smoke-test the multi-instruction window recogniser."""

    def test_window_over_instructions(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        seq = SequenceRecognizer(db)

        instructions = [
            "90",
            "90",
            "48 01 C0 48 89 C1",  # ADD handler
            "90",
            "90",
        ]
        matches = seq.recognize_sequence(
            instructions, window_size=3, min_confidence=0.5, architecture="x64",
        )
        # May or may not match depending on concatenation – at minimum no crash
        assert isinstance(matches, list)
