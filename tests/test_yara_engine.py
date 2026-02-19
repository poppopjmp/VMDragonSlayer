"""Tests for the YARA pattern matching engine."""

import pytest
from pathlib import Path

from dragonslayer.analysis.pattern_analysis.database import PatternDatabase, Pattern
from dragonslayer.analysis.pattern_analysis.yara_engine import (
    YaraEngine,
    YaraMatch,
    YARA_AVAILABLE,
    _sig_to_yara_hex,
    _safe_identifier,
    _build_yara_source,
)
from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer, Match


# ---------------------------------------------------------------------------
# Unit tests for helpers (always run – no yara dependency)
# ---------------------------------------------------------------------------


class TestYaraHelpers:
    """Test helper functions that don't need yara-python."""

    def test_sig_to_yara_hex_passthrough(self):
        """Signatures already in YARA-compatible format pass through."""
        assert _sig_to_yara_hex("48 01 ?? 48 89 ??") == "48 01 ?? 48 89 ??"

    def test_sig_to_yara_hex_strip_pipes(self):
        assert _sig_to_yara_hex("48|01|??|48|89|??") == "48 01 ?? 48 89 ??"

    def test_sig_to_yara_hex_strip_commas(self):
        assert _sig_to_yara_hex("48,01,??,48,89,??") == "48 01 ?? 48 89 ??"

    def test_safe_identifier_simple(self):
        assert _safe_identifier("vmp_add_64_v1") == "vmp_add_64_v1"

    def test_safe_identifier_leading_digit(self):
        assert _safe_identifier("1bad_name") == "_1bad_name"

    def test_safe_identifier_special_chars(self):
        assert _safe_identifier("my-pattern.v2!") == "my_pattern_v2_"


class TestBuildYaraSource:
    """Test YARA source generation from patterns."""

    def _make_pattern(self, pid="test_add", sig="48 01 C0", variants=None):
        return Pattern(
            pattern_id=pid,
            name=f"Test {pid}",
            signature=sig,
            architecture="x64",
            handler_type="arithmetic",
            operation="add",
            confidence=0.95,
            wildcards="??" in sig,
            variants=variants or [],
        )

    def test_source_single_pattern(self):
        pat = self._make_pattern()
        source, entries = _build_yara_source([pat])
        assert "rule test_add" in source
        assert "{ 48 01 C0 }" in source
        assert len(entries) == 1
        assert entries[0].pattern_id == "test_add"

    def test_source_with_variants(self):
        pat = self._make_pattern(variants=["48 03 C0", "4C 01 C0"])
        source, entries = _build_yara_source([pat])
        assert len(entries) == 3  # main + 2 variants
        assert "rule test_add_v1" in source
        assert "rule test_add_v2" in source

    def test_variant_confidence_penalty(self):
        pat = self._make_pattern(variants=["48 03 C0"])
        _, entries = _build_yara_source([pat])
        main = [e for e in entries if e.variant_index == 0][0]
        var = [e for e in entries if e.variant_index == 1][0]
        assert var.confidence < main.confidence

    def test_wildcard_signature(self):
        pat = self._make_pattern(sig="48 01 ?? 48 89 ??")
        source, entries = _build_yara_source([pat])
        assert "{ 48 01 ?? 48 89 ?? }" in source


# ---------------------------------------------------------------------------
# Integration tests (require yara-python)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
class TestYaraEngine:
    """Integration tests that scan bytes through the YARA engine."""

    def test_compile_from_database(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        engine = YaraEngine()
        count = engine.compile_from_database(db)
        assert count > 0
        assert engine.is_compiled

    def test_scan_finds_add_handler(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        engine = YaraEngine()
        engine.compile_from_database(db)

        # NOPs + ADD signature (48 01 C0 48 89 C1) + NOPs
        payload = b"\x90" * 64 + b"\x48\x01\xC0\x48\x89\xC1" + b"\x90" * 64
        matches = engine.scan(payload)
        add_matches = [m for m in matches if m.pattern_id == "vmp_add_64_v1"]
        assert len(add_matches) >= 1
        assert add_matches[0].offset == 64

    def test_scan_hex_convenience(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        engine = YaraEngine()
        engine.compile_from_database(db)

        nops = "90" * 64
        add_sig = "4801C04889C1"
        matches = engine.scan_hex(nops + add_sig + nops)
        assert any(m.pattern_id == "vmp_add_64_v1" for m in matches)

    def test_scan_no_match_on_zeroes(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        engine = YaraEngine()
        engine.compile_from_database(db)
        matches = engine.scan(b"\x00" * 256)
        assert len(matches) == 0

    def test_min_confidence_filter(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        engine = YaraEngine()
        engine.compile_from_database(db)
        payload = b"\x90" * 16 + b"\x48\x01\xC0\x48\x89\xC1" + b"\x90" * 16
        high = engine.scan(payload, min_confidence=0.99)
        low = engine.scan(payload, min_confidence=0.5)
        assert len(low) >= len(high)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
class TestRecognizerYaraIntegration:
    """Ensure PatternRecognizer correctly delegates to YARA."""

    def test_recognizer_uses_yara(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db, use_yara=True)
        stats = rec.get_statistics()
        assert stats["yara_active"] is True

    def test_recognizer_yara_match(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db, use_yara=True)
        nops = "90" * 128
        add_sig = "4801C04889C1"
        matches = rec.recognize(nops + add_sig + nops, min_confidence=0.5, architecture="x64")
        assert len(matches) >= 1
        assert matches[0].context["match_type"] == "yara"


class TestRecognizerRegexFallback:
    """Validate regex fallback when use_yara=False."""

    def test_fallback_explicit(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db, use_yara=False)
        assert rec.get_statistics()["yara_active"] is False

    def test_fallback_match(self, vmprotect_patterns_path: Path):
        db = PatternDatabase(vmprotect_patterns_path)
        rec = PatternRecognizer(db, use_yara=False)
        nops = "90" * 128
        add_sig = "4801C04889C1"
        matches = rec.recognize(nops + add_sig + nops, min_confidence=0.5, architecture="x64")
        assert len(matches) >= 1
        assert matches[0].pattern.operation == "add"
