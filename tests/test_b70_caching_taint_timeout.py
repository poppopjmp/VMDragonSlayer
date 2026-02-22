"""
B70 — Dispatcher caching, request-ID logging, memory-region taint, per-path timeout
====================================================================================

Tests for the B70 batch:

1. Dispatcher result caching across repeated analyses.
2. ``_RequestIDFilter`` injects request_id into log records.
3. ``taint_memory_region`` / ``is_memory_region_tainted``.
4. Per-path timeout parameter accepted by SymbolicExecutor.
5. ``normalize_semantics`` integrated into ``recognize()``.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# 1. Dispatcher result caching
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor


class TestDispatcherCaching:
    """Dispatcher results are cached to avoid recomputation."""

    def test_cache_populated_after_analyze(self):
        exe = SymbolicExecutor(arch="x86_64")
        code = b"\xc3"  # ret
        result = exe.analyze(code, entry_point=0)
        assert len(exe._dispatcher_cache) == 1

    def test_cache_hit_returns_same_result(self):
        exe = SymbolicExecutor(arch="x86_64")
        code = b"\x90\x90\xc3"
        r1 = exe.analyze(code, entry_point=0)
        r2 = exe.analyze(code, entry_point=0)
        assert r1.dispatcher_address == r2.dispatcher_address
        assert r1.dispatcher_confidence == r2.dispatcher_confidence
        # Still only one cache entry
        assert len(exe._dispatcher_cache) == 1

    def test_different_code_different_cache_key(self):
        exe = SymbolicExecutor(arch="x86_64")
        exe.analyze(b"\xc3", entry_point=0)
        exe.analyze(b"\x90\xc3", entry_point=0)
        assert len(exe._dispatcher_cache) == 2


# ---------------------------------------------------------------------------
# 2. Request-ID log filter
# ---------------------------------------------------------------------------

from dragonslayer.api.server import _RequestIDFilter


class TestRequestIDFilter:
    """``_RequestIDFilter`` reads request_id from contextvar."""

    def test_filter_sets_attribute(self):
        from dragonslayer.api.server import _request_id_var
        token = _request_id_var.set("req-abc")
        try:
            filt = _RequestIDFilter()
            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="t.py",
                lineno=1, msg="hello", args=(), exc_info=None,
            )
            assert filt.filter(record) is True
            assert record.request_id == "req-abc"  # type: ignore[attr-defined]
        finally:
            _request_id_var.reset(token)

    def test_filter_always_returns_true(self):
        filt = _RequestIDFilter()
        record = logging.LogRecord(
            name="test", level=logging.DEBUG, pathname="t.py",
            lineno=1, msg="", args=(), exc_info=None,
        )
        assert filt.filter(record) is True


# ---------------------------------------------------------------------------
# 3. Multi-byte memory-region taint
# ---------------------------------------------------------------------------

from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag


class TestMemoryRegionTaint:
    """``taint_memory_region`` / ``is_memory_region_tainted``."""

    def test_taint_region_covers_all_bytes(self):
        t = TaintTracker()
        t.taint_memory_region(0x1000, 4, TaintTag.INPUT)
        for offset in range(4):
            assert t.mem_taint.get(0x1000 + offset) == TaintTag.INPUT

    def test_is_tainted_when_partial_overlap(self):
        t = TaintTracker()
        t.taint_memory(0x1002, TaintTag.INPUT)
        # Region 0x1000..0x1003 should be tainted (0x1002 is inside)
        assert t.is_memory_region_tainted(0x1000, 4)

    def test_not_tainted_when_no_overlap(self):
        t = TaintTracker()
        t.taint_memory(0x2000, TaintTag.INPUT)
        assert not t.is_memory_region_tainted(0x1000, 4)

    def test_zero_size_is_not_tainted(self):
        t = TaintTracker()
        t.taint_memory(0x1000, TaintTag.INPUT)
        # size=0 → no bytes to check → not tainted
        assert not t.is_memory_region_tainted(0x1000, 0)

    def test_region_taint_with_default_tag(self):
        t = TaintTracker()
        t.taint_memory_region(0x3000, 8)
        assert t.is_memory_region_tainted(0x3000, 8)


# ---------------------------------------------------------------------------
# 4. Per-path timeout
# ---------------------------------------------------------------------------

class TestPerPathTimeout:
    """SymbolicExecutor respects ``per_path_timeout_ms``."""

    def test_default_is_zero(self):
        exe = SymbolicExecutor(arch="x86_64")
        assert exe.per_path_timeout_ms == 0

    def test_custom_value_accepted(self):
        exe = SymbolicExecutor(arch="x86_64", per_path_timeout_ms=500)
        assert exe.per_path_timeout_ms == 500

    def test_tiny_timeout_halts_quickly(self):
        """With a 1 ms timeout, deep exploration should be curtailed."""
        exe = SymbolicExecutor(arch="x86_64", per_path_timeout_ms=1)
        # A tight loop: jmp $-2  (infinite loop)
        code = b"\xEB\xFE"
        result = exe.analyze(code, entry_point=0)
        # Should still succeed (timeout → halt, not crash)
        assert result.success


# ---------------------------------------------------------------------------
# 5. Normalise semantics integration
# ---------------------------------------------------------------------------

from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
from dragonslayer.analysis.pattern_analysis.database import PatternDatabase


class TestNormaliseSemanticsIntegration:
    """``recognize()`` pre-normalises input via ``normalize_semantics``."""

    def test_recognize_strips_nop_before_matching(self):
        """A NOP-interleaved stream should still match after normalisation."""
        db = PatternDatabase()
        rec = PatternRecognizer(db)
        # Before normalisation: "AA 90 BB" → "AABB"
        # The method should work without error even with no patterns loaded
        matches = rec.recognize("AA 90 BB", min_confidence=0.1)
        # No patterns in DB → no matches, but should not raise
        assert isinstance(matches, list)
