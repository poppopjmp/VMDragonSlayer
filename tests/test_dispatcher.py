"""Tests for the dispatcher push/ret sequence detection."""

import struct
from dragonslayer.analysis.vm_discovery.dispatcher import (
    DispatcherAnalyzer,
    DispatcherInfo,
    DispatchTableResult,
    HandlerEntry,
)


class TestPushRetDetection:
    """Tests for _find_push_ret_sequences."""

    def test_single_push_ret(self):
        """Detect a single push imm32; ret sequence."""
        analyzer = DispatcherAnalyzer()
        addr = 0x00401000
        # push 0x00401000 ; ret
        seq = b"\x68" + struct.pack("<I", addr) + b"\xC3"
        data = b"\x90" * 64 + seq + b"\x90" * 64
        results = analyzer._find_push_ret_sequences(data)
        assert len(results) == 1
        offset, pushed = results[0]
        assert offset == 64
        assert pushed == addr

    def test_multiple_push_ret(self):
        """Detect multiple push/ret sequences."""
        analyzer = DispatcherAnalyzer()
        seq1 = b"\x68" + struct.pack("<I", 0x00401000) + b"\xC3"
        seq2 = b"\x68" + struct.pack("<I", 0x00402000) + b"\xC3"
        data = seq1 + b"\x90" * 10 + seq2
        results = analyzer._find_push_ret_sequences(data)
        assert len(results) == 2
        assert results[0][1] == 0x00401000
        assert results[1][1] == 0x00402000

    def test_push_without_ret_skipped(self):
        """push imm32 NOT followed by ret should be ignored."""
        analyzer = DispatcherAnalyzer()
        # push 0x00401000 ; nop (not ret)
        seq = b"\x68" + struct.pack("<I", 0x00401000) + b"\x90"
        data = b"\x90" * 16 + seq + b"\x90" * 16
        results = analyzer._find_push_ret_sequences(data)
        assert len(results) == 0

    def test_push_zero_skipped(self):
        """push 0 ; ret should be skipped (null pointers aren't code)."""
        analyzer = DispatcherAnalyzer()
        seq = b"\x68" + struct.pack("<I", 0) + b"\xC3"
        data = seq
        results = analyzer._find_push_ret_sequences(data)
        assert len(results) == 0

    def test_push_tiny_constant_skipped(self):
        """push <small constant> ; ret should be skipped."""
        analyzer = DispatcherAnalyzer()
        seq = b"\x68" + struct.pack("<I", 0x0100) + b"\xC3"
        data = seq
        results = analyzer._find_push_ret_sequences(data)
        assert len(results) == 0

    def test_image_base_filtering(self):
        """Addresses below image_base are rejected."""
        analyzer = DispatcherAnalyzer()
        seq = b"\x68" + struct.pack("<I", 0x00401000) + b"\xC3"
        data = seq
        # image_base = 0x00500000 → 0x00401000 is too low
        results = analyzer._find_push_ret_sequences(data, image_base=0x00500000)
        assert len(results) == 0
        # Without image_base it should pass
        results = analyzer._find_push_ret_sequences(data)
        assert len(results) == 1


class TestDispatcherAnalyzerPushRet:
    """Integration: push/ret results flow through analyze()."""

    def test_analyze_push_ret_creates_entries(self):
        """analyze() should include push/ret targets in handler_table."""
        analyzer = DispatcherAnalyzer()
        addr = 0x00401000
        seq = b"\x68" + struct.pack("<I", addr) + b"\xC3"
        data = b"\x90" * 128 + seq + b"\x90" * 128

        result = analyzer.analyze(data)
        assert result.success
        # Should find at least the push/ret target in handler table
        push_ret_handlers = [
            h for h in result.handler_table if h.category == "push_ret_target"
        ]
        assert len(push_ret_handlers) >= 1
        assert push_ret_handlers[0].handler_address == addr

    def test_analyze_push_ret_dispatcher(self):
        """analyze() should register a push_ret dispatcher."""
        analyzer = DispatcherAnalyzer()
        seq1 = b"\x68" + struct.pack("<I", 0x00401000) + b"\xC3"
        seq2 = b"\x68" + struct.pack("<I", 0x00402000) + b"\xC3"
        data = seq1 + b"\x90" * 10 + seq2

        result = analyzer.analyze(data)
        assert result.success
        pr_dispatchers = [
            d for d in result.dispatchers if d.dispatch_type == "push_ret"
        ]
        assert len(pr_dispatchers) >= 1
        assert pr_dispatchers[0].handler_count == 2
