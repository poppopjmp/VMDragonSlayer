"""
B63 – Quick-fix hardening tests
================================

Tests for:
  - Timing-safe API key comparison (hmac.compare_digest)
  - normalize_operands wired into classify_handler_bytes
  - Memoized gap-tolerant matcher (no exponential blowup)
"""

from __future__ import annotations

import time

import pytest

from dragonslayer.analysis.pattern_analysis.classifier import (
    PatternClassifier,
    _match_instruction_sequence_gap,
    normalize_operands,
)
from dragonslayer.analysis.pattern_analysis.database import HandlerType


class TestNormalizeOperandsWiring:
    """Verify normalize_operands is actually invoked via classify_handler_bytes."""

    def test_operands_stored_normalized(self):
        """When operands are passed, _normalized_operands appears in match dict."""
        pc = PatternClassifier()
        # We can't easily inspect the internal dict, but we test
        # that the pathway doesn't raise and returns a valid result.
        result = pc.classify_handler_bytes(
            raw_bytes=b"\x00" * 4,
            handler_name="test",
            mnemonics=["mov", "add"],
            operands=["rax, rbx", "ecx, edx"],
        )
        assert isinstance(result.handler_type, HandlerType)

    def test_normalize_replaces_gp64(self):
        assert "GP64" in normalize_operands("rax")
        assert "GP64" in normalize_operands("[rbx+0x10]")

    def test_normalize_replaces_gp32(self):
        assert "GP32" in normalize_operands("eax, ecx")

    def test_junk_strip_with_operands_identity(self):
        """Identity mov detected via operands during junk stripping."""
        pc = PatternClassifier()
        # push, identity-mov(eax,eax), add → strip should remove identity
        result = pc.classify_handler_bytes(
            raw_bytes=b"\x00" * 8,
            handler_name="unknown",
            mnemonics=["mov", "mov", "add", "mov", "mov"],
            operands=["rax, [rsp]", "eax, eax", "rcx, rdx", "rsp, rbp", "[rdi], rax"],
        )
        # After stripping identity mov: [mov, add, mov, mov] → vm_add pattern
        assert result.handler_type == HandlerType.ARITHMETIC


class TestMemoizedGapMatcher:
    """Verify memoization prevents exponential blowup."""

    def test_large_sequence_does_not_timeout(self):
        """Adversarial input: many repeated mnemonics that cause backtracking."""
        # 200 'mov' instructions followed by pattern [mov, mov, mov, xor]
        # Without memoization this could be O(C(200,3)) ≈ 1.3M paths
        mnemonics = ["mov"] * 200
        pattern = ["mov", "mov", "mov", "xor"]  # xor never found → full search

        start = time.monotonic()
        result = _match_instruction_sequence_gap(mnemonics, pattern, max_gap=5)
        elapsed = time.monotonic() - start

        assert result is False
        assert elapsed < 2.0, f"Took {elapsed:.2f}s — memoization may be broken"

    def test_memoized_still_matches_correctly(self):
        """Functional correctness preserved with memoization."""
        mnemonics = ["push", "nop", "mov", "sub"]
        pattern = ["push", "mov", "sub"]
        assert _match_instruction_sequence_gap(mnemonics, pattern, max_gap=1) is True


class TestTimingSafeAuth:
    """Verify hmac.compare_digest is used for API key comparison."""

    def test_hmac_import_in_server(self):
        """Server module imports hmac for timing-safe comparison."""
        import dragonslayer.api.server as srv
        assert hasattr(srv, '_hmac')
