"""
B61 – Mutation-Resilient Pattern Matching
=========================================

Tests for:
  - Junk-instruction filtering (strip_junk, _is_junk_instruction)
  - Register-agnostic operand normalisation (normalize_operands)
  - Gap-tolerant sequence matching (_match_instruction_sequence_gap)
  - End-to-end fallback wiring in PatternClassifier._classify_single
"""

from __future__ import annotations

import pytest

from dragonslayer.analysis.pattern_analysis.classifier import (
    ClassificationResult,
    PatternClassifier,
    _is_junk_instruction,
    _match_instruction_sequence,
    _match_instruction_sequence_gap,
    normalize_operands,
    strip_junk,
)
from dragonslayer.analysis.pattern_analysis.database import HandlerType


# ═══════════════════════════════════════════════════════════════════════════════
# 1. _is_junk_instruction
# ═══════════════════════════════════════════════════════════════════════════════


class TestIsJunkInstruction:
    """Unit tests for junk-instruction detection."""

    @pytest.mark.parametrize(
        "mnem",
        ["nop", "fnop", "pause", "int3", "ud2", "NOP", "Fnop"],
    )
    def test_pure_junk_mnemonics(self, mnem: str):
        assert _is_junk_instruction(mnem) is True

    def test_non_junk_mnemonic(self):
        assert _is_junk_instruction("mov") is False
        assert _is_junk_instruction("push") is False
        assert _is_junk_instruction("add") is False

    def test_identity_mov(self):
        assert _is_junk_instruction("mov", "eax, eax") is True

    def test_identity_xchg(self):
        assert _is_junk_instruction("xchg", "rax, rax") is True

    def test_non_identity_mov(self):
        assert _is_junk_instruction("mov", "eax, ebx") is False

    def test_lea_identity(self):
        assert _is_junk_instruction("lea", "rax, [rax]") is True

    def test_lea_zero_displacement(self):
        assert _is_junk_instruction("lea", "rax, [rax+0]") is True

    def test_lea_non_identity(self):
        assert _is_junk_instruction("lea", "rax, [rbx+8]") is False


# ═══════════════════════════════════════════════════════════════════════════════
# 2. strip_junk
# ═══════════════════════════════════════════════════════════════════════════════


class TestStripJunk:
    """Unit tests for bulk junk-instruction stripping."""

    def test_no_junk(self):
        mnems = ["push", "mov", "add", "pop"]
        assert strip_junk(mnems) == mnems

    def test_nop_removal(self):
        mnems = ["push", "nop", "mov", "nop", "pop"]
        assert strip_junk(mnems) == ["push", "mov", "pop"]

    def test_identity_removal_with_operands(self):
        mnems = ["push", "mov", "mov", "pop"]
        ops = ["rbp", "rax, [rsp]", "eax, eax", "rbp"]
        result = strip_junk(mnems, ops)
        assert result == ["push", "mov", "pop"]

    def test_empty_input(self):
        assert strip_junk([]) == []

    def test_all_junk(self):
        mnems = ["nop", "fnop", "pause"]
        assert strip_junk(mnems) == []


# ═══════════════════════════════════════════════════════════════════════════════
# 3. normalize_operands
# ═══════════════════════════════════════════════════════════════════════════════


class TestNormalizeOperands:
    """Test register-class normalisation."""

    def test_gp64_replacement(self):
        result = normalize_operands("rax, [rbx+0x10]")
        assert "GP64" in result
        assert "rax" not in result

    def test_gp32_replacement(self):
        result = normalize_operands("eax, ecx")
        assert result == "GP32, GP32"

    def test_mixed_size(self):
        result = normalize_operands("mov rax, edx")
        assert "GP64" in result
        assert "GP32" in result

    def test_no_registers(self):
        assert normalize_operands("0x10, [0x4000]") == "0x10, [0x4000]"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. _match_instruction_sequence_gap
# ═══════════════════════════════════════════════════════════════════════════════


class TestGapTolerantMatching:
    """Tests for gap-tolerant (fuzzy) sequence matching."""

    def test_exact_match_no_gap(self):
        assert _match_instruction_sequence_gap(
            ["push", "mov", "xor", "pop", "ret"],
            ["push", "mov", "xor", "pop", "ret"],
        ) is True

    def test_single_gap(self):
        # Pattern [push, pop] with one junk instruction in between
        assert _match_instruction_sequence_gap(
            ["push", "nop", "pop"],
            ["push", "pop"],
            max_gap=1,
        ) is True

    def test_gap_exceeds_limit(self):
        # Pattern [push, pop] with 3 junk instructions between → max_gap=2 fails
        assert _match_instruction_sequence_gap(
            ["push", "nop", "nop", "nop", "pop"],
            ["push", "pop"],
            max_gap=2,
        ) is False

    def test_wildcard_in_pattern(self):
        # * matches any single mnemonic
        assert _match_instruction_sequence_gap(
            ["push", "mov", "xor"],
            ["push", "*", "xor"],
            max_gap=0,
        ) is True

    def test_empty_pattern(self):
        assert _match_instruction_sequence_gap(["push", "pop"], []) is True

    def test_pattern_longer_than_sequence(self):
        assert _match_instruction_sequence_gap(
            ["push"],
            ["push", "mov", "pop"],
        ) is False

    def test_multiple_gaps(self):
        # [push, mov, pop] with gaps between each pair
        assert _match_instruction_sequence_gap(
            ["push", "nop", "mov", "nop", "pop"],
            ["push", "mov", "pop"],
            max_gap=1,
        ) is True

    def test_gap_tolerant_vm_enter_with_junk(self):
        """Realistic VMProtect scenario: vm_enter with interleaved junk."""
        # Standard vm_enter: push, mov, sub
        mutated = ["push", "nop", "mov", "lea", "sub"]
        assert _match_instruction_sequence_gap(
            mutated,
            ["push", "mov", "sub"],
            max_gap=1,
        ) is True


# ═══════════════════════════════════════════════════════════════════════════════
# 5. End-to-end: PatternClassifier with mutation-resilient fallbacks
# ═══════════════════════════════════════════════════════════════════════════════


class TestClassifySingleMutationFallback:
    """Integration tests for the three-tier sequence matching."""

    @pytest.fixture
    def classifier(self) -> PatternClassifier:
        return PatternClassifier()

    def test_strict_match_still_works(self, classifier: PatternClassifier):
        """Original strict match should still fire."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 8,
            handler_name="unknown",
            mnemonics=["push", "mov", "sub"],  # vm_enter pattern
        )
        assert result.handler_type == HandlerType.CONTROL_FLOW
        assert "instruction-seq match" in result.reasoning

    def test_junk_stripped_fallback(self, classifier: PatternClassifier):
        """With nops interleaved, strict fails but junk-stripped succeeds."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 16,
            handler_name="unknown",
            mnemonics=["push", "nop", "mov", "nop", "sub"],
        )
        assert result.handler_type == HandlerType.CONTROL_FLOW
        assert "junk-stripped" in result.reasoning or "gap-tolerant" in result.reasoning

    def test_gap_tolerant_fallback(self, classifier: PatternClassifier):
        """Non-junk filler that still fits max_gap=2 triggers gap-tolerant."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 16,
            handler_name="unknown",
            # push then 2 unique non-junk "fillers", then mov, then sub
            # Using 'cpuid' and 'rdtsc' which don't appear in any signature
            mnemonics=["push", "cpuid", "rdtsc", "mov", "sub"],
        )
        assert result.handler_type == HandlerType.CONTROL_FLOW
        assert "gap-tolerant" in result.reasoning

    def test_no_match_when_pattern_completely_absent(self, classifier: PatternClassifier):
        """Random instructions that don't resemble any known pattern."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 4,
            handler_name="unknown",
            mnemonics=["syscall", "hlt", "mfence"],
        )
        assert result.handler_type == HandlerType.UNKNOWN

    def test_vm_exit_with_junk(self, classifier: PatternClassifier):
        """vm_exit pattern: [mov, pop, ret] with interleaved nops."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 12,
            handler_name="unknown",
            mnemonics=["mov", "nop", "pop", "nop", "ret"],
        )
        assert result.handler_type == HandlerType.CONTROL_FLOW

    def test_arithmetic_with_junk(self, classifier: PatternClassifier):
        """Arithmetic handler mutated with junk nops: [mov, add, mov, mov]."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 16,
            handler_name="unknown",
            mnemonics=["mov", "nop", "add", "mov", "nop", "mov"],
        )
        assert result.handler_type == HandlerType.ARITHMETIC

    def test_classify_single_dict_with_operands(self, classifier: PatternClassifier):
        """_classify_single receives operands for identity detection."""
        match_dict = {
            "pattern_id": "test_1",
            "name": "identity_test",
            "operation": "",
            "handler_type": "unknown",
            "matched_bytes": "00",
            "confidence": 0.5,
            # push, identity mov, nop, mov, sub  → strip produces [push, mov, sub]
            "_mnemonics": ["push", "mov", "nop", "mov", "sub"],
            "_operands": ["rbp", "eax, eax", "", "rsp, rbp", "rsp, 0x80"],
        }
        result = classifier._classify_single(match_dict)
        assert result.handler_type == HandlerType.CONTROL_FLOW

    def test_stack_context_save_with_junk(self, classifier: PatternClassifier):
        """Stack context_save [push, push, push, mov] with junk."""
        result = classifier.classify_handler_bytes(
            raw_bytes=b"\x00" * 12,
            handler_name="unknown",
            mnemonics=["push", "nop", "push", "push", "nop", "mov"],
        )
        assert result.handler_type == HandlerType.STACK
