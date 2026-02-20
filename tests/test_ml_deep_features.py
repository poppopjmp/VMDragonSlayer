"""
Tests for B56 — ML Deep Features + Handler Body Signatures.

Covers:
  1. Trigram feature extraction
  2. Opcode histogram feature extraction
  3. Extended feature vector (130 features)
  4. Instruction-sequence signature matching
  5. PatternClassifier with instruction-sequence pass
"""

from __future__ import annotations

import pytest

from dragonslayer.ml.pipeline import (
    VMPROTECT_TRIGRAMS,
    OPCODE_VOCAB,
    TRIGRAM_FEATURE_NAMES,
    OPCODE_HIST_NAMES,
    EXTENDED_FEATURE_NAMES,
    extract_trigram_features,
    extract_opcode_histogram,
    extract_extended_features,
    extract_bigram_features,
)
from dragonslayer.analysis.pattern_analysis.classifier import (
    PatternClassifier,
    HandlerType,
    _INSTRUCTION_SEQ_SIGNATURES,
    _match_instruction_sequence,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Trigram features
# ═══════════════════════════════════════════════════════════════════════════════

class TestTrigramFeatures:
    """Trigram vocabulary and feature extraction."""

    def test_trigram_vocab_not_empty(self):
        assert len(VMPROTECT_TRIGRAMS) >= 15

    def test_trigram_feature_names_length(self):
        assert len(TRIGRAM_FEATURE_NAMES) == len(VMPROTECT_TRIGRAMS)

    def test_extract_empty(self):
        result = extract_trigram_features([])
        assert len(result) == len(VMPROTECT_TRIGRAMS)
        assert all(v == 0.0 for v in result)

    def test_extract_known_trigram(self):
        # "mov", "add", "mov" is a defined trigram
        result = extract_trigram_features(["mov", "add", "mov"])
        assert len(result) == len(VMPROTECT_TRIGRAMS)
        assert sum(result) > 0  # at least one trigram matched

    def test_extract_unknown_trigrams(self):
        result = extract_trigram_features(["nop", "nop", "nop"])
        assert all(v == 0.0 for v in result)

    def test_normalized(self):
        # 10 instructions → 8 trigrams
        mnems = ["mov", "add", "mov", "sub", "mov", "xor", "mov", "and", "mov", "or"]
        result = extract_trigram_features(mnems)
        assert all(0.0 <= v <= 1.0 for v in result)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Opcode histogram
# ═══════════════════════════════════════════════════════════════════════════════

class TestOpcodeHistogram:
    """Opcode frequency histogram extraction."""

    def test_vocab_size(self):
        assert len(OPCODE_VOCAB) == 32

    def test_hist_names_length(self):
        assert len(OPCODE_HIST_NAMES) == len(OPCODE_VOCAB)

    def test_extract_empty(self):
        result = extract_opcode_histogram([])
        assert len(result) == len(OPCODE_VOCAB)
        assert all(v == 0.0 for v in result)

    def test_extract_single(self):
        result = extract_opcode_histogram(["mov"])
        # "mov" is at index 0 in OPCODE_VOCAB
        idx = OPCODE_VOCAB.index("mov")
        assert result[idx] == 1.0

    def test_extract_mixed(self):
        result = extract_opcode_histogram(["mov", "push", "mov", "xor"])
        idx_mov = OPCODE_VOCAB.index("mov")
        idx_push = OPCODE_VOCAB.index("push")
        idx_xor = OPCODE_VOCAB.index("xor")
        assert result[idx_mov] == 0.5  # 2/4
        assert result[idx_push] == 0.25
        assert result[idx_xor] == 0.25

    def test_normalized(self):
        mnems = ["mov"] * 10 + ["add"] * 5
        result = extract_opcode_histogram(mnems)
        assert all(0.0 <= v <= 1.0 for v in result)
        total = sum(result)
        assert abs(total - 1.0) < 0.01


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Extended features — 130 dimensions
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtendedFeatures:
    """Extended feature vector includes n-gram + histogram features."""

    def test_feature_count(self):
        # 15 base + 25 bigram + 32 reg_effects + 6 operand + 20 trigram + 32 histogram
        assert len(EXTENDED_FEATURE_NAMES) == 15 + 25 + 32 + 6 + len(VMPROTECT_TRIGRAMS) + len(OPCODE_VOCAB)

    def test_extract_extended_returns_correct_length(self):
        handler = {
            "instructions": [
                {"mnemonic": "mov", "operands": "rax, rbx"},
                {"mnemonic": "add", "operands": "rax, 1"},
                {"mnemonic": "mov", "operands": "[rsp], rax"},
            ],
        }
        fv = extract_extended_features(handler)
        assert len(fv.values) == len(EXTENDED_FEATURE_NAMES)
        assert len(fv.feature_names) == len(EXTENDED_FEATURE_NAMES)

    def test_extract_extended_metadata(self):
        handler = {"instructions": []}
        fv = extract_extended_features(handler)
        assert fv.metadata["source"] == "handler_extended"

    def test_feature_names_include_trigrams(self):
        assert any("tg_" in n for n in EXTENDED_FEATURE_NAMES)

    def test_feature_names_include_histogram(self):
        assert any("freq_" in n for n in EXTENDED_FEATURE_NAMES)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Instruction-sequence matching
# ═══════════════════════════════════════════════════════════════════════════════

class TestInstructionSequenceMatching:
    """Test _match_instruction_sequence helper."""

    def test_empty_pattern_matches(self):
        assert _match_instruction_sequence(["mov", "add"], []) is True

    def test_exact_match(self):
        assert _match_instruction_sequence(
            ["mov", "add", "mov"],
            ["mov", "add", "mov"],
        ) is True

    def test_subsequence_match(self):
        assert _match_instruction_sequence(
            ["nop", "mov", "add", "mov", "ret"],
            ["mov", "add", "mov"],
        ) is True

    def test_no_match(self):
        assert _match_instruction_sequence(
            ["mov", "sub", "mov"],
            ["mov", "add", "mov"],
        ) is False

    def test_wildcard_match(self):
        assert _match_instruction_sequence(
            ["cmp", "jne", "mov"],
            ["cmp", "*", "mov"],
        ) is True

    def test_wildcard_any_mnemonic(self):
        assert _match_instruction_sequence(
            ["cmp", "whatever", "mov"],
            ["cmp", "*", "mov"],
        ) is True

    def test_pattern_longer_than_sequence(self):
        assert _match_instruction_sequence(
            ["mov"],
            ["mov", "add", "mov"],
        ) is False

    def test_signature_table_not_empty(self):
        assert len(_INSTRUCTION_SEQ_SIGNATURES) >= 15


# ═══════════════════════════════════════════════════════════════════════════════
# 5. PatternClassifier instruction-sequence pass
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifierInstructionSeq:
    """PatternClassifier uses instruction-sequence signatures."""

    def test_classify_with_mnemonics_vm_enter(self):
        cls = PatternClassifier()
        result = cls.classify_handler_bytes(
            b"\x55\x48\x89\xe5\x48\x83\xec\x20",
            handler_name="unknown",
            mnemonics=["push", "mov", "sub"],
        )
        assert result.handler_type == HandlerType.CONTROL_FLOW
        assert "vm_enter" in result.sub_category

    def test_classify_with_mnemonics_arithmetic(self):
        cls = PatternClassifier()
        result = cls.classify_handler_bytes(
            b"\x00" * 4,
            handler_name="unknown",
            mnemonics=["mov", "add", "mov", "mov"],
        )
        assert result.handler_type == HandlerType.ARITHMETIC

    def test_classify_with_mnemonics_crypto(self):
        cls = PatternClassifier()
        result = cls.classify_handler_bytes(
            b"\x00",
            handler_name="unknown",
            mnemonics=["xor", "rol", "xor"],
        )
        assert result.handler_type == HandlerType.CRYPTO

    def test_classify_without_mnemonics_falls_back(self):
        cls = PatternClassifier()
        # No mnemonics → falls through to byte heuristic
        result = cls.classify_handler_bytes(
            b"\x01\x00",  # ADD opcode prefix
            handler_name="unknown",
        )
        assert result.handler_type == HandlerType.ARITHMETIC

    def test_classify_known_name_still_uses_keyword(self):
        cls = PatternClassifier()
        # Name contains "xor" → keyword match wins before seq match
        result = cls.classify_handler_bytes(
            b"\x00",
            handler_name="vm_xor_handler",
            mnemonics=["mov", "xor", "mov", "mov"],
        )
        assert result.handler_type == HandlerType.BITWISE

    def test_instruction_seq_reasoning(self):
        cls = PatternClassifier()
        result = cls.classify_handler_bytes(
            b"\x00",
            handler_name="unknown_handler",
            mnemonics=["xor", "bswap", "xor"],
        )
        assert "instruction-seq" in result.reasoning
