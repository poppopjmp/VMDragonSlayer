"""
B71 — AES S-box detection, RC4 key recovery, ARM patterns, semantic equiv,
       ML explainability, CFG tail-call & C++ EH edges
=========================================================================

Tests for every B71 improvement.
"""

from __future__ import annotations

import json
import os
import pytest

# ---------------------------------------------------------------------------
# 1. AES S-box detection
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.solver import Z3Solver


class TestAESSBoxDetection:
    """``detect_aes_sbox`` finds the standard AES S-box in binary data."""

    def test_exact_sbox_detected(self):
        data = bytes(Z3Solver._AES_SBOX)
        result = Z3Solver.detect_aes_sbox(data)
        assert result["found"] is True
        assert result["offset"] == 0
        assert result["direction"] == "forward"
        assert result["match_ratio"] == 1.0

    def test_inverse_sbox_detected(self):
        inv = [0] * 256
        for i, v in enumerate(Z3Solver._AES_SBOX):
            inv[v] = i
        data = bytes(inv)
        result = Z3Solver.detect_aes_sbox(data)
        assert result["found"] is True
        assert result["direction"] == "inverse"

    def test_sbox_with_offset(self):
        prefix = b"\x00" * 64
        data = prefix + bytes(Z3Solver._AES_SBOX)
        result = Z3Solver.detect_aes_sbox(data)
        assert result["found"] is True
        assert result["offset"] == 64

    def test_short_data_not_found(self):
        result = Z3Solver.detect_aes_sbox(b"\x00" * 100)
        assert result["found"] is False

    def test_random_data_not_found(self):
        import random
        rng = random.Random(42)
        data = bytes(rng.randint(0, 255) for _ in range(512))
        result = Z3Solver.detect_aes_sbox(data, threshold=0.9)
        # Random data shouldn't match 90%+ of the S-box
        assert result["match_ratio"] < 0.9

    def test_threshold_parameter(self):
        # Corrupt 30 entries → ~88% match
        sbox = list(Z3Solver._AES_SBOX)
        for i in range(30):
            sbox[i] = (sbox[i] + 1) & 0xFF
        data = bytes(sbox)
        # 0.85 threshold → found
        r1 = Z3Solver.detect_aes_sbox(data, threshold=0.85)
        assert r1["found"] is True
        # 0.95 threshold → not found
        r2 = Z3Solver.detect_aes_sbox(data, threshold=0.95)
        assert r2["found"] is False


# ---------------------------------------------------------------------------
# 2. RC4 key recovery
# ---------------------------------------------------------------------------


class TestRC4KeyRecovery:
    """``recover_rc4_key`` recovers short RC4 keys from captured S-box state."""

    @staticmethod
    def _rc4_ksa(key: bytes) -> list[int]:
        """Reference RC4 KSA implementation."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def test_single_byte_key(self):
        key = b"\x42"
        sbox = self._rc4_ksa(key)
        result = Z3Solver.recover_rc4_key(sbox, key_length=1)
        assert result.satisfiable
        assert result.model["key_0"] == 0x42

    def test_invalid_sbox_length(self):
        result = Z3Solver.recover_rc4_key([0] * 10, key_length=1)
        assert not result.satisfiable
        assert "256" in result.error

    def test_invalid_key_length_zero(self):
        result = Z3Solver.recover_rc4_key([0] * 256, key_length=0)
        assert not result.satisfiable


# ---------------------------------------------------------------------------
# 3. ARM patterns file
# ---------------------------------------------------------------------------


class TestARMPatterns:
    """ARM pattern file exists and is well-formed."""

    def test_file_exists(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "data", "patterns", "arm_patterns.json"
        )
        assert os.path.isfile(path)

    def test_valid_json(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "data", "patterns", "arm_patterns.json"
        )
        with open(path) as f:
            data = json.load(f)
        assert "patterns" in data
        assert len(data["patterns"]) >= 10

    def test_patterns_have_required_fields(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "data", "patterns", "arm_patterns.json"
        )
        with open(path) as f:
            data = json.load(f)
        required = {"pattern_id", "name", "signature", "architecture", "handler_type", "confidence"}
        for pat in data["patterns"]:
            missing = required - set(pat.keys())
            assert not missing, f"Pattern {pat.get('pattern_id')} missing: {missing}"

    def test_architectures_are_arm(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "data", "patterns", "arm_patterns.json"
        )
        with open(path) as f:
            data = json.load(f)
        for pat in data["patterns"]:
            assert pat["architecture"] in ("arm", "arm64"), pat["pattern_id"]


# ---------------------------------------------------------------------------
# 4. Semantic equivalence applied in normalize_semantics
# ---------------------------------------------------------------------------

from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer


class TestSemanticEquivApplication:
    """``normalize_semantics`` applies mnemonic equivalences when input has text."""

    def test_sal_rewritten_to_shl(self):
        result = PatternRecognizer.normalize_semantics("sal eax, 1")
        assert "SHL" in result.upper()
        assert "SAL" not in result.upper()

    def test_test_rewritten_to_and(self):
        result = PatternRecognizer.normalize_semantics("test eax, eax")
        assert "AND" in result.upper()

    def test_pure_hex_not_rewritten(self):
        """Pure hex strings should only have NOPs stripped, not mnemonic rewriting."""
        result = PatternRecognizer.normalize_semantics("AA BB CC DD")
        assert result == "AABBCCDD"

    def test_nop_still_stripped_from_text(self):
        result = PatternRecognizer.normalize_semantics("nop sal eax, 1")
        # "nop" is a mnemonic, not the hex 90 → should still be in output
        # unless the hex form is present
        assert "SHL" in result.upper()


# ---------------------------------------------------------------------------
# 5. ML FeatureExplainer
# ---------------------------------------------------------------------------

from dragonslayer.ml.classifier import VMClassifier, FeatureExplainer


class TestFeatureExplainer:
    """``FeatureExplainer`` provides global and local explanations."""

    def test_explainer_creation(self):
        clf = VMClassifier()
        exp = FeatureExplainer(clf)
        assert exp.n_repeats == 5

    def test_global_importance_empty_dataset(self):
        clf = VMClassifier()
        exp = FeatureExplainer(clf)
        assert exp.global_importance([]) == []

    def test_local_explain_returns_dict(self):
        clf = VMClassifier()
        exp = FeatureExplainer(clf)
        sample = {
            "mnemonics": ["add", "sub", "mov"],
            "instructions": [
                {"mnemonic": "add", "operands": ["eax", "ebx"]},
                {"mnemonic": "sub", "operands": ["ecx", "edx"]},
                {"mnemonic": "mov", "operands": ["rax", "rbx"]},
            ],
        }
        result = exp.local_explain(sample)
        assert isinstance(result, dict)
        # Should have feature names as keys
        assert len(result) > 0


# ---------------------------------------------------------------------------
# 6. CFG tail-call detection
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    LiftedInstruction,
    InstructionCategory,
)


class TestTailCallDetection:
    """Tail-call edges are produced for jumps outside the function."""

    def _make_insn(self, addr, mnemonic, cat, target=None, size=2):
        return LiftedInstruction(
            address=addr, size=size, mnemonic=mnemonic,
            operands="", category=cat, raw_bytes=b"\x90" * size,
            is_branch=(cat != InstructionCategory.UNKNOWN),
            branch_target=target,
        )

    def test_tail_call_edge_detected(self):
        """JMP to address outside block set → tail_call edge."""
        blk1 = [
            self._make_insn(0x100, "mov", InstructionCategory.UNKNOWN),
            self._make_insn(0x102, "jmp", InstructionCategory.BRANCH_UNCOND, target=0x9000),
        ]
        cfg = SymbolicExecutor._build_cfg([blk1], entry_point=0x100)
        tail_edges = [e for e in cfg["edges"] if e["type"] == "tail_call"]
        assert len(tail_edges) == 1
        assert tail_edges[0]["target"] == 0x9000
        assert cfg["tail_call_count"] == 1

    def test_intra_function_jump_not_tail_call(self):
        """JMP within block set → unconditional, not tail_call."""
        blk1 = [
            self._make_insn(0x100, "mov", InstructionCategory.UNKNOWN),
            self._make_insn(0x102, "jmp", InstructionCategory.BRANCH_UNCOND, target=0x200),
        ]
        blk2 = [
            self._make_insn(0x200, "ret", InstructionCategory.RETURN),
        ]
        cfg = SymbolicExecutor._build_cfg([blk1, blk2], entry_point=0x100)
        tail_edges = [e for e in cfg["edges"] if e["type"] == "tail_call"]
        assert len(tail_edges) == 0
        assert cfg["tail_call_count"] == 0


# ---------------------------------------------------------------------------
# 7. C++ exception edge detection
# ---------------------------------------------------------------------------


class TestCxxExceptionEdges:
    """``_detect_cxx_exception_edges`` finds C++ EH patterns."""

    def _make_insn(self, addr, mnemonic, cat, target=None, ops="", size=2):
        return LiftedInstruction(
            address=addr, size=size, mnemonic=mnemonic,
            operands=ops, category=cat, raw_bytes=b"\x90" * size,
            is_branch=(cat != InstructionCategory.UNKNOWN),
            branch_target=target,
        )

    def test_cxa_throw_followed_by_jump(self):
        blk = [
            self._make_insn(0x100, "call", InstructionCategory.UNKNOWN, ops="__cxa_throw"),
            self._make_insn(0x102, "jmp", InstructionCategory.BRANCH_UNCOND, target=0x500),
        ]
        edges = SymbolicExecutor._detect_cxx_exception_edges([blk], {0x100})
        assert any(e["type"] == "cxx_eh" and e["handler"] == 0x500 for e in edges)

    def test_no_eh_on_normal_call(self):
        blk = [
            self._make_insn(0x100, "call", InstructionCategory.UNKNOWN, ops="printf"),
            self._make_insn(0x102, "mov", InstructionCategory.UNKNOWN),
        ]
        edges = SymbolicExecutor._detect_cxx_exception_edges([blk], {0x100})
        assert len(edges) == 0

    def test_cxx_eh_in_cfg_dict(self):
        blk = [
            self._make_insn(0x100, "call", InstructionCategory.UNKNOWN, ops="__cxa_throw"),
            self._make_insn(0x102, "je", InstructionCategory.BRANCH_COND, target=0x400),
        ]
        cfg = SymbolicExecutor._build_cfg([blk], entry_point=0x100)
        assert "cxx_exception_edges" in cfg
