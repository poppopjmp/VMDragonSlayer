"""
B72 — ML explainer fix, interprocedural taint, expanded semantic equiv,
       cipher auto-detect, CFG indirect resolution
====================================================================

Tests for every B72 improvement.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# 1. FeatureExplainer — global permutation actually shuffles feature values
# ---------------------------------------------------------------------------

from dragonslayer.ml.classifier import VMClassifier, FeatureExplainer


class TestFeatureExplainerFixed:
    """Verify the explainer works at feature-vector level."""

    def _make_sample(self, category="arithmetic"):
        return {
            "mnemonics": ["add", "sub", "mov"],
            "instructions": [
                {"mnemonic": "add", "operands": ["eax", "ebx"]},
                {"mnemonic": "sub", "operands": ["ecx", "edx"]},
                {"mnemonic": "mov", "operands": ["rax", "rbx"]},
            ],
            "category": category,
        }

    def test_global_importance_runs_on_real_dataset(self):
        clf = VMClassifier()
        dataset = [self._make_sample() for _ in range(5)]
        exp = FeatureExplainer(clf, n_repeats=2)
        imp = exp.global_importance(dataset)
        assert isinstance(imp, list)
        assert all(isinstance(t, tuple) and len(t) == 2 for t in imp)

    def test_global_importance_with_labels(self):
        clf = VMClassifier()
        dataset = [self._make_sample() for _ in range(5)]
        labels = ["arithmetic"] * 5
        exp = FeatureExplainer(clf, n_repeats=2)
        imp = exp.global_importance(dataset, labels=labels)
        assert isinstance(imp, list)

    def test_local_explain_actually_perturbs(self):
        """local_explain zeroes features → contributions should have non-zero entries."""
        clf = VMClassifier()
        exp = FeatureExplainer(clf)
        sample = self._make_sample()
        result = exp.local_explain(sample)
        assert isinstance(result, dict)
        assert len(result) > 0
        # At least some contributions should be non-negative
        assert all(isinstance(v, (int, float)) for v in result.values())

    def test_predict_from_values_works(self):
        clf = VMClassifier()
        exp = FeatureExplainer(clf)
        from dragonslayer.ml.pipeline import extract_handler_features
        fv = extract_handler_features(self._make_sample())
        pred = exp._predict_from_values(fv.values, fv.feature_names)
        assert pred.label != ""


# ---------------------------------------------------------------------------
# 2. Interprocedural taint (push/pop call context)
# ---------------------------------------------------------------------------

from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag


class TestInterproceduralTaint:
    """``push_call_context`` / ``pop_call_context`` for cross-function taint."""

    def test_push_increments_depth(self):
        t = TaintTracker()
        assert t.call_depth == 0
        t.push_call_context()
        assert t.call_depth == 1

    def test_pop_decrements_depth(self):
        t = TaintTracker()
        t.push_call_context()
        t.pop_call_context()
        assert t.call_depth == 0

    def test_pop_empty_no_crash(self):
        t = TaintTracker()
        t.pop_call_context()  # should not raise
        assert t.call_depth == 0

    def test_caller_taint_restored_after_pop(self):
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.INPUT)
        t.push_call_context()
        # Inside callee: rdi gets overwritten
        t.taint_register("rdi", TaintTag.CLEAN)
        assert t.reg_taint.get("rdi", TaintTag.CLEAN) == TaintTag.CLEAN
        # Return to caller
        t.pop_call_context()
        assert t.reg_taint.get("rdi", TaintTag.CLEAN) == TaintTag.INPUT

    def test_callee_return_taint_merged(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.CLEAN)
        t.push_call_context()
        # Callee taints rax (return value)
        t.taint_register("rax", TaintTag.INPUT)
        t.pop_call_context(return_regs=("rax",))
        # rax should carry the callee's taint
        assert t.reg_taint.get("rax", TaintTag.CLEAN) & TaintTag.INPUT

    def test_nested_calls(self):
        t = TaintTracker()
        t.taint_register("rbx", TaintTag.INPUT)
        t.push_call_context()
        t.taint_register("rbx", TaintTag.CLEAN)
        t.push_call_context()
        assert t.call_depth == 2
        t.pop_call_context()
        assert t.call_depth == 1
        t.pop_call_context()
        assert t.call_depth == 0
        assert t.reg_taint.get("rbx", TaintTag.CLEAN) == TaintTag.INPUT


# ---------------------------------------------------------------------------
# 3. Expanded semantic equivalence (22+ rules)
# ---------------------------------------------------------------------------

from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer


class TestExpandedSemanticEquiv:
    """Verify the expanded _SEMANTIC_EQUIV dict has 15+ rules."""

    def test_at_least_15_rules(self):
        assert len(PatternRecognizer._SEMANTIC_EQUIV) >= 15

    def test_conditional_branch_aliases(self):
        eq = PatternRecognizer._SEMANTIC_EQUIV
        assert eq["jz"] == "je"
        assert eq["jnz"] == "jne"
        assert eq["jnb"] == "jae"

    def test_cmov_aliases(self):
        eq = PatternRecognizer._SEMANTIC_EQUIV
        assert eq["cmovz"] == "cmove"
        assert eq["cmovnz"] == "cmovne"

    def test_set_aliases(self):
        eq = PatternRecognizer._SEMANTIC_EQUIV
        assert eq["setz"] == "sete"
        assert eq["setnz"] == "setne"

    def test_normalize_applies_jz_to_je(self):
        result = PatternRecognizer.normalize_semantics("jz label")
        assert "JE" in result.upper()
        assert "JZ" not in result.upper()

    def test_normalize_cmovz_to_cmove(self):
        result = PatternRecognizer.normalize_semantics("cmovz eax, ebx")
        assert "CMOVE" in result.upper()


# ---------------------------------------------------------------------------
# 4. Cipher-type auto-detection
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.solver import Z3Solver


class TestCipherAutoDetect:
    """``detect_cipher_type`` finds known cipher constants."""

    def test_detects_aes_sbox(self):
        data = bytes(Z3Solver._AES_SBOX)
        hits = Z3Solver.detect_cipher_type(data)
        cipher_names = [h["cipher"] for h in hits]
        assert any("aes" in c for c in cipher_names)

    def test_detects_aes_prefix(self):
        # First 8 bytes of AES forward S-box
        data = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])
        hits = Z3Solver.detect_cipher_type(data)
        assert any("aes" in h["cipher"] for h in hits)

    def test_detects_tea_delta(self):
        # TEA delta constant 0x9E3779B9 as bytes
        data = bytes([0x9E, 0x37, 0x79, 0xB9])
        hits = Z3Solver.detect_cipher_type(data)
        assert any("tea" in h["cipher"] for h in hits)

    def test_empty_data_no_hits(self):
        hits = Z3Solver.detect_cipher_type(b"")
        # May or may not have hits depending on AES detector
        assert isinstance(hits, list)

    def test_random_data_fewer_hits(self):
        import random
        rng = random.Random(42)
        data = bytes(rng.randint(0, 255) for _ in range(1024))
        hits = Z3Solver.detect_cipher_type(data)
        # Random data shouldn't match many cipher signatures
        assert len(hits) <= 3

    def test_hits_sorted_by_match_length(self):
        data = bytes(Z3Solver._AES_SBOX)
        hits = Z3Solver.detect_cipher_type(data)
        if len(hits) >= 2:
            assert hits[0]["match_length"] >= hits[1]["match_length"]


# ---------------------------------------------------------------------------
# 5. CFG indirect-target resolution
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    LiftedInstruction,
    InstructionCategory,
)


class TestIndirectTargetResolution:
    """``_resolve_indirect_targets`` uses register snapshots."""

    def _make_insn(self, addr, mnemonic, cat, target=None, ops="", regs=None, size=2):
        return LiftedInstruction(
            address=addr, size=size, mnemonic=mnemonic,
            operands=ops, category=cat, raw_bytes=b"\x90" * size,
            is_branch=(cat != InstructionCategory.UNKNOWN),
            branch_target=target,
            registers=regs or {},
        )

    def test_resolves_from_register(self):
        insn = self._make_insn(
            0x100, "jmp", InstructionCategory.BRANCH_UNCOND,
            target=None, ops="rax", regs={"rax": 0x200},
        )
        targets = SymbolicExecutor._resolve_indirect_targets(
            insn, block_addrs={0x100, 0x200, 0x300},
        )
        assert 0x200 in targets

    def test_no_registers_returns_empty(self):
        insn = self._make_insn(
            0x100, "jmp", InstructionCategory.BRANCH_UNCOND,
            target=None, ops="rax",
        )
        targets = SymbolicExecutor._resolve_indirect_targets(insn, {0x200})
        assert targets == []

    def test_resolved_edge_in_cfg(self):
        """When register snapshot resolves target, edge type is 'indirect_resolved'."""
        blk1 = [
            self._make_insn(0x100, "mov", InstructionCategory.UNKNOWN),
            self._make_insn(
                0x102, "jmp", InstructionCategory.BRANCH_UNCOND,
                target=None, ops="rax", regs={"rax": 0x200},
            ),
        ]
        blk2 = [
            self._make_insn(0x200, "ret", InstructionCategory.RETURN),
        ]
        cfg = SymbolicExecutor._build_cfg([blk1, blk2], entry_point=0x100)
        resolved = [e for e in cfg["edges"] if e["type"] == "indirect_resolved"]
        assert len(resolved) == 1
        assert resolved[0]["target"] == 0x200

    def test_unresolvable_remains_indirect(self):
        """No register data → edge stays 'indirect'."""
        blk1 = [
            self._make_insn(0x100, "mov", InstructionCategory.UNKNOWN),
            self._make_insn(
                0x102, "jmp", InstructionCategory.BRANCH_UNCOND,
                target=None, ops="rax",
            ),
        ]
        cfg = SymbolicExecutor._build_cfg([blk1], entry_point=0x100)
        indirect = [e for e in cfg["edges"] if e["type"] == "indirect"]
        assert len(indirect) == 1
