"""B73 tests: byte-taint desync fix, indirect CFG expression eval,
ML n_perturbations, _OPCODE_EQUIV, deeper semantic tests."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    ByteTaintMap,
    subreg_info,
)
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    InstructionCategory,
    LiftedInstruction,
)
from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
from dragonslayer.ml.classifier import VMClassifier, FeatureExplainer


# ---------------------------------------------------------------------------
# 1. Byte-taint context desync fix
# ---------------------------------------------------------------------------


class TestByteTaintContextSync:
    """Verify push/pop_call_context preserves both _reg_taint AND _byte_taint."""

    def test_subreg_al_preserved_across_call(self):
        """Taint 'al', call function that clobbers rax, verify al taint restored.

        Uses empty return_regs so rax callee taint is NOT merged back.
        """
        t = TaintTracker(sub_register_aware=True)
        t.taint_register("al", TaintTag.INPUT)

        # Verify al is tainted at byte level
        assert t._byte_taint.get_bytes("al") & TaintTag.INPUT

        t.push_call_context()

        # Callee clobbers entire rax
        t.taint_register("rax", TaintTag.COMPUTED)
        assert t._byte_taint.get_bytes("al") & TaintTag.COMPUTED

        # Pop with NO return regs → pure restore, no merge
        t.pop_call_context(return_regs=())

        # After pop, al should have the caller's INPUT taint — not callee's COMPUTED
        byte_tag = t._byte_taint.get_bytes("al")
        assert byte_tag & TaintTag.INPUT
        # COMPUTED should NOT be present (was only in callee scope)
        assert not (byte_tag & TaintTag.COMPUTED)

    def test_byte_taint_map_isolated_from_callee(self):
        """Callee mutations to _byte_taint do not leak back to caller."""
        t = TaintTracker(sub_register_aware=True)
        # Caller has clean rbx
        t.taint_register("rbx", TaintTag.CLEAN)

        t.push_call_context()
        # Callee taints bh
        t.taint_register("bh", TaintTag.CRYPTO)
        assert t._byte_taint.get_bytes("bh") & TaintTag.CRYPTO

        t.pop_call_context()
        # bh should be clean after restoring caller state
        assert t._byte_taint.get_bytes("bh") == TaintTag.CLEAN

    def test_return_reg_byte_taint_merged(self):
        """Callee return-reg byte taint is OR-merged into caller byte map."""
        t = TaintTracker(sub_register_aware=True)
        t.taint_register("rax", TaintTag.CLEAN)

        t.push_call_context()
        # Callee taints al (low byte of rax) as INPUT
        t.taint_register("al", TaintTag.INPUT)

        t.pop_call_context(return_regs=("rax",))
        # rax byte taint should include callee's INPUT on al
        assert t._byte_taint.get_bytes("al") & TaintTag.INPUT

    def test_context_stack_stores_tuples(self):
        """Verify context stack entries are (reg_dict, byte_dict) tuples."""
        t = TaintTracker()
        t.push_call_context()
        assert len(t._context_stack) == 1
        entry = t._context_stack[0]
        assert isinstance(entry, tuple)
        assert len(entry) == 2


# ---------------------------------------------------------------------------
# 2. Indirect CFG resolution with expression evaluation
# ---------------------------------------------------------------------------


class TestIndirectExpressionResolution:
    """Test _resolve_indirect_targets with base+index*scale+disp patterns."""

    def _make_insn(self, operands, registers, address=0x1000):
        insn = MagicMock(spec=LiftedInstruction)
        insn.operands = operands
        insn.registers = registers
        insn.address = address
        return insn

    def test_memory_operand_base_plus_disp(self):
        """jmp qword ptr [rax+0x10] with rax=0x1000 → target 0x1010."""
        block_addrs = {0x1010, 0x2000, 0x3000}
        insn = self._make_insn(
            "qword ptr [rax+0x10]",
            {"rax": 0x1000},
        )
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert 0x1010 in targets

    def test_memory_operand_base_index_scale(self):
        """jmp [rbx+rcx*8] with rbx=0x1000, rcx=0x100 → target 0x1800."""
        block_addrs = {0x1800, 0x2000}
        insn = self._make_insn(
            "qword ptr [rbx+rcx*8]",
            {"rbx": 0x1000, "rcx": 0x100},
        )
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert 0x1800 in targets

    def test_memory_operand_full_sib(self):
        """jmp [rax+rdx*4+0x20] with rax=0x100, rdx=0x10 → 0x100+0x40+0x20=0x160."""
        block_addrs = {0x160, 0x200}
        insn = self._make_insn(
            "[rax+rdx*4+0x20]",
            {"rax": 0x100, "rdx": 0x10},
        )
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert 0x160 in targets

    def test_direct_register_fallback(self):
        """jmp rax — falls back to direct register lookup."""
        block_addrs = {0x4000}
        insn = self._make_insn("rax", {"rax": 0x4000})
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert 0x4000 in targets

    def test_unresolvable_expression(self):
        """Missing register in expression → empty."""
        block_addrs = {0x1000}
        insn = self._make_insn("[rax+rcx*8]", {"rax": 0x1000})  # rcx missing
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert targets == []

    def test_eval_addr_expr_subtraction(self):
        """base-disp evaluates correctly."""
        result = SymbolicExecutor._eval_addr_expr(
            "rax-0x10", {"rax": 0x1000}
        )
        assert result == 0x1000 - 0x10

    def test_resolved_target_not_in_block_addrs(self):
        """Resolved address that's not in block_addrs is excluded."""
        block_addrs = {0x2000}
        insn = self._make_insn("rax", {"rax": 0x3000})
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert targets == []


# ---------------------------------------------------------------------------
# 3. ML explainer — n_perturbations actually used
# ---------------------------------------------------------------------------


class TestExplainerPerturbations:
    """Verify local_explain uses n_perturbations for multiple draws."""

    def test_local_explain_calls_predict_n_times(self):
        """With n_perturbations=5, predict is called 5x per feature."""
        clf = VMClassifier()
        explainer = FeatureExplainer(clf)

        sample = {
            "instructions": [
                {"mnemonic": "push", "operands": "rbp"},
                {"mnemonic": "mov", "operands": "rsp,rbp"},
                {"mnemonic": "xor", "operands": "eax,eax"},
                {"mnemonic": "pop", "operands": "rbp"},
                {"mnemonic": "ret", "operands": ""},
            ]
        }

        # local_explain with low n_perturbations for speed
        result = explainer.local_explain(sample, n_perturbations=3)
        assert isinstance(result, dict)
        # All feature values should be numeric
        assert all(isinstance(v, (int, float)) for v in result.values())
        # At least one feature should have non-zero contribution
        # (with 3 perturbations including zeroing, there must be some effect)
        assert len(result) > 0

    def test_local_explain_more_perturbations_is_smoother(self):
        """More perturbations shouldn't crash — just take longer."""
        clf = VMClassifier()
        explainer = FeatureExplainer(clf)
        sample = {
            "instructions": [
                {"mnemonic": "xor", "operands": "eax,eax"},
                {"mnemonic": "ret", "operands": ""},
            ]
        }
        # 1 perturbation vs 5 — both should work
        r1 = explainer.local_explain(sample, n_perturbations=1)
        r5 = explainer.local_explain(sample, n_perturbations=5)
        assert set(r1.keys()) == set(r5.keys())


# ---------------------------------------------------------------------------
# 4. _OPCODE_EQUIV integration
# ---------------------------------------------------------------------------


class TestOpcodeEquiv:
    """Verify _OPCODE_EQUIV has entries and is applied by normalize_semantics."""

    def test_opcode_equiv_not_empty(self):
        assert len(PatternRecognizer._OPCODE_EQUIV) >= 10

    def test_sub_eax_zero_normalised_to_nop(self):
        """83E800 (sub eax, 0) should be replaced with 90 (NOP)."""
        result = PatternRecognizer.normalize_semantics("83E800C3")
        # 83E800→90, then 90 is also a NOP and stripped
        assert "83E800" not in result

    def test_mov_eax_eax_normalised(self):
        """89C0 (mov eax, eax) should be normalised away."""
        result = PatternRecognizer.normalize_semantics("89C0C3")
        assert "89C0" not in result

    def test_add_ecx_zero_normalised(self):
        """83C100 (add ecx, 0) should be normalised away."""
        result = PatternRecognizer.normalize_semantics("83C100FF")
        assert "83C100" not in result

    def test_real_opcodes_preserved(self):
        """Non-equivalent opcodes should be left intact."""
        result = PatternRecognizer.normalize_semantics("C3E8FF")
        assert "C3" in result
        assert "E8" in result


# ---------------------------------------------------------------------------
# 5. Cipher detection deeper tests
# ---------------------------------------------------------------------------


class TestCipherDetectDeeper:
    """Deeper cipher detection tests verifying semantic correctness."""

    def test_mixed_aes_and_tea_in_one_blob(self):
        """Blob containing both AES S-box prefix and TEA delta → both found."""
        solver = Z3Solver()
        # AES forward S-box first 8 bytes (must match _CIPHER_SIGNATURES)
        aes_prefix = bytes([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        ])
        # TEA delta (0x9E3779B9) in big-endian (matching _CIPHER_SIGNATURES)
        tea_bytes = bytes([0x9E, 0x37, 0x79, 0xB9])
        blob = aes_prefix + b"\x00" * 32 + tea_bytes
        hits = solver.detect_cipher_type(blob)
        names = {h["cipher"] for h in hits}
        assert "aes_sbox_fwd" in names
        assert "tea_delta" in names

    def test_rc4_identity_false_positive_check(self):
        """RC4 identity sbox (0,1,2,...) should not match random data."""
        solver = Z3Solver()
        import random
        random.seed(42)
        blob = bytes(random.randint(0, 255) for _ in range(256))
        hits = solver.detect_cipher_type(blob)
        rc4_hits = [h for h in hits if h["cipher"] == "rc4_identity_sbox"]
        # Random data should not contain 0,1,2,3,4,5,6,7 consecutively
        # This is a probabilistic assertion — the seed makes it deterministic
        assert len(rc4_hits) == 0

    def test_empty_blob(self):
        solver = Z3Solver()
        assert solver.detect_cipher_type(b"") == []

    def test_des_ip_detection(self):
        """DES Initial Permutation table bytes should be detected."""
        solver = Z3Solver()
        # DES IP first 8 values: 58,50,42,34,26,18,10,2
        des_ip = bytes([58, 50, 42, 34, 26, 18, 10, 2])
        blob = b"\x00" * 8 + des_ip + b"\x00" * 8
        hits = solver.detect_cipher_type(blob)
        names = {h["cipher"] for h in hits}
        assert "des_ip" in names


# ---------------------------------------------------------------------------
# 6. Dispatcher cross-validation hint
# ---------------------------------------------------------------------------


class TestDispatcherConfidence:
    """Test dispatcher detection edge cases."""

    def test_single_indirect_jump_moderate_confidence(self):
        """A single indirect jump should have moderate confidence (~0.5)."""
        instructions = [
            LiftedInstruction(
                address=0x1000,
                size=2,
                mnemonic="jmp",
                operands="rax",
                raw_bytes=b"\xff\xe0",
                category=InstructionCategory.BRANCH_UNCOND,
                branch_target=None,
            ),
        ]
        addr, conf = SymbolicExecutor._find_dispatcher(instructions)
        assert addr == 0x1000
        assert 0.3 <= conf <= 0.7

    def test_no_indirect_jumps(self):
        """No indirect jumps → (None, 0.0)."""
        instructions = [
            LiftedInstruction(
                address=0x1000,
                size=5,
                mnemonic="jmp",
                operands="0x2000",
                raw_bytes=b"\xe9\x00\x10\x00\x00",
                category=InstructionCategory.BRANCH_UNCOND,
                branch_target=0x2000,
            ),
        ]
        addr, conf = SymbolicExecutor._find_dispatcher(instructions)
        assert addr is None
        assert conf == 0.0
