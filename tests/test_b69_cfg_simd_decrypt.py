"""
B69 — CFG switch-tables, exception edges, SIMD taint, key-schedule detection,
      semantic pattern normalisation
=====================================================================================

Tests covering the B69 batch:

1. ``_detect_switch_tables`` recognises cmp+ja+indirect-jmp patterns.
2. ``_detect_exception_edges`` recognises SEH push/fs:[0] patterns.
3. SIMD register families (xmm/ymm/zmm) in taint tracker.
4. ``detect_key_schedule_length`` finds shortest repeating XOR period.
5. ``PatternRecognizer.normalize_semantics`` strips NOP junk.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# 1. CFG: Switch / jump-table detection
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
from dragonslayer.analysis.symbolic_execution.lifter import (
    InstructionCategory,
    LiftedInstruction,
)


def _insn(addr, mnemonic, cat, target=None, operands=""):
    return LiftedInstruction(
        address=addr,
        size=2,
        mnemonic=mnemonic,
        operands=operands,
        raw_bytes=b"\x00\x00",
        category=cat,
        branch_target=target,
    )

# Shorthand for non-branch category
_GENERIC = InstructionCategory.UNKNOWN


class TestSwitchTableDetection:
    """``_detect_switch_tables`` detects cmp+indirect jmp patterns."""

    def test_basic_switch_pattern(self):
        blk = [
            _insn(0x100, "cmp", _GENERIC, operands="eax, 5"),
            _insn(0x102, "ja", InstructionCategory.BRANCH_COND, target=0x200, operands="0x200"),
            _insn(0x104, "jmp", InstructionCategory.BRANCH_UNCOND, target=None, operands="[rax*8+0x300]"),
        ]
        tables = SymbolicExecutor._detect_switch_tables([blk], {0x100})
        assert len(tables) == 1
        assert tables[0]["address"] == 0x104
        assert tables[0]["bound"] == 5
        assert tables[0]["targets_estimate"] == 6

    def test_no_switch_when_target_known(self):
        """Direct jump (known target) is NOT a switch table."""
        blk = [
            _insn(0x100, "cmp", _GENERIC, operands="eax, 10"),
            _insn(0x102, "jmp", InstructionCategory.BRANCH_UNCOND, target=0x300),
        ]
        tables = SymbolicExecutor._detect_switch_tables([blk], {0x100})
        assert tables == []

    def test_no_cmp_means_no_table(self):
        """Indirect jump without preceding CMP → not detected as switch."""
        blk = [
            _insn(0x100, "mov", _GENERIC, operands="rax, rbx"),
            _insn(0x102, "jmp", InstructionCategory.BRANCH_UNCOND, target=None),
        ]
        tables = SymbolicExecutor._detect_switch_tables([blk], {0x100})
        assert tables == []

    def test_hex_bound_parsing(self):
        blk = [
            _insn(0x100, "cmp", _GENERIC, operands="ecx, 0xFF"),
            _insn(0x104, "jmp", InstructionCategory.BRANCH_UNCOND, target=None),
        ]
        tables = SymbolicExecutor._detect_switch_tables([blk], {0x100})
        assert len(tables) == 1
        assert tables[0]["bound"] == 255


# ---------------------------------------------------------------------------
# 2. CFG: Exception edge detection
# ---------------------------------------------------------------------------

class TestExceptionEdgeDetection:
    """``_detect_exception_edges`` detects SEH push patterns."""

    def test_seh_push_pattern(self):
        blk = [
            _insn(0x100, "push", _GENERIC, operands="0x5000"),
            _insn(0x102, "push", _GENERIC, operands="dword ptr fs:[0]"),
        ]
        edges = SymbolicExecutor._detect_exception_edges([blk], {0x100})
        assert len(edges) == 1
        assert edges[0]["handler"] == 0x5000
        assert edges[0]["type"] == "seh"

    def test_no_seh_without_fs_access(self):
        blk = [
            _insn(0x100, "push", _GENERIC, operands="0x5000"),
            _insn(0x102, "push", _GENERIC, operands="dword ptr [esp]"),
        ]
        edges = SymbolicExecutor._detect_exception_edges([blk], {0x100})
        assert edges == []

    def test_empty_blocks(self):
        edges = SymbolicExecutor._detect_exception_edges([], set())
        assert edges == []


# ---------------------------------------------------------------------------
# 3. SIMD taint: xmm/ymm/zmm families
# ---------------------------------------------------------------------------

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    subreg_canonical,
    subreg_aliases,
    _SUBREG_FAMILIES,
)


class TestSIMDTaintFamilies:
    """SIMD registers share zmm canonical families."""

    def test_xmm_canonical_is_zmm(self):
        assert subreg_canonical("xmm0") == "zmm0"
        assert subreg_canonical("xmm15") == "zmm15"

    def test_ymm_canonical_is_zmm(self):
        assert subreg_canonical("ymm0") == "zmm0"
        assert subreg_canonical("ymm7") == "zmm7"

    def test_zmm_canonical_is_self(self):
        assert subreg_canonical("zmm0") == "zmm0"

    def test_aliases_include_all_widths(self):
        fam = subreg_aliases("xmm5")
        assert fam == {"xmm5", "ymm5", "zmm5"}

    def test_all_16_simd_families_exist(self):
        for n in range(16):
            assert f"xmm{n}" in _SUBREG_FAMILIES
            assert f"ymm{n}" in _SUBREG_FAMILIES
            assert f"zmm{n}" in _SUBREG_FAMILIES

    def test_xmm_width_128(self):
        info = _SUBREG_FAMILIES["xmm0"]
        assert info[2] == 128  # width

    def test_ymm_width_256(self):
        info = _SUBREG_FAMILIES["ymm0"]
        assert info[2] == 256

    def test_zmm_width_512(self):
        info = _SUBREG_FAMILIES["zmm0"]
        assert info[2] == 512

    def test_taint_xmm_propagates_to_ymm(self):
        """Tainting xmm0 should propagate to ymm0/zmm0 via family."""
        t = TaintTracker()
        t.taint_register("xmm0", TaintTag.INPUT)
        assert t.is_tainted("xmm0")
        # ymm0/zmm0 should also be tainted (same canonical family)
        assert t.is_tainted("ymm0")
        assert t.is_tainted("zmm0")


# ---------------------------------------------------------------------------
# 4. Adaptive key-schedule length detection
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.solver import Z3Solver


class TestKeyScheduleLengthDetection:
    """``detect_key_schedule_length`` finds the shortest repeating XOR key."""

    def test_period_1(self):
        """Single-byte repeating key."""
        key = 0x42
        pt = [0x10, 0x20, 0x30, 0x40]
        ct = [p ^ key for p in pt]

        solver = Z3Solver()
        result = solver.detect_key_schedule_length(ct, pt, max_period=8, bits=8)
        assert result.satisfiable
        assert result.model["key_length"] == 1
        assert result.model["key_0"] == key

    def test_period_3(self):
        """3-byte repeating key."""
        key = [0xAA, 0xBB, 0xCC]
        pt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        ct = [p ^ key[i % 3] for i, p in enumerate(pt)]

        solver = Z3Solver()
        result = solver.detect_key_schedule_length(ct, pt, max_period=8, bits=8)
        assert result.satisfiable
        assert result.model["key_length"] == 3
        for j in range(3):
            assert result.model[f"key_{j}"] == key[j]

    def test_no_match_returns_unsat(self):
        """If max_period is too small, no solution found."""
        key = [0x01, 0x02, 0x03, 0x04, 0x05]
        pt = list(range(10))
        ct = [p ^ key[i % 5] for i, p in enumerate(pt)]

        solver = Z3Solver()
        result = solver.detect_key_schedule_length(ct, pt, max_period=3, bits=8)
        assert not result.satisfiable

    def test_empty_input(self):
        solver = Z3Solver()
        result = solver.detect_key_schedule_length([], [], bits=8)
        assert not result.satisfiable

    def test_length_mismatch(self):
        solver = Z3Solver()
        result = solver.detect_key_schedule_length([1, 2], [3], bits=8)
        assert not result.satisfiable


# ---------------------------------------------------------------------------
# 5. Semantic pattern normalisation
# ---------------------------------------------------------------------------

from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer


class TestSemanticNormalisation:
    """``normalize_semantics`` strips NOP junk opcodes."""

    def test_strips_single_nop(self):
        assert PatternRecognizer.normalize_semantics("AA 90 BB") == "AABB"

    def test_strips_long_nop(self):
        # 0F1F00 is a 3-byte NOP
        assert PatternRecognizer.normalize_semantics("AA0F1F00BB") == "AABB"

    def test_no_change_when_no_nops(self):
        assert PatternRecognizer.normalize_semantics("AABBCCDD") == "AABBCCDD"

    def test_multiple_nops_stripped(self):
        assert PatternRecognizer.normalize_semantics("90 AA 90 BB 90") == "AABB"

    def test_case_insensitive_input(self):
        assert PatternRecognizer.normalize_semantics("aa 90 bb") == "AABB"

    def test_semantic_equiv_dict_exists(self):
        """_SEMANTIC_EQUIV maps known equivalences."""
        assert PatternRecognizer._SEMANTIC_EQUIV["sal"] == "shl"
        assert PatternRecognizer._SEMANTIC_EQUIV["test"] == "and"

    def test_nop_opcodes_set_exists(self):
        assert "90" in PatternRecognizer._NOP_OPCODES
        assert "6690" in PatternRecognizer._NOP_OPCODES
