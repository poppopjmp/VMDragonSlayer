"""B83 — LoopTree nesting, lane-aware SIMD, YARA version-map expansion.

Tests cover:
  1. NaturalLoop & LoopTree construction, nesting, queries
  2. Lane-aware SIMD arithmetic (z3 and concrete paths)
  3. Expanded _YARA_VERSION_MAP (≥16 entries) & dual-engine boost
"""

from __future__ import annotations

import importlib
import math
import re
import types
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# CFG imports
# ---------------------------------------------------------------------------
from dragonslayer.analysis.bytecode_cfg import (
    NaturalLoop,
    LoopTree,
    build_loop_tree,
    detect_natural_loops,
    HandlerBasicBlock,
    CFGEdge,
    HandlerCFG,
    VMInstruction,
)

# ---------------------------------------------------------------------------
# Pattern / recognizer imports
# ---------------------------------------------------------------------------
from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
from dragonslayer.analysis.pattern_analysis.database import PatternDatabase

# ---------------------------------------------------------------------------
# Symbolic execution imports
# ---------------------------------------------------------------------------
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    LiftedInstruction,
)
from dragonslayer.analysis.symbolic_execution.state import SymbolicState

try:
    import z3 as _z3
    _HAS_Z3 = True
except ImportError:
    _z3 = None  # type: ignore[assignment]
    _HAS_Z3 = False

# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _make_block(bid: int, *, entry: bool = False, exit_: bool = False,
                vip: int = 0) -> HandlerBasicBlock:
    """Convenience factory for a minimal HandlerBasicBlock."""
    return HandlerBasicBlock(
        block_id=bid,
        start_vip=vip or bid * 0x100,
        instructions=[],
        is_entry=entry,
        is_exit=exit_,
    )


def _make_state(arch: str = "x86_64") -> SymbolicState:
    return SymbolicState(arch=arch, bit_width=64, initial_pc=0)


def _insn(mnemonic: str, ops: str = "") -> LiftedInstruction:
    operands = [o.strip() for o in ops.split(",")] if ops else []
    return LiftedInstruction(
        address=0,
        mnemonic=mnemonic,
        operands=operands,
        category="",
        raw_bytes=b"",
        size=0,
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. NaturalLoop / LoopTree
# ═══════════════════════════════════════════════════════════════════════════


class TestNaturalLoop:
    """Unit tests for the NaturalLoop dataclass."""

    def test_basic_properties(self):
        lp = NaturalLoop(header=0, back_edge_sources=[3], body={0, 1, 2, 3})
        assert lp.header == 0
        assert 1 in lp
        assert 99 not in lp
        assert lp.nesting_depth == 0
        assert lp.is_innermost is True

    def test_nesting_depth(self):
        outer = NaturalLoop(header=0, body={0, 1, 2, 3, 4})
        inner = NaturalLoop(header=1, body={1, 2}, parent=outer)
        outer.children.append(inner)
        assert inner.nesting_depth == 1
        assert outer.nesting_depth == 0
        assert outer.is_innermost is False

    def test_to_dict(self):
        lp = NaturalLoop(header=5, back_edge_sources=[8], body={5, 6, 7, 8})
        d = lp.to_dict()
        assert d["header"] == 5
        assert d["body"] == [5, 6, 7, 8]
        assert d["nesting_depth"] == 0


class TestLoopTree:
    """Tests for LoopTree construction and queries."""

    def _single_loop_data(self) -> List[Dict[str, Any]]:
        return [{"header": 0, "back_edge_source": 3, "body": {0, 1, 2, 3}}]

    def _nested_loop_data(self) -> List[Dict[str, Any]]:
        return [
            {"header": 0, "back_edge_source": 5, "body": {0, 1, 2, 3, 4, 5}},
            {"header": 2, "back_edge_source": 3, "body": {2, 3}},
        ]

    def test_single_loop(self):
        tree = LoopTree(self._single_loop_data())
        assert tree.loop_count == 1
        assert tree.max_depth == 0
        assert len(tree.roots) == 1
        assert tree.roots[0].header == 0

    def test_nested_loops(self):
        tree = LoopTree(self._nested_loop_data())
        assert tree.loop_count == 2
        assert tree.max_depth == 1
        outer = tree.get_loop(0)
        inner = tree.get_loop(2)
        assert outer is not None
        assert inner is not None
        assert inner.parent is outer
        assert inner in outer.children

    def test_innermost_loops(self):
        tree = LoopTree(self._nested_loop_data())
        inner_list = tree.innermost_loops()
        assert len(inner_list) == 1
        assert inner_list[0].header == 2

    def test_loop_for_block(self):
        tree = LoopTree(self._nested_loop_data())
        # Block 2 is in BOTH loops; should return the innermost
        lp = tree.loop_for_block(2)
        assert lp is not None
        assert lp.header == 2
        # Block 1 is only in the outer loop
        lp2 = tree.loop_for_block(1)
        assert lp2 is not None
        assert lp2.header == 0
        # Block 99 not in any loop
        assert tree.loop_for_block(99) is None

    def test_is_reducible(self):
        tree = LoopTree(self._single_loop_data())
        assert tree.is_reducible() is True

    def test_empty_tree(self):
        tree = LoopTree()
        assert tree.loop_count == 0
        assert tree.max_depth == 0
        assert len(tree) == 0
        assert bool(tree) is False

    def test_bool_truthy(self):
        tree = LoopTree(self._single_loop_data())
        assert bool(tree) is True

    def test_to_dict(self):
        tree = LoopTree(self._nested_loop_data())
        d = tree.to_dict()
        assert d["loop_count"] == 2
        assert d["max_depth"] == 1
        assert d["reducible"] is True

    def test_merged_back_edges(self):
        """Two back-edges to the same header are merged."""
        data = [
            {"header": 0, "back_edge_source": 3, "body": {0, 1, 2, 3}},
            {"header": 0, "back_edge_source": 4, "body": {0, 1, 2, 3, 4}},
        ]
        tree = LoopTree(data)
        assert tree.loop_count == 1
        lp = tree.get_loop(0)
        assert lp is not None
        assert set(lp.back_edge_sources) == {3, 4}
        assert 4 in lp.body  # bodies merged

    def test_three_level_nesting(self):
        data = [
            {"header": 0, "back_edge_source": 9,
             "body": {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
            {"header": 2, "back_edge_source": 6,
             "body": {2, 3, 4, 5, 6}},
            {"header": 4, "back_edge_source": 5,
             "body": {4, 5}},
        ]
        tree = LoopTree(data)
        assert tree.loop_count == 3
        assert tree.max_depth == 2
        deepest = tree.get_loop(4)
        assert deepest is not None
        assert deepest.nesting_depth == 2

    def test_sibling_loops(self):
        """Two loops with no subset relationship → both are roots."""
        data = [
            {"header": 0, "back_edge_source": 2, "body": {0, 1, 2}},
            {"header": 5, "back_edge_source": 7, "body": {5, 6, 7}},
        ]
        tree = LoopTree(data)
        assert tree.loop_count == 2
        assert tree.max_depth == 0
        assert len(tree.roots) == 2


class TestBuildLoopTree:
    """Integration: build_loop_tree from blocks + edges."""

    def test_no_back_edges(self):
        blocks = [_make_block(0, entry=True), _make_block(1, exit_=True)]
        edges = [CFGEdge(0, 1, "fallthrough")]
        tree = build_loop_tree(blocks, edges)
        assert tree.loop_count == 0

    def test_simple_loop(self):
        blocks = [_make_block(0, entry=True), _make_block(1),
                  _make_block(2, exit_=True)]
        edges = [
            CFGEdge(0, 1, "fallthrough"),
            CFGEdge(1, 2, "branch_taken"),
            CFGEdge(1, 0, "back_edge"),
        ]
        tree = build_loop_tree(blocks, edges)
        assert tree.loop_count >= 1


class TestHandlerCFGLoopTree:
    """HandlerCFG integration with loop_tree field."""

    def test_summary_includes_depth(self):
        lt = LoopTree([
            {"header": 0, "back_edge_source": 3, "body": {0, 1, 2, 3}},
            {"header": 1, "back_edge_source": 2, "body": {1, 2}},
        ])
        cfg = HandlerCFG(loop_tree=lt)
        assert "max loop depth" in cfg.summary()

    def test_to_dict_includes_loop_tree(self):
        lt = LoopTree([
            {"header": 0, "back_edge_source": 1, "body": {0, 1}},
        ])
        cfg = HandlerCFG(loop_tree=lt)
        d = cfg.to_dict()
        assert "loop_tree" in d
        assert d["loop_tree"]["loop_count"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# 2. Lane-aware SIMD arithmetic
# ═══════════════════════════════════════════════════════════════════════════


class TestPackedMul:
    """SymbolicExecutor._packed_mul concrete tests."""

    def test_16bit_lanes(self):
        # 8 lanes of 16 bits, all set to value 3
        a = 0
        b = 0
        for i in range(8):
            a |= (5 << (i * 16))
            b |= (3 << (i * 16))
        result = SymbolicExecutor._packed_mul(a, b, 16)
        for i in range(8):
            lane = (result >> (i * 16)) & 0xFFFF
            assert lane == 15, f"lane {i} expected 15, got {lane}"

    def test_overflow_truncation(self):
        """0xFFFF * 0xFFFF → low 16 bits = 1."""
        a = 0xFFFF
        b = 0xFFFF
        result = SymbolicExecutor._packed_mul(a, b, 16)
        lane0 = result & 0xFFFF
        assert lane0 == (0xFFFF * 0xFFFF) & 0xFFFF

    def test_zero_mul(self):
        result = SymbolicExecutor._packed_mul(0, 0xFFFF_FFFF, 32)
        assert result == 0


class TestPackedAddSub:
    def test_packed_add_8bit(self):
        a = 0xFF  # lane0 = 255
        b = 0x01  # lane0 = 1
        result = SymbolicExecutor._packed_add(a, b, 8)
        lane0 = result & 0xFF
        assert lane0 == 0  # 255 + 1 wraps to 0 in 8-bit

    def test_packed_sub_16bit(self):
        a = 0x000A  # 10
        b = 0x0003  # 3
        result = SymbolicExecutor._packed_sub(a, b, 16)
        assert (result & 0xFFFF) == 7


@pytest.mark.skipif(not _HAS_Z3, reason="z3 not available")
class TestZ3LaneOp:
    """SymbolicExecutor._z3_lane_op z3 tests."""

    def test_add_16bit_lanes(self):
        a = _z3.BitVecVal(0x0003_0005_0007_0009_000B_000D_000F_0011, 128)
        b = _z3.BitVecVal(0x0001_0001_0001_0001_0001_0001_0001_0001, 128)
        result = SymbolicExecutor._z3_lane_op(a, b, 16, "add")
        val = result.as_long() if hasattr(result, "as_long") else _z3.simplify(result).as_long()
        lane0 = val & 0xFFFF
        assert lane0 == 0x0012  # 0x0011 + 0x0001

    def test_sub_32bit_lanes(self):
        a = _z3.BitVecVal(0x0000000A_0000000A_0000000A_0000000A, 128)
        b = _z3.BitVecVal(0x00000003_00000003_00000003_00000003, 128)
        result = SymbolicExecutor._z3_lane_op(a, b, 32, "sub")
        val = _z3.simplify(result).as_long()
        for i in range(4):
            lane = (val >> (i * 32)) & 0xFFFFFFFF
            assert lane == 7

    def test_mul_16bit_lanes(self):
        a = _z3.BitVecVal(0x0005_0005_0005_0005_0005_0005_0005_0005, 128)
        b = _z3.BitVecVal(0x0003_0003_0003_0003_0003_0003_0003_0003, 128)
        result = SymbolicExecutor._z3_lane_op(a, b, 16, "mul")
        val = _z3.simplify(result).as_long()
        for i in range(8):
            lane = (val >> (i * 16)) & 0xFFFF
            assert lane == 15


class TestExecSimdArithConcrete:
    """Integration: _exec_simd_arith with concrete values via the executor."""

    def _make_executor(self) -> SymbolicExecutor:
        return SymbolicExecutor(arch="x86_64")

    def test_paddw_concrete(self):
        ex = self._make_executor()
        state = _make_state()
        state.set_register("xmm0", 0x0001_0002_0003_0004_0005_0006_0007_0008)
        state.set_register("xmm1", 0x0001_0001_0001_0001_0001_0001_0001_0001)
        insn = _insn("paddw", "xmm0, xmm1")
        ex._exec_simd_arith(state, ["xmm0", "xmm1"], insn, "paddw")
        val = state.get_register("xmm0")
        lane0 = val & 0xFFFF
        assert lane0 == 0x0009  # 8+1

    def test_pmullw_concrete(self):
        ex = self._make_executor()
        state = _make_state()
        state.set_register("xmm0", 5)  # lane0 = 5
        state.set_register("xmm1", 3)  # lane0 = 3
        insn = _insn("pmullw", "xmm0, xmm1")
        ex._exec_simd_arith(state, ["xmm0", "xmm1"], insn, "pmullw")
        val = state.get_register("xmm0")
        assert (val & 0xFFFF) == 15

    def test_psubd_concrete(self):
        ex = self._make_executor()
        state = _make_state()
        state.set_register("xmm0", 0x0000000A_0000000A_0000000A_0000000A)
        state.set_register("xmm1", 0x00000003_00000003_00000003_00000003)
        insn = _insn("psubd", "xmm0, xmm1")
        ex._exec_simd_arith(state, ["xmm0", "xmm1"], insn, "psubd")
        val = state.get_register("xmm0")
        for i in range(4):
            lane = (val >> (i * 32)) & 0xFFFFFFFF
            assert lane == 7


# ═══════════════════════════════════════════════════════════════════════════
# 3. YARA version-map expansion & dual-engine boost
# ═══════════════════════════════════════════════════════════════════════════


class TestYARAVersionMapExpansion:
    """Verify _YARA_VERSION_MAP has ≥16 entries and covers key protectors."""

    def test_min_16_entries(self):
        assert len(PatternRecognizer._YARA_VERSION_MAP) >= 16

    def test_vmprotect_entries(self):
        vmp = [k for k, v in PatternRecognizer._YARA_VERSION_MAP.items()
               if v[0] == "VMProtect"]
        assert len(vmp) >= 8

    def test_themida_entries(self):
        th = [k for k, v in PatternRecognizer._YARA_VERSION_MAP.items()
              if v[0] == "Themida"]
        assert len(th) >= 8

    def test_all_entries_have_valid_structure(self):
        for name, (protector, version, conf) in PatternRecognizer._YARA_VERSION_MAP.items():
            assert isinstance(protector, str) and len(protector) > 0
            assert isinstance(version, str) and len(version) > 0
            assert 0.0 < conf <= 1.0, f"{name}: confidence {conf} out of range"


class TestDualEngineBoost:
    """Test the dual-engine confidence boost path with a mock YARA engine."""

    def _make_recognizer_with_mock_yara(self, yara_matches):
        db = PatternDatabase()
        rec = PatternRecognizer(db)
        # Inject a mock YARA engine
        mock_yara = MagicMock()
        mock_yara.scan.return_value = yara_matches
        rec._yara = mock_yara
        return rec

    def test_regex_only(self):
        db = PatternDatabase()
        rec = PatternRecognizer(db)
        # VMProtect 3.0.x: pushad + B8 immediate
        result = rec.version_fingerprint("60 11 B8 AABBCCDD")
        assert result["protector"] == "VMProtect"
        assert result["version"] == "3.0.x"
        assert "regex" in result["engines"]

    def test_dual_engine_agreement_boosts(self):
        """When regex + YARA agree on protector+version, confidence += 0.10."""
        yara_match = MagicMock()
        yara_match.rule = "VMP_30_Handler_Prologue"
        rec = self._make_recognizer_with_mock_yara([yara_match])

        result = rec.version_fingerprint("60 11 B8 AABBCCDD")
        assert result["protector"] == "VMProtect"
        assert result["version"] == "3.0.x"
        assert result["confidence"] >= 0.85 + PatternRecognizer._DUAL_ENGINE_BOOST - 0.001
        assert "regex" in result["engines"]
        assert "yara" in result["engines"]

    def test_yara_only_no_regex(self):
        """YARA hit with no regex match → yara-only result."""
        yara_match = MagicMock()
        yara_match.rule = "VMP_38_Complex_Dispatch"
        rec = self._make_recognizer_with_mock_yara([yara_match])

        result = rec.version_fingerprint("00 00 00 00")
        assert result["protector"] == "VMProtect"
        assert "yara" in result["engines"]

    def test_no_match_returns_unknown(self):
        db = PatternDatabase()
        rec = PatternRecognizer(db)
        result = rec.version_fingerprint("00 00 00 00")
        assert result["protector"] == "unknown"
        assert result["confidence"] == 0.0


class TestYARARulesFileConsistency:
    """Cross-check that every _YARA_VERSION_MAP entry has a .yar rule."""

    @pytest.fixture()
    def yar_rule_names(self) -> Set[str]:
        import pathlib
        rules: Set[str] = set()
        yar_dir = pathlib.Path("data/patterns")
        for yar_file in yar_dir.glob("*.yar"):
            text = yar_file.read_text(encoding="utf-8")
            rules |= set(re.findall(r"^rule\s+(\w+)", text, re.MULTILINE))
        return rules

    def test_all_map_entries_have_rules(self, yar_rule_names):
        missing = []
        for name in PatternRecognizer._YARA_VERSION_MAP:
            if name not in yar_rule_names:
                missing.append(name)
        assert missing == [], f"YARA rules missing for map entries: {missing}"
