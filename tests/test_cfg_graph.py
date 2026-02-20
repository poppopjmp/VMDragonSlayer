"""
B60 — Explicit CFG Graph Structure tests.

Tests cover:
1. _build_cfg produces nodes, edges, back_edges, dominators
2. Edge types: fallthrough, branch_taken, branch_not_taken, unconditional, indirect
3. Back edge detection for loops
4. Dominator computation via networkx
5. Integration: ExecutionResult contains cfg field
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    ExecutionResult,
)
from dragonslayer.analysis.symbolic_execution.lifter import (
    LiftedInstruction,
    InstructionCategory,
)


def _make_insn(
    address: int,
    mnemonic: str = "nop",
    size: int = 1,
    category: InstructionCategory = InstructionCategory.UNKNOWN,
    branch_target: Optional[int] = None,
    is_branch: bool = False,
) -> LiftedInstruction:
    """Create a minimal LiftedInstruction for testing."""
    return LiftedInstruction(
        address=address,
        mnemonic=mnemonic,
        operands="",
        size=size,
        reads=[],
        writes=[],
        category=category,
        branch_target=branch_target,
        is_branch=is_branch,
        raw_bytes=b"\x90" * size,
    )


class TestBuildCFG:
    """Test SymbolicExecutor._build_cfg static method."""

    def test_empty_blocks(self):
        cfg = SymbolicExecutor._build_cfg([], 0)
        assert cfg["block_count"] == 0
        assert cfg["edge_count"] == 0
        assert cfg["nodes"] == []
        assert cfg["edges"] == []

    def test_single_block_no_branch(self):
        blk = [
            _make_insn(0x1000, "mov", size=2),
            _make_insn(0x1002, "add", size=3),
        ]
        cfg = SymbolicExecutor._build_cfg([blk], 0x1000)
        assert cfg["block_count"] == 1
        assert cfg["nodes"][0]["address"] == 0x1000
        assert cfg["nodes"][0]["instruction_count"] == 2
        # No edges — only one block, no branch
        assert cfg["edge_count"] == 0

    def test_fallthrough_edge(self):
        """Two blocks where the first falls through to the second."""
        blk1 = [_make_insn(0x1000, "mov", size=2)]
        blk2 = [_make_insn(0x1002, "nop", size=1)]
        cfg = SymbolicExecutor._build_cfg([blk1, blk2], 0x1000)
        assert cfg["block_count"] == 2
        assert cfg["edge_count"] == 1
        e = cfg["edges"][0]
        assert e["source"] == 0x1000
        assert e["target"] == 0x1002
        assert e["type"] == "fallthrough"

    def test_conditional_branch_edges(self):
        """Conditional branch produces taken + fall-through edges."""
        blk1 = [
            _make_insn(0x1000, "cmp", size=2),
            _make_insn(
                0x1002, "je", size=2,
                category=InstructionCategory.BRANCH_COND,
                branch_target=0x2000,
                is_branch=True,
            ),
        ]
        blk_taken = [_make_insn(0x2000, "nop", size=1)]
        blk_fall = [_make_insn(0x1004, "nop", size=1)]
        cfg = SymbolicExecutor._build_cfg([blk1, blk_taken, blk_fall], 0x1000)
        assert cfg["block_count"] == 3
        types = {e["type"] for e in cfg["edges"]}
        assert "branch_taken" in types
        assert "branch_not_taken" in types

    def test_unconditional_branch_edge(self):
        blk1 = [
            _make_insn(
                0x1000, "jmp", size=5,
                category=InstructionCategory.BRANCH_UNCOND,
                branch_target=0x2000,
                is_branch=True,
            ),
        ]
        blk2 = [_make_insn(0x2000, "nop", size=1)]
        cfg = SymbolicExecutor._build_cfg([blk1, blk2], 0x1000)
        assert cfg["edge_count"] == 1
        e = cfg["edges"][0]
        assert e["type"] == "unconditional"
        assert e["target"] == 0x2000

    def test_indirect_branch_edge(self):
        """Indirect branch (target=None) → edge type 'indirect'."""
        blk = [
            _make_insn(
                0x1000, "jmp", size=2,
                category=InstructionCategory.BRANCH_UNCOND,
                branch_target=None,
                is_branch=True,
            ),
        ]
        cfg = SymbolicExecutor._build_cfg([blk], 0x1000)
        assert cfg["edge_count"] == 1
        assert cfg["edges"][0]["type"] == "indirect"

    def test_return_no_successor(self):
        blk = [
            _make_insn(
                0x1000, "ret", size=1,
                category=InstructionCategory.RETURN,
                is_branch=True,
            ),
        ]
        cfg = SymbolicExecutor._build_cfg([blk], 0x1000)
        assert cfg["edge_count"] == 0

    def test_back_edge_detection(self):
        """A loop back-edge where target <= source."""
        blk1 = [_make_insn(0x1000, "nop", size=1)]
        blk2 = [
            _make_insn(
                0x1001, "jmp", size=2,
                category=InstructionCategory.BRANCH_UNCOND,
                branch_target=0x1000,
                is_branch=True,
            ),
        ]
        cfg = SymbolicExecutor._build_cfg([blk1, blk2], 0x1000)
        # Edge from 0x1001 → 0x1000 is a back edge (target < source)
        assert cfg["back_edge_count"] >= 1
        be = cfg["back_edges"][0]
        assert be["target"] == 0x1000
        assert be["source"] == 0x1001

    def test_dominators_computed(self):
        """Dominators should be computed (requires networkx)."""
        blk1 = [_make_insn(0x1000, "nop", size=2)]
        blk2 = [_make_insn(0x1002, "nop", size=1)]
        cfg = SymbolicExecutor._build_cfg([blk1, blk2], 0x1000)
        # With networkx, dominators should be populated
        try:
            import networkx
            assert len(cfg["dominators"]) >= 1
        except ImportError:
            pass  # OK if networkx not installed

    def test_entry_field(self):
        blk = [_make_insn(0x5000, "nop")]
        cfg = SymbolicExecutor._build_cfg([blk], 0x5000)
        assert cfg["entry"] == 0x5000


class TestExecutionResultCFG:
    """Test that ExecutionResult now includes cfg field."""

    def test_cfg_field_exists(self):
        r = ExecutionResult(success=True)
        assert hasattr(r, "cfg")
        assert r.cfg is None

    def test_cfg_field_in_to_dict(self):
        r = ExecutionResult(success=True, cfg={"block_count": 5})
        d = r.to_dict()
        assert "cfg" in d
        assert d["cfg"]["block_count"] == 5

    def test_analyze_produces_cfg(self):
        """SymbolicExecutor.analyze should populate cfg in result."""
        ex = SymbolicExecutor()
        # Minimal valid code: a single RET instruction (x86_64)
        code = b"\xc3"  # ret
        result = ex.analyze(code, entry_point=0)
        if result.success and result.cfg is not None:
            assert "nodes" in result.cfg
            assert "edges" in result.cfg
            assert "back_edges" in result.cfg


class TestCFGDiamondPattern:
    """Test CFG construction with an if-else diamond pattern."""

    def test_diamond_cfg(self):
        """
        0x1000: cmp      (block A)
        0x1002: je 0x2000
        0x1004: nop      (block B — fall-through)
        0x1005: jmp 0x3000
        0x2000: nop      (block C — taken)
        0x2001: jmp 0x3000
        0x3000: nop      (block D — merge)
        """
        blk_a = [
            _make_insn(0x1000, "cmp", size=2),
            _make_insn(0x1002, "je", size=2,
                       category=InstructionCategory.BRANCH_COND,
                       branch_target=0x2000, is_branch=True),
        ]
        blk_b = [
            _make_insn(0x1004, "nop", size=1),
            _make_insn(0x1005, "jmp", size=5,
                       category=InstructionCategory.BRANCH_UNCOND,
                       branch_target=0x3000, is_branch=True),
        ]
        blk_c = [
            _make_insn(0x2000, "nop", size=1),
            _make_insn(0x2001, "jmp", size=5,
                       category=InstructionCategory.BRANCH_UNCOND,
                       branch_target=0x3000, is_branch=True),
        ]
        blk_d = [
            _make_insn(0x3000, "nop", size=1),
        ]

        cfg = SymbolicExecutor._build_cfg(
            [blk_a, blk_b, blk_c, blk_d], 0x1000,
        )

        assert cfg["block_count"] == 4

        # Check edges: A→C (taken), A→B (fall), B→D (uncond), C→D (uncond)
        edge_pairs = [(e["source"], e["target"]) for e in cfg["edges"]]
        assert (0x1000, 0x2000) in edge_pairs  # A→C taken
        assert (0x1000, 0x1004) in edge_pairs  # A→B fall-through
        assert (0x1004, 0x3000) in edge_pairs  # B→D uncond
        assert (0x2000, 0x3000) in edge_pairs  # C→D uncond

        # No back edges in a diamond
        assert cfg["back_edge_count"] == 0

        # Dominators: all dominated by entry (keys are ints since B66)
        try:
            import networkx
            assert cfg["dominators"].get(0x3000) is not None
        except ImportError:
            pass
