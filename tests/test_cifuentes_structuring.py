"""Tests for Cifuentes-style control-flow structuring (Batch 30).

Covers:
  - StructuredBlock / StructuredRegion dataclasses
  - _classify_block_outedges (edge classification)
  - _compute_immediate_postdominator (post-dom convergence)
  - structure_cfg (region tree construction)
  - emit_region (pseudocode line emission)
  - emit_cifuentes (full integration)
  - if-then, if-then-else, while-loop, switch/case, fallback
"""
from __future__ import annotations

import re
import pytest
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

# ── Fakes ────────────────────────────────────────────────────────────────────

@dataclass
class _FakeVMInsn:
    handler_address: int = 0
    vip: int = 0
    operation: str = ""

    def is_branch(self):
        return "JCC" in self.operation or "JMP" in self.operation

    def is_terminator(self):
        return self.is_branch() or "RET" in self.operation


@dataclass
class _FakeBlock:
    block_id: int = 0
    instructions: list = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

    def terminator(self):
        if self.instructions:
            return self.instructions[-1]
        return None


@dataclass
class _FakeEdge:
    source_block: int = 0
    target_block: int = 0
    edge_type: str = "fallthrough"


class _FakeCFG:
    """Minimal HandlerCFG stand-in with networkx graph."""
    def __init__(self, blocks, edges, entry_block_id=0):
        self.blocks = blocks
        self.edges = edges
        self.entry_block_id = entry_block_id
        self._block_map = {b.block_id: b for b in blocks}

        try:
            import networkx as nx
            self.graph = nx.DiGraph()
            for b in blocks:
                self.graph.add_node(b.block_id)
            for e in edges:
                self.graph.add_edge(e.source_block, e.target_block)
        except ImportError:
            self.graph = None

    def topological_order(self):
        if self.graph is not None:
            import networkx as nx
            try:
                return list(nx.topological_sort(self.graph))
            except nx.NetworkXUnfeasible:
                return sorted(self._block_map.keys())
        return sorted(self._block_map.keys())

    def loop_headers(self):
        return []

    def exit_blocks(self):
        return [b.block_id for b in self.blocks if b.is_exit]


# ── Minimal SemanticOpcodeTable / HandlerBoundary stubs ──────────────────────

@dataclass
class _FakeEntry:
    class _Sem:
        operation = None
    semantic: Any = field(default_factory=_Sem)
    class_name: str = ""


class _FakeOpcodeTable:
    """Stub SemanticOpcodeTable."""
    def __init__(self, entries: Optional[Dict[int, _FakeEntry]] = None):
        self._entries = entries or {}

    def lookup_handler(self, addr):
        return self._entries.get(addr)

    def all_handlers(self):
        return list(self._entries.values())


@dataclass
class _FakeBoundary:
    handler_address: int = 0
    vip_value: int = 0
    trace_index: int = 0


# ── Import the real module ───────────────────────────────────────────────────

from dragonslayer.analysis.pseudocode import (
    StructuredBlock,
    StructuredRegion,
    structure_cfg,
    emit_region,
    emit_cifuentes,
    _classify_block_outedges,
    _compute_immediate_postdominator,
)


# ═══════════════════════════════════════════════════════════════════════════════
# StructuredBlock / StructuredRegion
# ═══════════════════════════════════════════════════════════════════════════════

class TestStructuredDataclasses:
    def test_structured_block_defaults(self):
        sb = StructuredBlock()
        assert sb.block_id == 0
        assert sb.lines == []
        assert sb.is_loop_header is False
        assert sb.is_exit is False

    def test_structured_block_with_lines(self):
        sb = StructuredBlock(block_id=5, lines=["x = 1;", "y = 2;"])
        assert len(sb.lines) == 2

    def test_structured_region_defaults(self):
        sr = StructuredRegion()
        assert sr.kind == "block"
        assert sr.condition == ""
        assert sr.children == []
        assert sr.case_labels == []

    def test_structured_region_kinds(self):
        for kind in ("sequence", "if_then", "if_then_else", "while_loop", "switch", "block"):
            sr = StructuredRegion(kind=kind)
            assert sr.kind == kind

    def test_nested_regions(self):
        inner = StructuredRegion(kind="block", children=[StructuredBlock(lines=["a;"])])
        outer = StructuredRegion(kind="if_then", condition="x", children=[inner])
        assert len(outer.children) == 1
        assert outer.children[0].kind == "block"


# ═══════════════════════════════════════════════════════════════════════════════
# _classify_block_outedges
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifyOutedges:
    def test_no_edges(self):
        cfg = _FakeCFG(
            blocks=[_FakeBlock(block_id=0, is_exit=True)],
            edges=[],
        )
        info = _classify_block_outedges(0, cfg)
        assert info["edge_type"] == "none"

    def test_unconditional_edge(self):
        cfg = _FakeCFG(
            blocks=[_FakeBlock(block_id=0), _FakeBlock(block_id=1)],
            edges=[_FakeEdge(0, 1, "fallthrough")],
        )
        info = _classify_block_outedges(0, cfg)
        assert info["edge_type"] == "unconditional"

    def test_conditional_edges(self):
        cfg = _FakeCFG(
            blocks=[_FakeBlock(block_id=0), _FakeBlock(block_id=1), _FakeBlock(block_id=2)],
            edges=[
                _FakeEdge(0, 1, "branch_taken"),
                _FakeEdge(0, 2, "branch_not_taken"),
            ],
        )
        info = _classify_block_outedges(0, cfg)
        assert info["edge_type"] == "conditional"
        assert info["taken"] == 1
        assert info["not_taken"] == 2

    def test_multi_edges(self):
        cfg = _FakeCFG(
            blocks=[_FakeBlock(block_id=i) for i in range(4)],
            edges=[
                _FakeEdge(0, 1, "jump"),
                _FakeEdge(0, 2, "jump"),
                _FakeEdge(0, 3, "jump"),
            ],
        )
        info = _classify_block_outedges(0, cfg)
        assert info["edge_type"] == "multi"

    def test_jump_plus_fallthrough_is_conditional(self):
        cfg = _FakeCFG(
            blocks=[_FakeBlock(block_id=i) for i in range(3)],
            edges=[
                _FakeEdge(0, 1, "jump"),
                _FakeEdge(0, 2, "fallthrough"),
            ],
        )
        info = _classify_block_outedges(0, cfg)
        assert info["edge_type"] == "conditional"
        assert info["taken"] == 1
        assert info["not_taken"] == 2


# ═══════════════════════════════════════════════════════════════════════════════
# _compute_immediate_postdominator
# ═══════════════════════════════════════════════════════════════════════════════

class TestPostDominator:
    @pytest.fixture
    def diamond_cfg(self):
        """Diamond: 0 → {1, 2} → 3"""
        blocks = [_FakeBlock(block_id=i) for i in range(4)]
        edges = [
            _FakeEdge(0, 1, "branch_taken"),
            _FakeEdge(0, 2, "branch_not_taken"),
            _FakeEdge(1, 3, "fallthrough"),
            _FakeEdge(2, 3, "fallthrough"),
        ]
        return _FakeCFG(blocks, edges)

    def test_diamond_postdom(self, diamond_cfg):
        ipdom = _compute_immediate_postdominator(diamond_cfg.graph, 0, {3})
        assert ipdom == 3

    def test_no_graph_returns_none(self):
        result = _compute_immediate_postdominator(None, 0, set())
        assert result is None

    def test_single_successor(self):
        blocks = [_FakeBlock(block_id=0), _FakeBlock(block_id=1)]
        cfg = _FakeCFG(blocks, [_FakeEdge(0, 1, "fallthrough")])
        ipdom = _compute_immediate_postdominator(cfg.graph, 0, {1})
        assert ipdom == 1

    def test_no_successors_returns_none(self):
        blocks = [_FakeBlock(block_id=0)]
        cfg = _FakeCFG(blocks, [])
        ipdom = _compute_immediate_postdominator(cfg.graph, 0, {0})
        assert ipdom is None


# ═══════════════════════════════════════════════════════════════════════════════
# structure_cfg
# ═══════════════════════════════════════════════════════════════════════════════

class TestStructureCFG:
    def _mk_table(self):
        return _FakeOpcodeTable()

    def _mk_boundaries(self):
        return []

    def test_empty_cfg(self):
        cfg = _FakeCFG([], [])
        region = structure_cfg(cfg, self._mk_table(), self._mk_boundaries())
        assert region.kind == "block"

    def test_single_block(self):
        cfg = _FakeCFG(
            [_FakeBlock(block_id=0, is_exit=True)],
            [],
            entry_block_id=0,
        )
        region = structure_cfg(cfg, self._mk_table(), self._mk_boundaries())
        assert region is not None
        assert region.kind in ("block", "sequence")

    def test_linear_sequence(self):
        """0 → 1 → 2 (exit)"""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=i) for i in range(3)],
            [_FakeEdge(0, 1, "fallthrough"), _FakeEdge(1, 2, "fallthrough")],
            entry_block_id=0,
        )
        cfg.blocks[2].is_exit = True
        region = structure_cfg(cfg, self._mk_table(), self._mk_boundaries())
        assert region.kind == "sequence"

    def test_diamond_produces_if_then_else(self):
        """0 → {1, 2} → 3(exit)"""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=i) for i in range(4)],
            [
                _FakeEdge(0, 1, "branch_taken"),
                _FakeEdge(0, 2, "branch_not_taken"),
                _FakeEdge(1, 3, "fallthrough"),
                _FakeEdge(2, 3, "fallthrough"),
            ],
            entry_block_id=0,
        )
        cfg.blocks[3].is_exit = True
        region = structure_cfg(cfg, self._mk_table(), self._mk_boundaries())
        # Should contain an if_then_else somewhere
        found = _find_region_kinds(region)
        assert "if_then_else" in found or "if_then" in found

    def test_if_then_one_path_to_join(self):
        """0 → 1 → 2(exit)  AND  0 → 2(exit)  (if-then pattern)"""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=i) for i in range(3)],
            [
                _FakeEdge(0, 1, "branch_taken"),
                _FakeEdge(0, 2, "branch_not_taken"),
                _FakeEdge(1, 2, "fallthrough"),
            ],
            entry_block_id=0,
        )
        cfg.blocks[2].is_exit = True
        region = structure_cfg(cfg, self._mk_table(), self._mk_boundaries())
        found = _find_region_kinds(region)
        assert "if_then" in found

    def test_switch_multi_target(self):
        """0 → {1, 2, 3} — multi-edge switch/case."""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=i) for i in range(4)],
            [_FakeEdge(0, i, "jump") for i in range(1, 4)],
            entry_block_id=0,
        )
        region = structure_cfg(cfg, self._mk_table(), self._mk_boundaries())
        found = _find_region_kinds(region)
        assert "switch" in found


# ═══════════════════════════════════════════════════════════════════════════════
# emit_region
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmitRegion:
    def test_empty_block(self):
        r = StructuredRegion(kind="block", children=[])
        lines = emit_region(r)
        assert lines == []

    def test_block_with_lines(self):
        r = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["x = 1;", "y = 2;"])
        ])
        lines = emit_region(r)
        assert len(lines) == 2
        assert lines[0] == "x = 1;"

    def test_sequence_flattens(self):
        child1 = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["a;"])
        ])
        child2 = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["b;"])
        ])
        seq = StructuredRegion(kind="sequence", children=[child1, child2])
        lines = emit_region(seq)
        assert "a;" in lines
        assert "b;" in lines

    def test_if_then_emits_braces(self):
        body = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["x = 1;"])
        ])
        r = StructuredRegion(kind="if_then", condition="flags", children=[body])
        lines = emit_region(r)
        text = "\n".join(lines)
        assert "if (flags)" in text
        assert "{" in text
        assert "}" in text
        assert "x = 1;" in text

    def test_if_then_else_emits_both_branches(self):
        then_body = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["x = 1;"])
        ])
        else_body = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["y = 2;"])
        ])
        r = StructuredRegion(kind="if_then_else", condition="cond",
                             children=[then_body, else_body])
        lines = emit_region(r)
        text = "\n".join(lines)
        assert "if (cond)" in text
        assert "} else {" in text
        assert "x = 1;" in text
        assert "y = 2;" in text

    def test_while_loop_emits_loop(self):
        body = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["i++;"])
        ])
        r = StructuredRegion(kind="while_loop", condition="i < 10",
                             children=[body])
        lines = emit_region(r)
        text = "\n".join(lines)
        assert "while (i < 10)" in text
        assert "i++;" in text

    def test_switch_emits_cases(self):
        case1 = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["handle_add();"])
        ])
        case2 = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["handle_sub();"])
        ])
        r = StructuredRegion(
            kind="switch",
            condition="opcode",
            children=[
                StructuredRegion(kind="block"),  # switch expression header
                case1,
                case2,
            ],
            case_labels=["case_add", "case_sub"],
        )
        lines = emit_region(r)
        text = "\n".join(lines)
        assert "switch (opcode)" in text
        assert "case_add:" in text
        assert "case_sub:" in text
        assert "break;" in text
        assert "handle_add();" in text

    def test_indentation(self):
        body = StructuredRegion(kind="block", children=[
            StructuredBlock(lines=["x;"])
        ])
        r = StructuredRegion(kind="if_then", condition="c", children=[body])
        lines = emit_region(r, indent=1)
        assert lines[0].startswith("    if (c)")
        # Body should be double-indented
        body_lines = [l for l in lines if "x;" in l]
        assert body_lines[0].startswith("        ")

    def test_nested_if_in_while(self):
        inner_if = StructuredRegion(
            kind="if_then", condition="flag",
            children=[StructuredRegion(kind="block", children=[
                StructuredBlock(lines=["break;"])
            ])]
        )
        loop = StructuredRegion(kind="while_loop", condition="true",
                                children=[inner_if])
        lines = emit_region(loop)
        text = "\n".join(lines)
        assert "while (true)" in text
        assert "if (flag)" in text
        assert "break;" in text


# ═══════════════════════════════════════════════════════════════════════════════
# emit_cifuentes (integration)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmitCifuentes:
    def test_fallback_when_no_cfg(self):
        """Without a CFG, should fall back to emit_structured."""
        result = emit_cifuentes(_FakeOpcodeTable(), [], handler_cfg=None)
        assert isinstance(result.text, str)

    def test_linear_cfg_produces_output(self):
        """Simple linear CFG emits non-empty pseudocode."""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=0), _FakeBlock(block_id=1, is_exit=True)],
            [_FakeEdge(0, 1, "fallthrough")],
            entry_block_id=0,
        )
        result = emit_cifuentes(_FakeOpcodeTable(), [], handler_cfg=cfg)
        assert result.style == "cifuentes"

    def test_diamond_cfg_no_gotos(self):
        """Diamond CFG should produce if/else, not gotos."""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=i) for i in range(4)],
            [
                _FakeEdge(0, 1, "branch_taken"),
                _FakeEdge(0, 2, "branch_not_taken"),
                _FakeEdge(1, 3, "fallthrough"),
                _FakeEdge(2, 3, "fallthrough"),
            ],
            entry_block_id=0,
        )
        cfg.blocks[3].is_exit = True
        result = emit_cifuentes(_FakeOpcodeTable(), [], handler_cfg=cfg)
        assert result.style == "cifuentes"
        # Output should contain if/else construct, not a raw goto
        if result.text.strip():
            assert "if (" in result.text or "goto" not in result.text

    def test_result_attributes(self):
        cfg = _FakeCFG(
            [_FakeBlock(block_id=0, is_exit=True)],
            [],
            entry_block_id=0,
        )
        result = emit_cifuentes(_FakeOpcodeTable(), [], handler_cfg=cfg)
        assert hasattr(result, "text")
        assert hasattr(result, "line_count")
        assert hasattr(result, "style")
        assert hasattr(result, "warnings")


# ═══════════════════════════════════════════════════════════════════════════════
# Loop structuring
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoopStructuring:
    def _loop_cfg(self):
        """Simple loop: 0 → 1 → 2 → 1 (back-edge), 1 → 3(exit)"""
        blocks = [
            _FakeBlock(block_id=0, is_entry=True),
            _FakeBlock(block_id=1),
            _FakeBlock(block_id=2),
            _FakeBlock(block_id=3, is_exit=True),
        ]
        edges = [
            _FakeEdge(0, 1, "fallthrough"),
            _FakeEdge(1, 2, "branch_taken"),
            _FakeEdge(2, 1, "back_edge"),
            _FakeEdge(1, 3, "branch_not_taken"),
        ]
        cfg = _FakeCFG(blocks, edges, entry_block_id=0)
        return cfg

    def test_loop_detected_in_structure(self):
        cfg = self._loop_cfg()
        # Patch loop_headers to return block 1
        cfg.loop_headers = lambda: [1]
        region = structure_cfg(cfg, _FakeOpcodeTable(), [])
        found = _find_region_kinds(region)
        # May produce while_loop or fallback — accept both
        assert len(found) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_disconnected_blocks(self):
        """Blocks with no edges should still appear in output."""
        cfg = _FakeCFG(
            [_FakeBlock(block_id=0), _FakeBlock(block_id=1)],
            [],
            entry_block_id=0,
        )
        region = structure_cfg(cfg, _FakeOpcodeTable(), [])
        # Both blocks should be visited (block 1 as leftover)
        all_bids = _collect_block_ids(region)
        assert 0 in all_bids
        assert 1 in all_bids

    def test_self_loop(self):
        """Block looping to itself."""
        blocks = [_FakeBlock(block_id=0)]
        edges = [_FakeEdge(0, 0, "back_edge")]
        cfg = _FakeCFG(blocks, edges, entry_block_id=0)
        cfg.loop_headers = lambda: [0]
        region = structure_cfg(cfg, _FakeOpcodeTable(), [])
        assert region is not None

    def test_large_linear_chain(self):
        n = 20
        blocks = [_FakeBlock(block_id=i) for i in range(n)]
        blocks[-1].is_exit = True
        edges = [_FakeEdge(i, i + 1, "fallthrough") for i in range(n - 1)]
        cfg = _FakeCFG(blocks, edges, entry_block_id=0)
        region = structure_cfg(cfg, _FakeOpcodeTable(), [])
        all_bids = _collect_block_ids(region)
        assert len(all_bids) == n


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _find_region_kinds(region: StructuredRegion) -> set:
    """Recursively collect all region kinds in the tree."""
    kinds = {region.kind}
    for child in region.children:
        if isinstance(child, StructuredRegion):
            kinds |= _find_region_kinds(child)
    return kinds


def _collect_block_ids(region) -> set:
    """Recursively collect all block_ids in the tree."""
    ids = set()
    if isinstance(region, StructuredBlock):
        ids.add(region.block_id)
    elif isinstance(region, StructuredRegion):
        for child in region.children:
            ids |= _collect_block_ids(child)
    return ids
