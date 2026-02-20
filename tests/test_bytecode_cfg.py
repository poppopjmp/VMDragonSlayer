"""Batch 19 — Bytecode Walker & Handler-Level CFG Reconstruction tests.

Tests for :mod:`dragonslayer.analysis.bytecode_cfg`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

from dragonslayer.analysis.handler_semantics import (
    HandlerSemantic,
    OpcodeTableEntry,
    SemanticOpcodeTable,
    VMOperation,
)
from dragonslayer.analysis.bytecode_cfg import (
    VMInstruction,
    HandlerBasicBlock,
    CFGEdge,
    HandlerCFG,
    walk_trace_bytecode,
    build_handler_cfg,
    walk_static_bytecode,
    build_static_cfg,
    detect_natural_loops,
    _identify_leaders,
    _partition_into_blocks,
    _build_edges,
    _build_nx_graph,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeBoundary:
    """Lightweight HandlerBoundary stub."""
    vip_value: int = 0
    handler_address: int = 0x401000
    vip_delta: int = 1
    instruction_count: int = 5
    trace_start: int = 0
    trace_end: int = 5
    category: str = "unknown"


def _sem(operation: str, *, confidence: float = 0.9, width: int = 4) -> HandlerSemantic:
    return HandlerSemantic(
        handler_address=0,
        operation=operation,
        confidence=confidence,
        operand_width=width,
    )


def _entry(opcode: int, addr: int, operation: str, vip_delta: int = 1) -> OpcodeTableEntry:
    return OpcodeTableEntry(
        opcode=opcode,
        handler_address=addr,
        semantic=_sem(operation),
        vip_delta=vip_delta,
    )


def _table(entries: List[OpcodeTableEntry]) -> SemanticOpcodeTable:
    return SemanticOpcodeTable(
        entries=entries,
        handler_count=len(entries),
        unique_operations=len({e.semantic.operation for e in entries}),
    )


# ---------------------------------------------------------------------------
# VMInstruction tests
# ---------------------------------------------------------------------------

class TestVMInstruction:
    def test_branch_detection(self):
        jmp = VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.JMP)
        jcc = VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.JCC)
        add = VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.ADD)
        ret = VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.RET)

        assert jmp.is_branch()
        assert jmp.is_unconditional_jump()
        assert not jmp.is_conditional_jump()

        assert jcc.is_branch()
        assert jcc.is_conditional_jump()
        assert not jcc.is_unconditional_jump()

        assert not add.is_branch()
        assert add.is_terminator() is False

        assert ret.is_return()
        assert ret.is_terminator()

    def test_fallthrough_vip(self):
        insn = VMInstruction(vip=100, opcode=0, handler_address=0, vip_delta=3)
        assert insn.fallthrough_vip() == 103

    def test_to_dict(self):
        insn = VMInstruction(vip=0, opcode=5, handler_address=0x1000, operation=VMOperation.ADD)
        d = insn.to_dict()
        assert d["opcode"] == 5
        assert d["operation"] == VMOperation.ADD


# ---------------------------------------------------------------------------
# HandlerBasicBlock tests
# ---------------------------------------------------------------------------

class TestHandlerBasicBlock:
    def test_properties(self):
        insns = [
            VMInstruction(vip=0, opcode=0, handler_address=0x1000, operation=VMOperation.ADD),
            VMInstruction(vip=1, opcode=1, handler_address=0x2000, operation=VMOperation.SUB),
        ]
        block = HandlerBasicBlock(block_id=0, start_vip=0, instructions=insns, is_entry=True)

        assert block.instruction_count == 2
        assert block.end_vip() == 1
        assert block.terminator() == insns[-1]
        assert block.operations_list() == [VMOperation.ADD, VMOperation.SUB]

    def test_empty_block(self):
        block = HandlerBasicBlock(block_id=0, start_vip=0)
        assert block.instruction_count == 0
        assert block.terminator() is None
        assert block.end_vip() == 0

    def test_to_dict(self):
        block = HandlerBasicBlock(block_id=7, start_vip=100, is_entry=True, is_exit=False)
        d = block.to_dict()
        assert d["block_id"] == 7
        assert d["is_entry"] is True


# ---------------------------------------------------------------------------
# HandlerCFG tests
# ---------------------------------------------------------------------------

class TestHandlerCFG:
    def test_empty_cfg(self):
        cfg = HandlerCFG()
        assert cfg.block_count == 0
        assert cfg.edge_count == 0
        assert cfg.back_edges() == []
        assert cfg.loop_headers() == set()

    def test_find_block(self):
        b1 = HandlerBasicBlock(block_id=0, start_vip=0)
        b2 = HandlerBasicBlock(block_id=1, start_vip=10)
        cfg = HandlerCFG(blocks=[b1, b2])

        assert cfg.find_block(0) is b1
        assert cfg.find_block(1) is b2
        assert cfg.find_block(99) is None

    def test_find_block_by_vip(self):
        b1 = HandlerBasicBlock(block_id=0, start_vip=100)
        cfg = HandlerCFG(blocks=[b1])
        assert cfg.find_block_by_vip(100) is b1
        assert cfg.find_block_by_vip(200) is None

    def test_summary(self):
        cfg = HandlerCFG()
        s = cfg.summary()
        assert "0 blocks" in s

    def test_topological_no_nx(self):
        b1 = HandlerBasicBlock(block_id=0, start_vip=0)
        b2 = HandlerBasicBlock(block_id=1, start_vip=5)
        cfg = HandlerCFG(blocks=[b1, b2])
        assert cfg.topological_order() == [0, 1]


# ---------------------------------------------------------------------------
# walk_trace_bytecode tests
# ---------------------------------------------------------------------------

class TestWalkTraceBytecode:
    def test_simple_linear(self):
        """Linear sequence of PUSH, ADD, POP boundaries."""
        entries = [
            _entry(0x01, 0x1000, VMOperation.PUSH, vip_delta=1),
            _entry(0x02, 0x2000, VMOperation.ADD, vip_delta=1),
            _entry(0x03, 0x3000, VMOperation.POP, vip_delta=1),
        ]
        table = _table(entries)

        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=1),
            FakeBoundary(vip_value=2, handler_address=0x3000, vip_delta=1),
        ]

        insns = walk_trace_bytecode(table, boundaries)
        assert len(insns) == 3
        assert insns[0].operation == VMOperation.PUSH
        assert insns[0].opcode == 0x01
        assert insns[1].operation == VMOperation.ADD
        assert insns[2].operation == VMOperation.POP

    def test_unknown_handler(self):
        """Unknown handler should produce UNKNOWN instruction."""
        table = _table([_entry(0x01, 0x1000, VMOperation.ADD)])
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x9999, vip_delta=1),
        ]
        insns = walk_trace_bytecode(table, boundaries)
        assert len(insns) == 1
        assert insns[0].operation == VMOperation.UNKNOWN
        assert insns[0].opcode == -1

    def test_empty(self):
        table = _table([])
        insns = walk_trace_bytecode(table, [])
        assert insns == []

    def test_boundary_index_recorded(self):
        table = _table([_entry(0x01, 0x1000, VMOperation.ADD)])
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000),
            FakeBoundary(vip_value=1, handler_address=0x1000),
        ]
        insns = walk_trace_bytecode(table, boundaries)
        assert insns[0].boundary_index == 0
        assert insns[1].boundary_index == 1


# ---------------------------------------------------------------------------
# _identify_leaders tests
# ---------------------------------------------------------------------------

class TestIdentifyLeaders:
    def test_first_is_always_leader(self):
        insns = [VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.ADD)]
        leaders = _identify_leaders(insns)
        assert 0 in leaders

    def test_after_jmp_is_leader(self):
        insns = [
            VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.JMP, vip_delta=5),
            VMInstruction(vip=5, opcode=0, handler_address=0, operation=VMOperation.ADD),
        ]
        leaders = _identify_leaders(insns)
        assert 0 in leaders
        assert 1 in leaders  # after the jump

    def test_branch_target_is_leader(self):
        insns = [
            VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.ADD),
            VMInstruction(vip=1, opcode=0, handler_address=0, operation=VMOperation.JCC, vip_delta=0),  # branch to vip 1
            VMInstruction(vip=2, opcode=0, handler_address=0, operation=VMOperation.ADD),
        ]
        leaders = _identify_leaders(insns)
        assert 2 in leaders  # after branch
        assert 1 in leaders  # target (vip 1 → index 1)

    def test_empty(self):
        assert _identify_leaders([]) == set()


# ---------------------------------------------------------------------------
# _partition_into_blocks tests
# ---------------------------------------------------------------------------

class TestPartitionBlocks:
    def test_single_block(self):
        insns = [
            VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.ADD),
            VMInstruction(vip=1, opcode=0, handler_address=0, operation=VMOperation.RET),
        ]
        leaders = {0}
        blocks = _partition_into_blocks(insns, leaders)
        assert len(blocks) == 1
        assert blocks[0].instruction_count == 2
        assert blocks[0].is_entry is True
        assert blocks[0].is_exit is True

    def test_two_blocks(self):
        insns = [
            VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.JMP, vip_delta=2),
            VMInstruction(vip=2, opcode=0, handler_address=0, operation=VMOperation.RET),
        ]
        leaders = {0, 1}
        blocks = _partition_into_blocks(insns, leaders)
        assert len(blocks) == 2
        assert blocks[0].instruction_count == 1
        assert blocks[1].instruction_count == 1

    def test_empty(self):
        blocks = _partition_into_blocks([], set())
        assert blocks == []


# ---------------------------------------------------------------------------
# _build_edges tests
# ---------------------------------------------------------------------------

class TestBuildEdges:
    def test_fallthrough_edge(self):
        """Non-terminator last instruction → fallthrough."""
        b1 = HandlerBasicBlock(
            block_id=0, start_vip=0,
            instructions=[VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.ADD)],
        )
        b2 = HandlerBasicBlock(
            block_id=1, start_vip=1,
            instructions=[VMInstruction(vip=1, opcode=0, handler_address=0, operation=VMOperation.RET)],
            is_exit=True,
        )
        edges = _build_edges([b1, b2], [])
        assert len(edges) == 1
        assert edges[0].edge_type == "fallthrough"
        assert edges[0].source_block == 0
        assert edges[0].target_block == 1

    def test_jump_edge(self):
        """Unconditional jump → target block."""
        b1 = HandlerBasicBlock(
            block_id=0, start_vip=0,
            instructions=[VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.JMP, vip_delta=10)],
        )
        b2 = HandlerBasicBlock(
            block_id=1, start_vip=10,
            instructions=[VMInstruction(vip=10, opcode=0, handler_address=0, operation=VMOperation.RET)],
            is_exit=True,
        )
        edges = _build_edges([b1, b2], [])
        assert len(edges) == 1
        assert edges[0].edge_type == "jump"

    def test_return_no_edges(self):
        """Return block should have no outgoing edges."""
        b1 = HandlerBasicBlock(
            block_id=0, start_vip=0,
            instructions=[VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.RET)],
            is_exit=True,
        )
        edges = _build_edges([b1], [])
        assert edges == []

    def test_back_edge_detection(self):
        """Jump to earlier block should be a back-edge."""
        b1 = HandlerBasicBlock(
            block_id=0, start_vip=0,
            instructions=[VMInstruction(vip=0, opcode=0, handler_address=0, operation=VMOperation.ADD)],
        )
        b2 = HandlerBasicBlock(
            block_id=1, start_vip=5,
            instructions=[VMInstruction(vip=5, opcode=0, handler_address=0, operation=VMOperation.JMP, vip_delta=-5)],
        )
        edges = _build_edges([b1, b2], [])
        back = [e for e in edges if e.edge_type == "back_edge"]
        assert len(back) == 1
        assert back[0].source_block == 1
        assert back[0].target_block == 0


# ---------------------------------------------------------------------------
# build_handler_cfg end-to-end tests
# ---------------------------------------------------------------------------

class TestBuildHandlerCFG:
    def test_linear_function(self):
        """3 instructions, no branches → 1 block, 0 edges (exit block)."""
        entries = [
            _entry(0, 0x1000, VMOperation.PUSH),
            _entry(1, 0x2000, VMOperation.ADD),
            _entry(2, 0x3000, VMOperation.RET),
        ]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=1),
            FakeBoundary(vip_value=2, handler_address=0x3000, vip_delta=1),
        ]

        cfg = build_handler_cfg(table, boundaries)
        assert cfg.block_count == 1
        assert cfg.blocks[0].instruction_count == 3
        assert cfg.blocks[0].is_exit is True

    def test_function_with_jump(self):
        """PUSH, JMP(→vip=3), NOP, PUSH, RET → 3 blocks."""
        entries = [
            _entry(0x10, 0x1000, VMOperation.PUSH),
            _entry(0x20, 0x2000, VMOperation.JMP, vip_delta=2),
            _entry(0x30, 0x3000, VMOperation.NOP),
            _entry(0x40, 0x4000, VMOperation.PUSH),
            _entry(0x50, 0x5000, VMOperation.RET),
        ]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=2),  # JMP over NOP
            FakeBoundary(vip_value=3, handler_address=0x4000, vip_delta=1),  # land here
            FakeBoundary(vip_value=4, handler_address=0x5000, vip_delta=1),  # RET
        ]

        cfg = build_handler_cfg(table, boundaries)
        assert cfg.block_count >= 2
        assert cfg.edge_count >= 1
        assert any(e.edge_type == "jump" for e in cfg.edges)

    def test_function_with_loop(self):
        """Simple loop: PUSH, ADD, JMP(→vip=1), RET.

        The JMP at vip=2 targets vip=1 (ADD), creating a back-edge.
        But since we're replaying the trace in execution order, the JMP's
        fallthrough vip = 2 + (-1) = 1 should target the earlier block.
        """
        entries = [
            _entry(0x10, 0x1000, VMOperation.PUSH),
            _entry(0x20, 0x2000, VMOperation.ADD),
            _entry(0x30, 0x3000, VMOperation.JMP, vip_delta=-1),
            _entry(0x40, 0x4000, VMOperation.RET),
        ]
        table = _table(entries)

        # Simulate loop: PUSH, ADD, JMP, ADD, JMP, ADD, JMP, RET
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),  # PUSH
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=1),  # ADD (1st iter)
            FakeBoundary(vip_value=2, handler_address=0x3000, vip_delta=-1), # JMP → vip=1
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=1),  # ADD (2nd iter)
            FakeBoundary(vip_value=2, handler_address=0x3000, vip_delta=-1), # JMP → vip=1
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=1),  # ADD (3rd iter)
            FakeBoundary(vip_value=2, handler_address=0x3000, vip_delta=-1), # JMP → exit
            FakeBoundary(vip_value=3, handler_address=0x4000, vip_delta=1),  # RET
        ]

        cfg = build_handler_cfg(table, boundaries)
        assert cfg.block_count >= 2
        # Should have at least one back-edge.
        assert len(cfg.back_edges()) >= 1

    def test_conditional_branch(self):
        """PUSH, JCC, (taken path) ADD, RET."""
        entries = [
            _entry(0x10, 0x1000, VMOperation.PUSH),
            _entry(0x20, 0x2000, VMOperation.JCC, vip_delta=2),
            _entry(0x30, 0x3000, VMOperation.ADD),
            _entry(0x40, 0x4000, VMOperation.RET),
        ]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=2),  # JCC
            FakeBoundary(vip_value=3, handler_address=0x3000, vip_delta=1),  # taken
            FakeBoundary(vip_value=4, handler_address=0x4000, vip_delta=1),  # RET
        ]

        cfg = build_handler_cfg(table, boundaries)
        assert cfg.block_count >= 2
        # Should have a branch edge.
        branch_edges = [e for e in cfg.edges if "branch" in e.edge_type]
        assert len(branch_edges) >= 1

    def test_empty_boundaries(self):
        table = _table([])
        cfg = build_handler_cfg(table, [])
        assert cfg.block_count == 0

    def test_nx_graph_created(self):
        """networkx DiGraph should be created when available."""
        entries = [_entry(0, 0x1000, VMOperation.ADD), _entry(1, 0x2000, VMOperation.RET)]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000),
            FakeBoundary(vip_value=1, handler_address=0x2000),
        ]
        cfg = build_handler_cfg(table, boundaries)
        # networkx should be available in the test environment.
        assert cfg.graph is not None

    def test_to_dict_roundtrip(self):
        entries = [_entry(0, 0x1000, VMOperation.ADD), _entry(1, 0x2000, VMOperation.RET)]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000),
            FakeBoundary(vip_value=1, handler_address=0x2000),
        ]
        cfg = build_handler_cfg(table, boundaries)
        d = cfg.to_dict()
        assert "blocks" in d
        assert "edges" in d
        assert d["block_count"] > 0


# ---------------------------------------------------------------------------
# walk_static_bytecode tests
# ---------------------------------------------------------------------------

class TestWalkStaticBytecode:
    def test_simple_decode(self):
        """Static disassembly of 3 bytes → 3 VM instructions."""
        entries = [
            _entry(0x00, 0x1000, VMOperation.NOP),
            _entry(0x01, 0x2000, VMOperation.ADD),
            _entry(0xFF, 0x3000, VMOperation.RET),
        ]
        table = _table(entries)
        bytecode = bytes([0x00, 0x01, 0xFF])

        insns = walk_static_bytecode(bytecode, table, start_vip=0x1000)
        assert len(insns) == 3
        assert insns[0].vip == 0x1000
        assert insns[0].operation == VMOperation.NOP
        assert insns[1].operation == VMOperation.ADD
        assert insns[2].operation == VMOperation.RET

    def test_stop_at_ret(self):
        """Should stop after RET instruction."""
        entries = [
            _entry(0x00, 0x1000, VMOperation.ADD),
            _entry(0x01, 0x2000, VMOperation.RET),
        ]
        table = _table(entries)
        bytecode = bytes([0x00, 0x01, 0x00, 0x00])  # extra bytes after RET

        insns = walk_static_bytecode(bytecode, table, start_vip=0)
        assert len(insns) == 2  # stops at RET

    def test_unknown_opcode(self):
        """Unknown opcode should produce UNKNOWN instruction."""
        entries = [_entry(0x00, 0x1000, VMOperation.ADD)]
        table = _table(entries)
        bytecode = bytes([0x00, 0x99, 0x00])

        insns = walk_static_bytecode(bytecode, table, start_vip=0)
        assert len(insns) >= 2
        assert insns[1].operation == VMOperation.UNKNOWN

    def test_multi_byte_delta(self):
        """Handler with vip_delta > 1 should skip operand bytes."""
        entries = [
            _entry(0x10, 0x1000, VMOperation.PUSH, vip_delta=5),
            _entry(0x20, 0x2000, VMOperation.RET),
        ]
        table = _table(entries)
        bytecode = bytes([0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0x20])

        insns = walk_static_bytecode(bytecode, table, start_vip=0)
        assert len(insns) == 2
        assert insns[0].operation == VMOperation.PUSH
        assert insns[0].operand_bytes == bytes([0xAA, 0xBB, 0xCC, 0xDD])
        assert insns[1].vip == 5
        assert insns[1].operation == VMOperation.RET

    def test_empty_bytecode(self):
        insns = walk_static_bytecode(b"", _table([]))
        assert insns == []

    def test_max_instructions_limit(self):
        entries = [_entry(0x00, 0x1000, VMOperation.NOP)]
        table = _table(entries)
        bytecode = bytes([0x00] * 100)

        insns = walk_static_bytecode(bytecode, table, max_instructions=5)
        assert len(insns) == 5


# ---------------------------------------------------------------------------
# build_static_cfg tests
# ---------------------------------------------------------------------------

class TestBuildStaticCFG:
    def test_basic_static_cfg(self):
        entries = [
            _entry(0x00, 0x1000, VMOperation.PUSH),
            _entry(0x01, 0x2000, VMOperation.ADD),
            _entry(0x02, 0x3000, VMOperation.RET),
        ]
        table = _table(entries)
        bytecode = bytes([0x00, 0x01, 0x02])

        cfg = build_static_cfg(bytecode, table, start_vip=0)
        assert cfg.block_count == 1
        assert cfg.blocks[0].instruction_count == 3

    def test_static_with_jump(self):
        """Static CFG with a JMP instruction."""
        entries = [
            _entry(0x00, 0x1000, VMOperation.PUSH),
            _entry(0x01, 0x2000, VMOperation.JMP, vip_delta=2),
            _entry(0x02, 0x3000, VMOperation.RET),
        ]
        table = _table(entries)
        # PUSH at offset 0, JMP at offset 1 (delta=2→ target=3), RET at offset 2
        # but JMP stops at next instruction which is RET at offset 2 in static view
        bytecode = bytes([0x00, 0x01, 0x02])

        cfg = build_static_cfg(bytecode, table, start_vip=0)
        assert cfg.block_count >= 1

    def test_empty(self):
        cfg = build_static_cfg(b"", _table([]))
        assert cfg.block_count == 0


# ---------------------------------------------------------------------------
# detect_natural_loops tests
# ---------------------------------------------------------------------------

class TestDetectNaturalLoops:
    def test_no_back_edges_no_loops(self):
        blocks = [HandlerBasicBlock(block_id=0, start_vip=0)]
        edges = [CFGEdge(0, 1, "fallthrough")]
        loops = detect_natural_loops(blocks, edges)
        assert loops == []

    def test_back_edge_creates_loop(self):
        b0 = HandlerBasicBlock(block_id=0, start_vip=0, is_entry=True)
        b1 = HandlerBasicBlock(block_id=1, start_vip=5)
        blocks = [b0, b1]
        edges = [
            CFGEdge(0, 1, "fallthrough"),
            CFGEdge(1, 0, "back_edge"),
        ]
        graph = _build_nx_graph(blocks, edges)
        loops = detect_natural_loops(blocks, edges, graph)
        assert len(loops) == 1
        assert loops[0]["header"] == 0
        assert 0 in loops[0]["body"]
        assert 1 in loops[0]["body"]

    def test_fallback_without_graph(self):
        b0 = HandlerBasicBlock(block_id=0, start_vip=0)
        b1 = HandlerBasicBlock(block_id=1, start_vip=5)
        blocks = [b0, b1]
        edges = [CFGEdge(1, 0, "back_edge")]
        loops = detect_natural_loops(blocks, edges, graph=None)
        assert len(loops) == 1


# ---------------------------------------------------------------------------
# CFGEdge tests
# ---------------------------------------------------------------------------

class TestCFGEdge:
    def test_to_dict(self):
        e = CFGEdge(source_block=0, target_block=1, edge_type="jump")
        d = e.to_dict()
        assert d["source"] == 0
        assert d["target"] == 1
        assert d["type"] == "jump"


# ---------------------------------------------------------------------------
# Full pipeline scenario test
# ---------------------------------------------------------------------------

class TestFullScenario:
    """Simulate a realistic VMProtect-like function."""

    def test_vmprotect_style_function(self):
        """vm_push imm
        vm_push reg
        vm_add
        vm_cmp
        vm_jcc +offset
        vm_push result
        vm_ret
        """
        entries = [
            _entry(0x01, 0xA000, VMOperation.PUSH, vip_delta=5),
            _entry(0x02, 0xB000, VMOperation.PUSH, vip_delta=2),
            _entry(0x03, 0xC000, VMOperation.ADD, vip_delta=1),
            _entry(0x04, 0xD000, VMOperation.CMP, vip_delta=1),
            _entry(0x05, 0xE000, VMOperation.JCC, vip_delta=3),
            _entry(0x06, 0xF000, VMOperation.PUSH, vip_delta=2),
            _entry(0x07, 0xF100, VMOperation.RET, vip_delta=1),
        ]
        table = _table(entries)

        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0xA000, vip_delta=5),
            FakeBoundary(vip_value=5, handler_address=0xB000, vip_delta=2),
            FakeBoundary(vip_value=7, handler_address=0xC000, vip_delta=1),
            FakeBoundary(vip_value=8, handler_address=0xD000, vip_delta=1),
            FakeBoundary(vip_value=9, handler_address=0xE000, vip_delta=3),  # JCC
            FakeBoundary(vip_value=12, handler_address=0xF000, vip_delta=2),  # taken
            FakeBoundary(vip_value=14, handler_address=0xF100, vip_delta=1),  # RET
        ]

        cfg = build_handler_cfg(table, boundaries)

        # Basic sanity.
        assert cfg.block_count >= 2  # at least pre-branch + post-branch
        assert cfg.vm_instructions  # instructions were generated
        assert len(cfg.vm_instructions) == 7

        # Should have an exit block.
        exits = cfg.exit_blocks()
        assert len(exits) >= 1

        # Summary should be non-empty.
        s = cfg.summary()
        assert "blocks" in s
        assert "edges" in s

        # to_dict should be serialisable.
        d = cfg.to_dict()
        assert d["block_count"] == cfg.block_count

    def test_handler_cfg_with_networkx(self):
        """Verify networkx graph properties."""
        entries = [
            _entry(0, 0x1000, VMOperation.PUSH),
            _entry(1, 0x2000, VMOperation.JMP, vip_delta=2),
            _entry(2, 0x3000, VMOperation.ADD),
            _entry(3, 0x4000, VMOperation.RET),
        ]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=2),
            FakeBoundary(vip_value=3, handler_address=0x3000, vip_delta=1),
            FakeBoundary(vip_value=4, handler_address=0x4000, vip_delta=1),
        ]

        cfg = build_handler_cfg(table, boundaries)
        assert cfg.graph is not None

        import networkx as nx
        assert isinstance(cfg.graph, nx.DiGraph)
        assert cfg.graph.number_of_nodes() == cfg.block_count

    def test_topological_order_with_graph(self):
        """Topological order should work when graph is available."""
        entries = [
            _entry(0, 0x1000, VMOperation.ADD),
            _entry(1, 0x2000, VMOperation.ADD),
            _entry(2, 0x3000, VMOperation.RET),
        ]
        table = _table(entries)
        boundaries = [
            FakeBoundary(vip_value=0, handler_address=0x1000, vip_delta=1),
            FakeBoundary(vip_value=1, handler_address=0x2000, vip_delta=1),
            FakeBoundary(vip_value=2, handler_address=0x3000, vip_delta=1),
        ]

        cfg = build_handler_cfg(table, boundaries)
        order = cfg.topological_order()
        # Since it's linear, topological order = natural order.
        assert order == [b.block_id for b in cfg.blocks]
