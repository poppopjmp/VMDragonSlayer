"""Tests for CFG reconstruction module."""

import pytest

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceControlFlow,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)
from dragonslayer.analysis.cfg import (
    build_instruction_cfg,
    build_handler_cfg,
    extract_basic_blocks,
    analyse_cfg,
    find_dominators,
    BasicBlock,
    CFGStats,
    NX_AVAILABLE as MODULE_NX,
)


pytestmark = pytest.mark.skipif(not NX_AVAILABLE, reason="networkx not installed")


def _ti(addr, size=1, disasm="nop"):
    return TraceInstruction(
        address=addr, size=size, raw_bytes=b"\x90" * size, disassembly=disasm,
    )


# ---------------------------------------------------------------------------
# Instruction-level CFG
# ---------------------------------------------------------------------------

class TestBuildInstructionCFG:
    def test_basic_linear(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x1000), _ti(0x1001), _ti(0x1002),
        ])
        G = build_instruction_cfg(trace)
        assert G.number_of_nodes() == 3
        assert G.has_edge(0x1000, 0x1001)
        assert G.has_edge(0x1001, 0x1002)

    def test_branch_edges_from_control_flow(self):
        trace = ExecutionTrace(
            instructions=[_ti(0x1000), _ti(0x1001), _ti(0x2000)],
            control_flow=[
                TraceControlFlow(type="jmp", source=0x1001, target=0x2000),
            ],
        )
        G = build_instruction_cfg(trace)
        assert G[0x1001][0x2000]["type"] == "jmp"

    def test_no_fallthrough(self):
        trace = ExecutionTrace(instructions=[_ti(0x1000), _ti(0x2000)])
        G = build_instruction_cfg(trace, include_fallthrough=False)
        assert G.number_of_edges() == 0

    def test_self_loop_excluded(self):
        trace = ExecutionTrace(instructions=[_ti(0x1000), _ti(0x1000)])
        G = build_instruction_cfg(trace)
        assert not G.has_edge(0x1000, 0x1000)

    def test_weight_accumulation(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x1000), _ti(0x1001),
            _ti(0x1000), _ti(0x1001),
        ])
        G = build_instruction_cfg(trace)
        assert G[0x1000][0x1001]["weight"] == 2

    def test_empty_trace(self):
        G = build_instruction_cfg(ExecutionTrace())
        assert G.number_of_nodes() == 0

    def test_control_flow_adds_missing_nodes(self):
        trace = ExecutionTrace(
            instructions=[],
            control_flow=[
                TraceControlFlow(type="call", source=0x1000, target=0x2000),
            ],
        )
        G = build_instruction_cfg(trace)
        assert G.has_node(0x1000)
        assert G.has_node(0x2000)


# ---------------------------------------------------------------------------
# Basic blocks
# ---------------------------------------------------------------------------

class TestExtractBasicBlocks:
    def test_single_block(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x1000), _ti(0x1001), _ti(0x1002),
        ])
        G = build_instruction_cfg(trace)
        blocks = extract_basic_blocks(G)
        assert len(blocks) >= 1
        assert blocks[0].start_address == 0x1000

    def test_split_at_branch_target(self):
        trace = ExecutionTrace(
            instructions=[
                _ti(0x1000), _ti(0x1001), _ti(0x2000), _ti(0x2001),
            ],
            control_flow=[
                TraceControlFlow(type="jmp", source=0x1001, target=0x2000),
            ],
        )
        G = build_instruction_cfg(trace)
        blocks = extract_basic_blocks(G)
        # There should be at least 2 blocks since 0x2000 is a branch target
        assert len(blocks) >= 2

    def test_block_size_property(self):
        b = BasicBlock(start_address=0x1000, end_address=0x1010)
        assert b.size == 0x10


# ---------------------------------------------------------------------------
# Handler-level CFG
# ---------------------------------------------------------------------------

class TestBuildHandlerCFG:
    def test_sequential_chain(self):
        boundaries = [
            HandlerBoundary(vip_value=0x100, handler_address=0x6000,
                            trace_start=0, trace_end=5, instruction_count=5),
            HandlerBoundary(vip_value=0x104, handler_address=0x7000,
                            trace_start=5, trace_end=10, instruction_count=5),
            HandlerBoundary(vip_value=0x108, handler_address=0x8000,
                            trace_start=10, trace_end=15, instruction_count=5),
        ]
        G = build_handler_cfg(boundaries)
        assert G.number_of_nodes() == 3
        assert G.has_edge(0, 1)
        assert G.has_edge(1, 2)

    def test_back_edge_detected(self):
        boundaries = [
            HandlerBoundary(vip_value=0x100, handler_address=0x6000,
                            trace_start=0, trace_end=5, instruction_count=5),
            HandlerBoundary(vip_value=0x104, handler_address=0x7000,
                            trace_start=5, trace_end=10, instruction_count=5),
            HandlerBoundary(vip_value=0x108, handler_address=0x6000,  # same as first
                            trace_start=10, trace_end=15, instruction_count=5),
        ]
        G = build_handler_cfg(boundaries)
        # Back edge from index 2 to index 0 (same handler address)
        assert G.has_edge(2, 0)
        assert G[2][0]["type"] == "back_edge"

    def test_node_attributes(self):
        boundaries = [
            HandlerBoundary(vip_value=0x100, handler_address=0x6000,
                            trace_start=0, trace_end=5, instruction_count=5,
                            category="arithmetic"),
        ]
        G = build_handler_cfg(boundaries)
        assert G.nodes[0]["category"] == "arithmetic"
        assert G.nodes[0]["vip_value"] == 0x100

    def test_empty(self):
        G = build_handler_cfg([])
        assert G.number_of_nodes() == 0


# ---------------------------------------------------------------------------
# CFG analysis
# ---------------------------------------------------------------------------

class TestAnalyseCFG:
    def test_stats_linear(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x1000), _ti(0x1001), _ti(0x1002),
        ])
        G = build_instruction_cfg(trace)
        stats = analyse_cfg(G)
        assert stats.node_count == 3
        assert stats.edge_count == 2
        assert stats.loop_count == 0
        assert len(stats.entry_points) == 1
        assert len(stats.exit_points) == 1

    def test_stats_with_back_edge(self):
        boundaries = [
            HandlerBoundary(vip_value=0x100, handler_address=0x6000,
                            trace_start=0, trace_end=5, instruction_count=5),
            HandlerBoundary(vip_value=0x104, handler_address=0x7000,
                            trace_start=5, trace_end=10, instruction_count=5),
            HandlerBoundary(vip_value=0x108, handler_address=0x6000,
                            trace_start=10, trace_end=15, instruction_count=5),
        ]
        G = build_handler_cfg(boundaries)
        stats = analyse_cfg(G)
        assert stats.back_edge_count == 1
        assert stats.loop_count >= 1

    def test_to_dict(self):
        stats = CFGStats(node_count=5, edge_count=4, entry_points=[0x1000])
        d = stats.to_dict()
        assert d["node_count"] == 5
        assert d["entry_points"] == ["0x1000"]


class TestFindDominators:
    def test_linear_dominators(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x1000), _ti(0x1001), _ti(0x1002),
        ])
        G = build_instruction_cfg(trace)
        doms = find_dominators(G)
        assert doms[0x1001] == 0x1000
        assert doms[0x1002] == 0x1001

    def test_empty_graph(self):
        import networkx as nx
        G = nx.DiGraph()
        doms = find_dominators(G)
        assert doms == {}
