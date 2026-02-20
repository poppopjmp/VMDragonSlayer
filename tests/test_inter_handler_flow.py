"""
B46 — Inter-Handler Data-Flow Tests
=====================================

Tests for:
1. HandlerTaintSummary construction (from symbolic summaries + raw instructions)
2. InterHandlerDataFlow fixed-point propagation
3. Backward taint slicing
4. Live-register analysis
5. Inter-handler flow edge construction
6. Canonical register normalisation
"""

import pytest

from dragonslayer.analysis.taint_tracking.inter_handler import (
    HandlerTaintSummary,
    InterHandlerDataFlow,
    InterHandlerFlowEdge,
    InterHandlerFlowResult,
    build_handler_summary,
    canonicalize_reg,
)


# ---------------------------------------------------------------------------
# 1. canonicalize_reg
# ---------------------------------------------------------------------------

class TestCanonicalizeReg:
    def test_64bit_identity(self):
        assert canonicalize_reg("rax") == "rax"
        assert canonicalize_reg("r15") == "r15"

    def test_32bit(self):
        assert canonicalize_reg("eax") == "rax"
        assert canonicalize_reg("r8d") == "r8"

    def test_16bit(self):
        assert canonicalize_reg("ax") == "rax"
        assert canonicalize_reg("si") == "rsi"

    def test_8bit(self):
        assert canonicalize_reg("al") == "rax"
        assert canonicalize_reg("ah") == "rax"
        assert canonicalize_reg("r9b") == "r9"

    def test_upper_case(self):
        assert canonicalize_reg("RAX") == "rax"
        assert canonicalize_reg("EBX") == "rbx"

    def test_unknown_passthrough(self):
        assert canonicalize_reg("xmm0") == "xmm0"


# ---------------------------------------------------------------------------
# 2. build_handler_summary
# ---------------------------------------------------------------------------

class TestBuildHandlerSummary:
    def test_from_symbolic_summary(self):
        sym = {
            "final_registers": {"rax": "init_rbx + 1", "rcx": "42"},
            "simplified_registers": {},
            "input_symbols": {"init_rbx": "64", "init_rsi": "64"},
            "memory_effects": {
                "loads": [{"region": "vm_context"}],
                "stores": [{"region": "stack"}],
            },
        }
        s = build_handler_summary(0x1000, symbolic_summary=sym)
        assert s.handler_id == 0x1000
        assert "rax" in s.defs
        assert "rcx" in s.defs
        assert "rbx" in s.uses
        assert "rsi" in s.uses
        assert "vm_context" in s.memory_uses
        assert "stack" in s.memory_defs
        assert s.kill == s.defs

    def test_from_instructions(self):
        insns = [
            {"reads": ["rsi", "rdi"], "writes": ["rax"]},
            {"reads": ["rax"], "writes": ["rcx"]},
        ]
        s = build_handler_summary(0x2000, instructions=insns)
        assert "rsi" in s.uses
        assert "rdi" in s.uses
        # rax is read in insn 2, but defined in insn 1 → not a use
        assert "rax" not in s.uses
        assert "rax" in s.defs
        assert "rcx" in s.defs

    def test_empty(self):
        s = build_handler_summary(0)
        assert s.defs == set()
        assert s.uses == set()


# ---------------------------------------------------------------------------
# 3. InterHandlerDataFlow.propagate
# ---------------------------------------------------------------------------

class TestTaintPropagation:
    def _make_chain(self):
        """Three-handler chain: A → B → C.

        A: uses rsi, defs rax
        B: uses rax, defs rcx
        C: uses rcx, defs rdx
        """
        a = HandlerTaintSummary(handler_id=1, uses={"rsi"}, defs={"rax"}, kill={"rax"})
        b = HandlerTaintSummary(handler_id=2, uses={"rax"}, defs={"rcx"}, kill={"rcx"})
        c = HandlerTaintSummary(handler_id=3, uses={"rcx"}, defs={"rdx"}, kill={"rdx"})
        return [a, b, c]

    def test_propagation_converges(self):
        chain = self._make_chain()
        flow = InterHandlerDataFlow()
        result = flow.propagate(chain, initial_taint={"rsi"})
        assert result.converged is True
        assert result.iterations <= 5

    def test_taint_reaches_last_handler(self):
        chain = self._make_chain()
        flow = InterHandlerDataFlow()
        result = flow.propagate(chain, initial_taint={"rsi"})
        # rsi → A defs rax → B uses rax, defs rcx → C uses rcx
        assert "rsi" in chain[0].taint_in
        assert "rax" in chain[0].taint_out
        assert "rax" in chain[1].taint_in
        assert "rcx" in chain[1].taint_out
        assert "rcx" in chain[2].taint_in

    def test_untainted_register_not_propagated(self):
        chain = self._make_chain()
        flow = InterHandlerDataFlow()
        result = flow.propagate(chain, initial_taint={"rsi"})
        # rbx is never mentioned — should not appear
        for s in chain:
            assert "rbx" not in s.taint_in
            assert "rbx" not in s.taint_out

    def test_kill_stops_propagation(self):
        """A register killed by handler stops flowing."""
        a = HandlerTaintSummary(handler_id=1, defs={"rax"}, kill={"rax"})
        b = HandlerTaintSummary(handler_id=2, uses={"rbx"}, defs=set(), kill=set())
        flow = InterHandlerDataFlow()
        result = flow.propagate([a, b], initial_taint={"rax", "rbx"})
        # rax is killed by A, but A also defs it — so it appears in taint_out
        # of A if any input is tainted. Since rax is in initial_taint,
        # A's taint_in has rax but A uses nothing tainted, so defs don't fire.
        # rax is killed → disappears. rbx passes through (not killed by A).
        assert "rbx" in b.taint_in

    def test_empty_summaries(self):
        flow = InterHandlerDataFlow()
        result = flow.propagate([])
        assert result.converged is True
        assert result.summaries == []

    def test_single_handler(self):
        s = HandlerTaintSummary(handler_id=1, uses={"rax"}, defs={"rbx"}, kill={"rbx"})
        flow = InterHandlerDataFlow()
        result = flow.propagate([s], initial_taint={"rax"})
        assert result.converged
        assert "rax" in s.taint_in
        assert "rbx" in s.taint_out


# ---------------------------------------------------------------------------
# 4. Flow edges
# ---------------------------------------------------------------------------

class TestFlowEdges:
    def test_register_flow_edge(self):
        a = HandlerTaintSummary(handler_id=1, uses={"rsi"}, defs={"rax"}, kill={"rax"})
        b = HandlerTaintSummary(handler_id=2, uses={"rax"}, defs={"rcx"}, kill={"rcx"})
        flow = InterHandlerDataFlow()
        result = flow.propagate([a, b], initial_taint={"rsi"})
        reg_edges = [e for e in result.edges if not e.via_memory]
        assert any(e.register == "rax" and e.source == 1 and e.target == 2 for e in reg_edges)

    def test_memory_flow_edge(self):
        a = HandlerTaintSummary(handler_id=1, defs=set(), memory_defs={"stack"}, kill=set())
        b = HandlerTaintSummary(handler_id=2, uses=set(), memory_uses={"stack"}, kill=set())
        flow = InterHandlerDataFlow()
        result = flow.propagate([a, b])
        mem_edges = [e for e in result.edges if e.via_memory]
        assert any(e.register == "mem:stack" for e in mem_edges)

    def test_no_edge_without_def_use_match(self):
        a = HandlerTaintSummary(handler_id=1, defs={"rax"}, kill={"rax"})
        b = HandlerTaintSummary(handler_id=2, uses={"rbx"}, defs=set(), kill=set())
        flow = InterHandlerDataFlow()
        result = flow.propagate([a, b], initial_taint={"rax"})
        reg_edges = [e for e in result.edges if not e.via_memory]
        # rax flows from A but B doesn't use rax → no register edge
        assert not any(e.register == "rax" for e in reg_edges)


# ---------------------------------------------------------------------------
# 5. Backward taint slice
# ---------------------------------------------------------------------------

class TestTaintSlice:
    def test_slice_for_rdx(self):
        """rdx defined by C ← rcx used from B ← rax used from A."""
        chain = [
            HandlerTaintSummary(handler_id=1, uses={"rsi"}, defs={"rax"}, kill={"rax"}),
            HandlerTaintSummary(handler_id=2, uses={"rax"}, defs={"rcx"}, kill={"rcx"}),
            HandlerTaintSummary(handler_id=3, uses={"rcx"}, defs={"rdx"}, kill={"rdx"}),
        ]
        flow = InterHandlerDataFlow()
        contributors = flow.compute_taint_slice(chain, "rdx")
        assert 3 in contributors
        assert 2 in contributors
        assert 1 in contributors

    def test_slice_single_handler(self):
        chain = [HandlerTaintSummary(handler_id=1, uses=set(), defs={"rax"}, kill={"rax"})]
        flow = InterHandlerDataFlow()
        contributors = flow.compute_taint_slice(chain, "rax")
        assert contributors == [1]

    def test_slice_no_match(self):
        chain = [HandlerTaintSummary(handler_id=1, uses=set(), defs={"rax"}, kill={"rax"})]
        flow = InterHandlerDataFlow()
        contributors = flow.compute_taint_slice(chain, "rbx")
        assert contributors == []


# ---------------------------------------------------------------------------
# 6. Live-register analysis
# ---------------------------------------------------------------------------

class TestLiveRegisters:
    def test_live_at_entry(self):
        chain = [
            HandlerTaintSummary(handler_id=1, uses={"rsi"}, defs={"rax"}, kill={"rax"}),
            HandlerTaintSummary(handler_id=2, uses={"rax"}, defs={"rcx"}, kill={"rcx"}),
        ]
        flow = InterHandlerDataFlow()
        live = flow.get_live_registers(chain, 0)
        assert "rsi" in live
        # rax is killed (defined) by handler 1, so it's NOT live at entry
        # but it IS live at handler 2's entry
        live2 = flow.get_live_registers(chain, 1)
        assert "rax" in live2

    def test_dead_after_kill(self):
        chain = [
            HandlerTaintSummary(handler_id=1, uses=set(), defs={"rax"}, kill={"rax"}),
            HandlerTaintSummary(handler_id=2, uses=set(), defs=set(), kill=set()),
        ]
        flow = InterHandlerDataFlow()
        live = flow.get_live_registers(chain, 0)
        # rax is defined but never used later → not live
        assert "rax" not in live

    def test_empty(self):
        flow = InterHandlerDataFlow()
        assert flow.get_live_registers([], 0) == set()

    def test_out_of_bounds(self):
        chain = [HandlerTaintSummary(handler_id=1)]
        flow = InterHandlerDataFlow()
        assert flow.get_live_registers(chain, 5) == set()


# ---------------------------------------------------------------------------
# 7. Serialisation
# ---------------------------------------------------------------------------

class TestSerialisation:
    def test_summary_to_dict(self):
        s = HandlerTaintSummary(handler_id=1, defs={"rax"}, uses={"rbx"})
        d = s.to_dict()
        assert d["handler_id"] == 1
        assert "rax" in d["defs"]
        assert "rbx" in d["uses"]

    def test_edge_to_dict(self):
        e = InterHandlerFlowEdge(source=1, target=2, register="rax")
        d = e.to_dict()
        assert d["source"] == 1
        assert d["register"] == "rax"
        assert d["via_memory"] is False

    def test_result_to_dict(self):
        r = InterHandlerFlowResult(summaries=[], edges=[], iterations=3, converged=True)
        d = r.to_dict()
        assert d["converged"] is True
        assert d["iterations"] == 3
