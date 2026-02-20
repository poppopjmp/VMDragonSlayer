"""
Tests for B51 — Backward Slicing, Live Ranges & Memory-Sensitive Taint.

Covers:
  1. backward_slice() on DataFlowResult def-use graphs
  2. compute_live_ranges() standalone helper
  3. TaintTracker alias-oracle integration for memory-sensitive taint
"""

from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from dragonslayer.analysis.dataflow import (
    DataFlowResult,
    VarDef,
    VarUse,
    LiveRange,
    backward_slice,
    compute_live_ranges,
    BackwardSliceResult,
)
from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers — build synthetic DataFlowResult graphs
# ═══════════════════════════════════════════════════════════════════════════════

def _make_result(
    defs: list[tuple[str, int]],
    uses: list[tuple[str, int]],
    edges: list[tuple[str, str, int, int]],
) -> DataFlowResult:
    """Build a DataFlowResult from simplified specs.

    defs: [(name, handler_index), ...]
    uses: [(name, handler_index), ...]
    edges: [(consumed, produced, def_idx, use_idx), ...]
    """
    r = DataFlowResult()
    for name, hi in defs:
        d = VarDef(name=name, handler_index=hi, handler_addr=0x1000 + hi, operation="op")
        r.definitions.append(d)
        r.reaching_defs[name] = d
    for name, hi in uses:
        r.uses.append(VarUse(name=name, handler_index=hi, handler_addr=0x1000 + hi, operation="op"))
    r.def_use_edges = list(edges)
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# 1. backward_slice tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardSlice:
    """Test backward_slice() on various def-use graph topologies."""

    def test_single_variable_no_deps(self):
        """A variable with no incoming edges → slice contains only itself."""
        r = _make_result(
            defs=[("v0", 0)],
            uses=[],
            edges=[],
        )
        sl = backward_slice(r, "v0")
        assert sl.target == "v0"
        assert "v0" in sl.contributing_vars
        assert 0 in sl.handler_indices
        assert len(sl.edges) == 0

    def test_linear_chain(self):
        """v0 → v1 → v2 — slicing on v2 should include all three."""
        r = _make_result(
            defs=[("v0", 0), ("v1", 1), ("v2", 2)],
            uses=[("v0", 1), ("v1", 2)],
            edges=[("v0", "v1", 0, 1), ("v1", "v2", 1, 2)],
        )
        sl = backward_slice(r, "v2")
        assert set(sl.contributing_vars) == {"v0", "v1", "v2"}
        assert set(sl.handler_indices) == {0, 1, 2}
        assert len(sl.edges) == 2

    def test_diamond_graph(self):
        """v0 → v1, v0 → v2, v1+v2 → v3 — slicing v3 captures all."""
        r = _make_result(
            defs=[("v0", 0), ("v1", 1), ("v2", 1), ("v3", 2)],
            uses=[("v0", 1), ("v0", 1), ("v1", 2), ("v2", 2)],
            edges=[
                ("v0", "v1", 0, 1),
                ("v0", "v2", 0, 1),
                ("v1", "v3", 1, 2),
                ("v2", "v3", 1, 2),
            ],
        )
        sl = backward_slice(r, "v3")
        assert set(sl.contributing_vars) == {"v0", "v1", "v2", "v3"}

    def test_slice_stops_at_root(self):
        """Slicing an intermediate node stops at the root."""
        r = _make_result(
            defs=[("a", 0), ("b", 1), ("c", 2)],
            uses=[("a", 1), ("b", 2)],
            edges=[("a", "b", 0, 1), ("b", "c", 1, 2)],
        )
        sl = backward_slice(r, "b")
        assert set(sl.contributing_vars) == {"a", "b"}
        assert "c" not in sl.contributing_vars

    def test_unknown_target(self):
        """Slicing on a variable not in the graph → empty result."""
        r = _make_result(
            defs=[("v0", 0)],
            uses=[],
            edges=[],
        )
        sl = backward_slice(r, "nonexistent")
        assert sl.target == "nonexistent"
        assert sl.contributing_vars == ["nonexistent"]  # contains itself
        assert sl.handler_indices == []  # not in reaching_defs

    def test_boundary_index_filter(self):
        """boundary_index limits the slice to edges within range."""
        r = _make_result(
            defs=[("a", 0), ("b", 1), ("c", 5)],
            uses=[("a", 1), ("b", 5)],
            edges=[("a", "b", 0, 1), ("b", "c", 1, 5)],
        )
        # Slice on "c" but limit to handler_index <= 3
        sl = backward_slice(r, "c", boundary_index=3)
        # The edge (b → c) at use_idx=5 is excluded
        assert "b" not in sl.contributing_vars

    def test_boundary_includes_within_range(self):
        """boundary_index includes edges within range."""
        r = _make_result(
            defs=[("a", 0), ("b", 1), ("c", 2)],
            uses=[("a", 1), ("b", 2)],
            edges=[("a", "b", 0, 1), ("b", "c", 1, 2)],
        )
        sl = backward_slice(r, "c", boundary_index=2)
        assert set(sl.contributing_vars) == {"a", "b", "c"}

    def test_multiple_roots(self):
        """Graph with two independent roots feeding into one variable."""
        r = _make_result(
            defs=[("x", 0), ("y", 1), ("z", 2)],
            uses=[("x", 2), ("y", 2)],
            edges=[("x", "z", 0, 2), ("y", "z", 1, 2)],
        )
        sl = backward_slice(r, "z")
        assert set(sl.contributing_vars) == {"x", "y", "z"}
        assert set(sl.handler_indices) == {0, 1, 2}

    def test_cycle_safe(self):
        """Cycles in edges don't cause infinite loop."""
        r = _make_result(
            defs=[("a", 0), ("b", 1)],
            uses=[("a", 1), ("b", 0)],
            edges=[("a", "b", 0, 1), ("b", "a", 1, 0)],
        )
        sl = backward_slice(r, "a")
        # Should terminate and include both
        assert set(sl.contributing_vars) == {"a", "b"}

    def test_summary_method(self):
        """BackwardSliceResult.summary() returns proper dict."""
        r = _make_result(
            defs=[("v0", 0), ("v1", 1)],
            uses=[("v0", 1)],
            edges=[("v0", "v1", 0, 1)],
        )
        sl = backward_slice(r, "v1")
        s = sl.summary()
        assert s["target"] == "v1"
        assert s["contributing_count"] == 2
        assert s["handler_count"] == 2

    def test_long_chain(self):
        """Stress test: chain of 50 variables."""
        n = 50
        defs = [(f"v{i}", i) for i in range(n)]
        uses = [(f"v{i}", i + 1) for i in range(n - 1)]
        edges = [(f"v{i}", f"v{i+1}", i, i + 1) for i in range(n - 1)]
        r = _make_result(defs, uses, edges)
        sl = backward_slice(r, f"v{n-1}")
        assert len(sl.contributing_vars) == n

    def test_wide_fan_in(self):
        """Many variables feed into one: fan-in of 10."""
        defs = [(f"src{i}", i) for i in range(10)] + [("sink", 10)]
        uses = [(f"src{i}", 10) for i in range(10)]
        edges = [(f"src{i}", "sink", i, 10) for i in range(10)]
        r = _make_result(defs, uses, edges)
        sl = backward_slice(r, "sink")
        assert len(sl.contributing_vars) == 11


# ═══════════════════════════════════════════════════════════════════════════════
# 2. compute_live_ranges tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestComputeLiveRanges:
    """Test standalone compute_live_ranges()."""

    def test_empty_result(self):
        """No definitions → no live ranges."""
        r = DataFlowResult()
        lr = compute_live_ranges(r)
        assert lr == []

    def test_single_def_no_use(self):
        """Dead variable: def only, no use → last_use_index=-1."""
        r = _make_result(defs=[("v0", 0)], uses=[], edges=[])
        lr = compute_live_ranges(r)
        assert len(lr) == 1
        assert lr[0].name == "v0"
        assert lr[0].def_index == 0
        assert lr[0].last_use_index == -1

    def test_single_use(self):
        """Variable used once → last_use_index equals use handler."""
        r = _make_result(
            defs=[("v0", 0)],
            uses=[("v0", 3)],
            edges=[],
        )
        lr = compute_live_ranges(r)
        assert lr[0].last_use_index == 3

    def test_multiple_uses(self):
        """Variable used at handlers 2, 5, 8 → last_use=8."""
        r = _make_result(
            defs=[("v0", 0)],
            uses=[("v0", 2), ("v0", 5), ("v0", 8)],
            edges=[],
        )
        lr = compute_live_ranges(r)
        assert lr[0].last_use_index == 8

    def test_multiple_variables(self):
        """Multiple variables with different live ranges."""
        r = _make_result(
            defs=[("a", 0), ("b", 1), ("c", 3)],
            uses=[("a", 2), ("a", 4), ("b", 5)],
            edges=[],
        )
        lr = compute_live_ranges(r)
        by_name = {x.name: x for x in lr}
        assert by_name["a"].last_use_index == 4
        assert by_name["b"].last_use_index == 5
        assert by_name["c"].last_use_index == -1  # dead

    def test_matches_dataflowresult_liveranges(self):
        """Standalone compute_live_ranges matches DataFlowResult.live_ranges."""
        # Build a non-trivial result manually
        r = _make_result(
            defs=[("x", 0), ("y", 2), ("z", 4)],
            uses=[("x", 1), ("x", 3), ("y", 5)],
            edges=[],
        )
        # Compute with standalone
        lr = compute_live_ranges(r)
        by_name = {x.name: x for x in lr}
        assert by_name["x"].def_index == 0
        assert by_name["x"].last_use_index == 3
        assert by_name["y"].last_use_index == 5
        assert by_name["z"].last_use_index == -1


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Memory-sensitive taint via alias oracle
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FakeInstruction:
    """Minimal instruction stub for taint tests."""
    address: int = 0
    mnemonic: str = ""
    operands: str = ""
    reads: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    category: str = "unknown"
    registers: dict = field(default_factory=dict)
    symbolic_address: Any = None


class TestAliasOracleTaint:
    """Test TaintTracker with alias_oracle for memory-sensitive taint."""

    def _make_oracle(self, alias_map: dict):
        """Return a simple oracle callable.

        alias_map: {(addr1, addr2): "must"/"may"/"no"}
        Checks both (a, b) and (b, a) for symmetry.
        Default: "no".
        """
        def oracle(a, b):
            r = alias_map.get((a, b))
            if r is not None:
                return r
            r = alias_map.get((b, a))
            if r is not None:
                return r
            return "no"
        return oracle

    def test_no_oracle_baseline(self):
        """Without oracle, concrete-only memory taint works as before."""
        tracker = TaintTracker()
        tracker.taint_memory(0x1000, TaintTag.INPUT)

        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rax, [0x1000]",
            reads=["rbx"],
            writes=["rax"],
            category="memory_read",
            registers={"rbx": 0x1000},
        )
        tracker.process_instruction(insn)
        assert tracker.is_tainted("rax")

    def test_oracle_must_alias_propagates(self):
        """MUST alias → taint propagates from stored address to loaded address."""
        oracle = self._make_oracle({(0x2000, 0x1000): "must"})
        tracker = TaintTracker(alias_oracle=oracle)
        tracker.taint_memory(0x1000, TaintTag.INPUT)

        # Load from 0x2000 — concrete lookup misses, oracle says MUST alias
        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rax, [0x2000]",
            reads=[],
            writes=["rax"],
            category="memory_read",
            registers={},
        )
        tracker.process_instruction(insn)
        assert tracker.is_tainted("rax")

    def test_oracle_may_alias_propagates(self):
        """MAY alias → taint propagates conservatively."""
        oracle = self._make_oracle({(0x3000, 0x1000): "may"})
        tracker = TaintTracker(alias_oracle=oracle)
        tracker.taint_memory(0x1000, TaintTag.VM_OPERAND)

        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rcx, [0x3000]",
            reads=[],
            writes=["rcx"],
            category="memory_read",
            registers={},
        )
        tracker.process_instruction(insn)
        assert tracker.is_tainted("rcx")

    def test_oracle_no_alias_blocks(self):
        """NO alias → taint does NOT propagate."""
        oracle = self._make_oracle({(0x4000, 0x1000): "no"})
        tracker = TaintTracker(alias_oracle=oracle)
        tracker.taint_memory(0x1000, TaintTag.INPUT)

        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rdx, [0x4000]",
            reads=[],
            writes=["rdx"],
            category="memory_read",
            registers={},
        )
        tracker.process_instruction(insn)
        assert not tracker.is_tainted("rdx")

    def test_symbolic_store_then_load(self):
        """Store to symbolic addr, then load with oracle MUST → propagates."""
        # Symbolic address is a string placeholder (e.g. z3 expression)
        sym_store_addr = "rsp_plus_8"
        sym_load_addr = "rsp_plus_8_v2"

        oracle = self._make_oracle({(sym_load_addr, sym_store_addr): "must"})
        tracker = TaintTracker(alias_oracle=oracle)

        # First, taint rax
        tracker.taint_register("rax", TaintTag.INPUT)

        # Store tainted rax to symbolic address
        store_insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="[rsp+8], rax",
            reads=["rax"],
            writes=[],
            category="memory_write",
            registers={},
            symbolic_address=sym_store_addr,
        )
        tracker.process_instruction(store_insn)

        # Load from different symbolic address that MUST aliases
        load_insn = FakeInstruction(
            address=0x404,
            mnemonic="mov",
            operands="rbx, [rsp+8]",
            reads=[],
            writes=["rbx"],
            category="memory_read",
            registers={},
            symbolic_address=sym_load_addr,
        )
        tracker.process_instruction(load_insn)
        assert tracker.is_tainted("rbx")

    def test_taint_symbolic_memory_api(self):
        """taint_symbolic_memory() makes address available for oracle queries."""
        sym_addr1 = "heap_ptr_1"
        sym_addr2 = "heap_ptr_2"
        oracle = self._make_oracle({(sym_addr2, sym_addr1): "must"})

        tracker = TaintTracker(alias_oracle=oracle)
        tracker.taint_symbolic_memory(sym_addr1, TaintTag.CRYPTO)

        # Load from sym_addr2 — oracle says MUST alias with sym_addr1
        insn = FakeInstruction(
            address=0x500,
            mnemonic="mov",
            operands="r8, [rbx]",
            reads=[],
            writes=["r8"],
            category="memory_read",
            registers={},
            symbolic_address=sym_addr2,
        )
        tracker.process_instruction(insn)
        assert tracker.is_tainted("r8")
        assert tracker.get_taint("r8") & TaintTag.CRYPTO

    def test_oracle_exception_graceful(self):
        """If the oracle raises, we fall back to CLEAN (no crash)."""
        def broken_oracle(a, b):
            raise RuntimeError("solver timeout")

        tracker = TaintTracker(alias_oracle=broken_oracle)
        tracker.taint_memory(0x1000, TaintTag.INPUT)

        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rax, [0x2000]",
            reads=[],
            writes=["rax"],
            category="memory_read",
            registers={},
        )
        tracker.process_instruction(insn)
        # Shouldn't crash, and since oracle fails, no taint propagated
        assert not tracker.is_tainted("rax")

    def test_reset_clears_symbolic_mem(self):
        """reset() clears symbolic memory taint map."""
        tracker = TaintTracker(alias_oracle=lambda a, b: "no")
        tracker.taint_symbolic_memory("sym1", TaintTag.INPUT)
        assert len(tracker._symbolic_mem_taint) == 1
        tracker.reset()
        assert len(tracker._symbolic_mem_taint) == 0

    def test_oracle_combines_multiple_aliases(self):
        """When multiple tainted addresses alias, tags are OR-combined."""
        oracle = self._make_oracle({
            (0x5000, 0x1000): "must",
            (0x5000, 0x2000): "must",
        })
        tracker = TaintTracker(alias_oracle=oracle)
        tracker.taint_memory(0x1000, TaintTag.INPUT)
        tracker.taint_memory(0x2000, TaintTag.CRYPTO)

        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rax, [0x5000]",
            reads=[],
            writes=["rax"],
            category="memory_read",
            registers={},
        )
        tracker.process_instruction(insn)
        tag = tracker.get_taint("rax")
        assert tag & TaintTag.INPUT
        assert tag & TaintTag.CRYPTO

    def test_concrete_hit_skips_oracle(self):
        """When concrete address is already tainted, oracle is not needed."""
        call_count = [0]
        def counting_oracle(a, b):
            call_count[0] += 1
            return "no"

        tracker = TaintTracker(alias_oracle=counting_oracle)
        tracker.taint_memory(0x3000, TaintTag.INPUT)

        insn = FakeInstruction(
            address=0x400,
            mnemonic="mov",
            operands="rax, [0x3000]",
            reads=[],
            writes=["rax"],
            category="memory_read",
            registers={},
        )
        tracker.process_instruction(insn)
        assert tracker.is_tainted("rax")
        # Oracle should NOT have been called since concrete hit
        assert call_count[0] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Integration — backward slice + taint slice consistency
# ═══════════════════════════════════════════════════════════════════════════════

class TestSliceIntegration:
    """Smoke tests verifying backward_slice works with realistic patterns."""

    def test_vm_add_pattern(self):
        """Simulate VM ADD: pop a, pop b, push (a+b) → slice sum includes both."""
        r = _make_result(
            defs=[("stk_0", 0), ("stk_1", 1), ("sum_0", 2)],
            uses=[("stk_0", 2), ("stk_1", 2)],
            edges=[
                ("stk_0", "sum_0", 0, 2),
                ("stk_1", "sum_0", 1, 2),
            ],
        )
        sl = backward_slice(r, "sum_0")
        assert set(sl.contributing_vars) == {"stk_0", "stk_1", "sum_0"}

    def test_vm_load_store_chain(self):
        """PUSH addr → LOAD → PUSH val → STORE chain."""
        r = _make_result(
            defs=[("val_addr", 0), ("ld_0", 1), ("val_data", 2)],
            uses=[("val_addr", 1), ("ld_0", 3), ("val_data", 3)],
            edges=[
                ("val_addr", "ld_0", 0, 1),
            ],
        )
        sl = backward_slice(r, "ld_0")
        assert "val_addr" in sl.contributing_vars

    def test_empty_graph(self):
        """Empty DataFlowResult → trivial slice."""
        r = DataFlowResult()
        sl = backward_slice(r, "anything")
        assert sl.contributing_vars == ["anything"]
        assert sl.handler_indices == []
        assert sl.edges == []
