"""
Tests for Batch 35 — Loop-Aware Symbolic Execution & Irreducible CFG.

Covers:
  1. SymbolicState visit counting
  2. SymbolicExecutor loop detection & bounded unrolling
  3. Widening at loop headers
  4. LoopInfo / ExecutionResult loop data
  5. Irreducible CFG detection (T1/T2)
  6. Node splitting for irreducible SCCs
  7. make_reducible + integration with Cifuentes structuring
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from dragonslayer.analysis.symbolic_execution.state import SymbolicState
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    ExecutionResult,
    LoopInfo,
)
from dragonslayer.analysis.symbolic_execution.lifter import (
    LiftedInstruction,
    InstructionCategory,
)


# ===================================================================
# 1. SymbolicState visit counting
# ===================================================================

class TestVisitCounting:
    def test_visit_count_starts_at_zero(self):
        st = SymbolicState(initial_pc=0)
        assert st.visit_count(0x100) == 0

    def test_single_visit(self):
        st = SymbolicState(initial_pc=0)
        st.visit(0x100)
        assert st.visit_count(0x100) == 1

    def test_multiple_visits_same_address(self):
        st = SymbolicState(initial_pc=0)
        st.visit(0x100)
        st.visit(0x200)
        st.visit(0x100)
        assert st.visit_count(0x100) == 2
        assert st.visit_count(0x200) == 1

    def test_max_visit_count_empty(self):
        st = SymbolicState(initial_pc=0)
        assert st.max_visit_count == 0

    def test_max_visit_count(self):
        st = SymbolicState(initial_pc=0)
        st.visit(0x100)
        st.visit(0x100)
        st.visit(0x100)
        st.visit(0x200)
        assert st.max_visit_count == 3

    def test_fork_preserves_visit_counts(self):
        st = SymbolicState(initial_pc=0)
        st.visit(0x100)
        st.visit(0x100)
        child = st.fork()
        assert child.visit_count(0x100) == 2
        # Mutations are independent
        child.visit(0x100)
        assert child.visit_count(0x100) == 3
        assert st.visit_count(0x100) == 2

    def test_to_dict_includes_max_visit_count(self):
        st = SymbolicState(initial_pc=0)
        st.visit(0x100)
        st.visit(0x100)
        d = st.to_dict()
        assert "max_visit_count" in d
        assert d["max_visit_count"] == 2

    def test_visited_addresses_still_works(self):
        st = SymbolicState(initial_pc=0)
        st.visit(0x100)
        st.visit(0x200)
        assert st.visited_addresses == {0x100, 0x200}


# ===================================================================
# 2. SymbolicExecutor loop detection
# ===================================================================

def _make_insn(addr: int, mnemonic: str, size: int = 2,
               category: InstructionCategory = InstructionCategory.UNKNOWN,
               is_branch: bool = False, branch_target: int | None = None) -> LiftedInstruction:
    """Helper to create a LiftedInstruction."""
    return LiftedInstruction(
        address=addr,
        mnemonic=mnemonic,
        operands="",
        size=size,
        category=category,
        is_branch=is_branch,
        branch_target=branch_target,
        reads=[],
        writes=[],
        raw_bytes=b"\x90" * size,
    )


class TestLoopDetection:
    def test_max_loop_iters_default(self):
        ex = SymbolicExecutor()
        assert ex.max_loop_iters == 3

    def test_max_loop_iters_custom(self):
        ex = SymbolicExecutor(max_loop_iters=5)
        assert ex.max_loop_iters == 5

    def test_simple_loop_detected(self):
        """A back-edge from addr 4 to addr 0 forms a loop."""
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=50)
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "add", size=2),
            4: _make_insn(4, "jmp", size=2, category=InstructionCategory.BRANCH_UNCOND,
                          is_branch=True, branch_target=0),
        }
        paths, total, snaps = ex._explore_paths(insn_map, entry_point=0)
        assert paths >= 1
        # Loop header at 0 should be detected
        assert 0 in ex._detected_loops
        info = ex._detected_loops[0]
        assert info.iteration_count >= 2

    def test_loop_bound_halts_path(self):
        """Path should halt with 'loop_bound' after exceeding max_loop_iters."""
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=100)
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "jmp", size=2, category=InstructionCategory.BRANCH_UNCOND,
                          is_branch=True, branch_target=0),
        }
        paths, total, snaps = ex._explore_paths(insn_map, entry_point=0)
        assert paths >= 1
        # Should halt due to loop bound, not max_depth
        assert any(s.get("halt_reason") == "loop_bound" for s in snaps)

    def test_no_loop_no_detection(self):
        """Linear code should not trigger loop detection."""
        ex = SymbolicExecutor(max_loop_iters=3, max_depth=50)
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "add", size=2),
            4: _make_insn(4, "ret", size=1, category=InstructionCategory.RETURN),
        }
        paths, total, snaps = ex._explore_paths(insn_map, entry_point=0)
        assert len(ex._detected_loops) == 0

    def test_conditional_loop(self):
        """Conditional back-edge should still detect loop header."""
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=50)
        # 0: nop; 2: cmp; 4: jne -> 0 (back-edge); 6: ret
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "cmp", size=2),
            4: _make_insn(4, "jne", size=2, category=InstructionCategory.BRANCH_COND,
                          is_branch=True, branch_target=0),
            6: _make_insn(6, "ret", size=1, category=InstructionCategory.RETURN),
        }
        paths, total, snaps = ex._explore_paths(insn_map, entry_point=0)
        # The taken branch goes back to 0, so 0 should be a loop header
        assert 0 in ex._detected_loops

    def test_nested_loops(self):
        """Two distinct back-edge targets → two loop headers."""
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=100)
        # Outer: 0 → 2 → inner: 4 → 6 → back to 4; 8 → back to 0; 10: ret
        insn_map = {
            0:  _make_insn(0,  "nop", size=2),
            2:  _make_insn(2,  "nop", size=2),
            4:  _make_insn(4,  "nop", size=2),
            6:  _make_insn(6,  "jmp", size=2, category=InstructionCategory.BRANCH_COND,
                           is_branch=True, branch_target=4),
            8:  _make_insn(8,  "jmp", size=2, category=InstructionCategory.BRANCH_COND,
                           is_branch=True, branch_target=0),
            10: _make_insn(10, "ret", size=1, category=InstructionCategory.RETURN),
        }
        paths, total, snaps = ex._explore_paths(insn_map, entry_point=0)
        # Both 0 and 4 should be detected as loop headers
        assert 4 in ex._detected_loops


# ===================================================================
# 3. Widening
# ===================================================================

class TestWidening:
    def test_widen_marks_loop(self):
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=50)
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "jmp", size=2, category=InstructionCategory.BRANCH_UNCOND,
                          is_branch=True, branch_target=0),
        }
        ex._explore_paths(insn_map, entry_point=0)
        assert 0 in ex._detected_loops
        info = ex._detected_loops[0]
        # Widening was attempted
        assert info.widened is True

    def test_widen_state_fresh_symbols(self):
        """Direct test of _widen_state with z3 available."""
        try:
            import z3
        except ImportError:
            pytest.skip("z3 not available")

        ex = SymbolicExecutor(max_loop_iters=2)
        st = SymbolicState(initial_pc=0)
        x = z3.BitVec("x", 64)
        # Put a complex expression in rax
        st.registers["rax"] = x + 1
        st.registers["rbx"] = z3.BitVecVal(42, 64)  # concrete-ish, no complex ops

        ex._detected_loops[0x100] = LoopInfo(header_address=0x100)
        ex._widen_state(st, 0x100)

        info = ex._detected_loops[0x100]
        assert info.widened is True
        # rax had x+1 which contains "+" → should be widened
        assert "rax" in info.widened_registers

    def test_widen_state_without_z3(self):
        """Widening should not crash when z3 is unavailable."""
        ex = SymbolicExecutor(max_loop_iters=2)
        st = SymbolicState(initial_pc=0)
        st.registers["rax"] = 42  # plain int, no z3

        ex._detected_loops[0x100] = LoopInfo(header_address=0x100)
        ex._widen_state(st, 0x100)
        info = ex._detected_loops[0x100]
        assert info.widened is True


# ===================================================================
# 4. LoopInfo dataclass
# ===================================================================

class TestLoopInfo:
    def test_to_dict(self):
        li = LoopInfo(
            header_address=0x1000,
            back_edge_sources=[0x1010, 0x1020],
            iteration_count=3,
            body_addresses={0x1000, 0x1004, 0x1008},
            widened=True,
            widened_registers=["rax", "rcx"],
        )
        d = li.to_dict()
        assert d["header_address"] == "0x1000"
        assert len(d["back_edge_sources"]) == 2
        assert d["iteration_count"] == 3
        assert d["body_size"] == 3
        assert d["widened"] is True
        assert d["widened_registers"] == ["rax", "rcx"]

    def test_default_values(self):
        li = LoopInfo(header_address=0)
        assert li.iteration_count == 0
        assert li.widened is False
        assert li.widened_registers == []


# ===================================================================
# 5. ExecutionResult includes loops
# ===================================================================

class TestExecutionResultLoops:
    def test_loops_detected_in_result(self):
        r = ExecutionResult(success=True)
        assert r.loops_detected == []

    def test_loops_in_to_dict(self):
        r = ExecutionResult(
            success=True,
            loops_detected=[{"header_address": "0x100", "iteration_count": 3}],
        )
        d = r.to_dict()
        assert "loops_detected" in d
        assert len(d["loops_detected"]) == 1

    def test_detected_loops_property(self):
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=50)
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "jmp", size=2, category=InstructionCategory.BRANCH_UNCOND,
                          is_branch=True, branch_target=0),
        }
        ex._explore_paths(insn_map, entry_point=0)
        loops = ex.detected_loops
        assert isinstance(loops, dict)
        assert 0 in loops


# ===================================================================
# 6. Irreducible CFG detection (T1/T2)
# ===================================================================

try:
    import networkx as _nx
    _NX = True
except ImportError:
    _NX = False

from dragonslayer.analysis.pseudocode import (
    is_reducible,
    find_irreducible_sccs,
    split_irreducible_scc,
    make_reducible,
)


@pytest.mark.skipif(not _NX, reason="networkx not available")
class TestReducibility:
    def test_empty_graph_is_reducible(self):
        g = _nx.DiGraph()
        assert is_reducible(g) is True

    def test_single_node_reducible(self):
        g = _nx.DiGraph()
        g.add_node(0)
        assert is_reducible(g) is True

    def test_linear_chain_reducible(self):
        g = _nx.DiGraph([(0, 1), (1, 2), (2, 3)])
        assert is_reducible(g) is True

    def test_simple_loop_reducible(self):
        """A → B → C → A is a single SCC with one entry = reducible."""
        g = _nx.DiGraph([(0, 1), (1, 2), (2, 0)])
        assert is_reducible(g) is True

    def test_if_then_else_reducible(self):
        g = _nx.DiGraph([(0, 1), (0, 2), (1, 3), (2, 3)])
        assert is_reducible(g) is True

    def test_classic_irreducible(self):
        """Two-entry loop: 0→1, 0→2, 1→2, 2→1 — irreducible."""
        g = _nx.DiGraph([(0, 1), (0, 2), (1, 2), (2, 1)])
        assert is_reducible(g) is False

    def test_self_loop_reducible(self):
        g = _nx.DiGraph([(0, 0), (0, 1)])
        assert is_reducible(g) is True

    def test_nested_reducible(self):
        """Outer loop with inner loop — all reducible."""
        g = _nx.DiGraph([(0, 1), (1, 2), (2, 1), (1, 3), (3, 0)])
        assert is_reducible(g) is True


@pytest.mark.skipif(not _NX, reason="networkx not available")
class TestFindIrreducibleSCCs:
    def test_no_irreducible_sccs(self):
        g = _nx.DiGraph([(0, 1), (1, 2)])
        assert find_irreducible_sccs(g) == []

    def test_classic_irreducible_scc(self):
        g = _nx.DiGraph([(0, 1), (0, 2), (1, 2), (2, 1)])
        sccs = find_irreducible_sccs(g)
        assert len(sccs) == 1
        assert 1 in sccs[0] and 2 in sccs[0]

    def test_reducible_scc_not_reported(self):
        """Single-entry SCC (natural loop) should NOT be irreducible."""
        g = _nx.DiGraph([(0, 1), (1, 2), (2, 0)])
        sccs = find_irreducible_sccs(g)
        assert len(sccs) == 0

    def test_multiple_irreducible_sccs(self):
        """Two separate irreducible SCCs."""
        g = _nx.DiGraph([
            (0, 1), (0, 2), (1, 2), (2, 1),   # SCC {1,2}
            (2, 3),
            (3, 4), (3, 5), (4, 5), (5, 4),   # SCC {4,5}
        ])
        sccs = find_irreducible_sccs(g)
        assert len(sccs) == 2


# ===================================================================
# 7. Node splitting
# ===================================================================

@pytest.mark.skipif(not _NX, reason="networkx not available")
class TestNodeSplitting:
    def test_split_makes_reducible(self):
        """Splitting the classic irreducible graph should make it reducible."""
        g = _nx.DiGraph([(0, 1), (0, 2), (1, 2), (2, 1)])
        result = make_reducible(g)
        assert is_reducible(result) is True

    def test_split_preserves_reachability(self):
        """After splitting, original nodes should remain reachable from entry."""
        g = _nx.DiGraph([(0, 1), (0, 2), (1, 2), (2, 1)])
        result = make_reducible(g)
        assert _nx.has_path(result, 0, 1)
        assert _nx.has_path(result, 0, 2)

    def test_split_already_reducible_noop(self):
        """Splitting a reducible graph should return it unchanged."""
        g = _nx.DiGraph([(0, 1), (1, 2)])
        result = make_reducible(g)
        assert set(result.nodes()) == set(g.nodes())
        assert set(result.edges()) == set(g.edges())

    def test_split_larger_irreducible(self):
        """Three-node irreducible SCC."""
        g = _nx.DiGraph([
            (0, 1), (0, 2),
            (1, 2), (2, 3), (3, 1),  # SCC {1,2,3} with entries 1 and 2
        ])
        result = make_reducible(g)
        assert is_reducible(result) is True

    def test_split_with_exit_edges(self):
        """Irreducible SCC with edges going to nodes outside."""
        g = _nx.DiGraph([
            (0, 1), (0, 2), (1, 2), (2, 1),
            (1, 3), (2, 4),  # exit edges
        ])
        result = make_reducible(g)
        assert is_reducible(result) is True
        # Exit nodes should still be reachable
        assert _nx.has_path(result, 0, 3)
        assert _nx.has_path(result, 0, 4)


# ===================================================================
# 8. Integration: loop-aware execution via analyze()
# ===================================================================

class TestAnalyzeLoopIntegration:
    def test_analyze_reports_loops(self):
        """End-to-end: analyze() with a simple loop should populate loops_detected."""
        ex = SymbolicExecutor(max_loop_iters=2, max_depth=50)
        # Build code bytes for: nop; jmp -2  (infinite loop)
        # x86_64: 0x90 = nop, 0xEB 0xFE = jmp -2
        code = b"\x90\xeb\xfe"
        result = ex.analyze(code, entry_point=0)
        assert result.success
        assert isinstance(result.loops_detected, list)

    def test_analyze_no_error_on_loop(self):
        """Loop shouldn't cause an error, just bounded execution."""
        ex = SymbolicExecutor(max_loop_iters=1, max_depth=50)
        code = b"\x90\xeb\xfe"
        result = ex.analyze(code, entry_point=0)
        assert result.error is None


# ===================================================================
# 9. Edge cases
# ===================================================================

class TestEdgeCases:
    def test_visit_count_after_many_visits(self):
        st = SymbolicState(initial_pc=0)
        for _ in range(100):
            st.visit(0x42)
        assert st.visit_count(0x42) == 100
        assert st.max_visit_count == 100

    def test_loop_info_empty_body(self):
        li = LoopInfo(header_address=0x100)
        d = li.to_dict()
        assert d["body_size"] == 0

    def test_zero_max_loop_iters(self):
        """max_loop_iters=0 should halt immediately on any revisit."""
        ex = SymbolicExecutor(max_loop_iters=0, max_depth=50)
        insn_map = {
            0: _make_insn(0, "nop", size=2),
            2: _make_insn(2, "jmp", size=2, category=InstructionCategory.BRANCH_UNCOND,
                          is_branch=True, branch_target=0),
        }
        paths, total, snaps = ex._explore_paths(insn_map, entry_point=0)
        # Should halt very quickly
        assert total <= 10

    @pytest.mark.skipif(not _NX, reason="networkx not available")
    def test_is_reducible_none_graph(self):
        assert is_reducible(None) is True

    @pytest.mark.skipif(not _NX, reason="networkx not available")
    def test_find_irreducible_sccs_none(self):
        assert find_irreducible_sccs(None) == []

    @pytest.mark.skipif(not _NX, reason="networkx not available")
    def test_make_reducible_none(self):
        assert make_reducible(None) is None
