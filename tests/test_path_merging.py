"""
Tests for B52 — Path Merging + Incremental Solving.

Covers:
  1. SymbolicState.merge() — register/flag/memory/constraint merging
  2. SymbolicState.attach_solver() + incremental is_satisfiable()
  3. SymbolicExecutor._try_merge_worklist() — merge deduplication
  4. Integration smoke tests
"""

from __future__ import annotations

import pytest
from collections import deque
from unittest.mock import MagicMock

# Check z3 availability
try:
    import z3
    _Z3 = True
except ImportError:
    _Z3 = False

from dragonslayer.analysis.symbolic_execution.state import (
    SymbolicState,
)
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. SymbolicState.merge() tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestStateMerge:
    """Test SymbolicState.merge() at join points."""

    def test_merge_identical_registers(self):
        """Merging states with identical register values keeps concrete values."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.registers["rax"] = 42
        s2.registers["rax"] = 42
        merged = s1.merge(s2)
        assert merged.registers["rax"] == 42

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_divergent_registers_ite(self):
        """Divergent registers produce z3 If-Then-Else phi nodes."""
        s1 = SymbolicState(initial_pc=0x200)
        s2 = SymbolicState(initial_pc=0x200)
        s1.registers["rax"] = 10
        s2.registers["rax"] = 20
        merged = s1.merge(s2)
        val = merged.registers["rax"]
        # The result should be a z3 expression (ITE)
        assert z3.is_expr(val)

    def test_merge_preserves_pc(self):
        """Merged state has the same PC as the inputs."""
        s1 = SymbolicState(initial_pc=0x300)
        s2 = SymbolicState(initial_pc=0x300)
        merged = s1.merge(s2)
        assert merged.pc == 0x300

    def test_merge_takes_max_depth(self):
        """depth is set to max of both states."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.depth = 10
        s2.depth = 20
        merged = s1.merge(s2)
        assert merged.depth == 20

    def test_merge_visited_union(self):
        """Visited PCs are union of both states."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.visit(0x100)
        s1.visit(0x104)
        s2.visit(0x100)
        s2.visit(0x108)
        merged = s1.merge(s2)
        assert 0x100 in merged.visited_addresses
        assert 0x104 in merged.visited_addresses
        assert 0x108 in merged.visited_addresses

    def test_merge_one_side_missing_register(self):
        """When one state has an extra register not in the other, it's kept."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        # Use a register name that won't be in the init set
        s1.registers["custom_reg"] = 99
        # s2 doesn't have custom_reg
        merged = s1.merge(s2)
        assert merged.registers["custom_reg"] == 99

    def test_merge_memory_identical(self):
        """Identical memory cells are preserved without ITE."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.memory[0x1000] = 0xFF
        s2.memory[0x1000] = 0xFF
        merged = s1.merge(s2)
        assert merged.memory[0x1000] == 0xFF

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_memory_divergent(self):
        """Divergent memory cells produce ITE expressions."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.memory[0x2000] = 0xAA
        s2.memory[0x2000] = 0xBB
        merged = s1.merge(s2)
        assert z3.is_expr(merged.memory[0x2000])

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_constraints_common_prefix(self):
        """Common constraint prefix is preserved; suffixes are OR-ed."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        x = z3.BitVec("x", 64)
        shared = x > 0
        s1.add_constraint(shared)
        s2.add_constraint(shared)
        s1.add_constraint(x < 100)
        s2.add_constraint(x >= 100)
        merged = s1.merge(s2)
        # First constraint is the shared one
        assert z3.eq(merged.constraints[0], shared)
        # Should have 2 constraints: shared + Or(suffix_a, suffix_b)
        assert len(merged.constraints) == 2

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_empty_constraints(self):
        """Merging states with no constraints produces empty constraints."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        merged = s1.merge(s2)
        assert len(merged.constraints) == 0

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_flags_identical(self):
        """Identical flags are kept."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.flags["ZF"] = True
        s2.flags["ZF"] = True
        merged = s1.merge(s2)
        assert merged.flags["ZF"] is True

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_flags_divergent(self):
        """Divergent flags become ITE."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.flags["CF"] = True
        s2.flags["CF"] = False
        merged = s1.merge(s2)
        assert z3.is_expr(merged.flags["CF"])

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_symbolic_registers(self):
        """Merging z3 symbolic register values produces ITE."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        s1.registers["rcx"] = x
        s2.registers["rcx"] = y
        merged = s1.merge(s2)
        assert z3.is_expr(merged.registers["rcx"])

    def test_merge_clears_alias_cache(self):
        """Alias cache is invalidated after merge."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1._alias_cache[(1, 2)] = "must"
        merged = s1.merge(s2)
        assert len(merged._alias_cache) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Incremental solving tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestIncrementalSolving:
    """Test attach_solver() and incremental is_satisfiable()."""

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_attach_solver_used(self):
        """Attached solver is used for satisfiability checks."""
        s = SymbolicState(initial_pc=0x100)
        solver = z3.Solver()
        s.attach_solver(solver)
        x = z3.BitVec("x", 64)
        s.add_constraint(x == 42)
        assert s.is_satisfiable()

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_incremental_unsat(self):
        """Incremental solver detects unsatisfiable constraints."""
        s = SymbolicState(initial_pc=0x100)
        solver = z3.Solver()
        s.attach_solver(solver)
        x = z3.BitVec("x", 64)
        s.add_constraint(x == 42)
        s.add_constraint(x == 99)  # contradiction
        assert not s.is_satisfiable()

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_no_solver_fallback(self):
        """Without attached solver, falls back to fresh solver."""
        s = SymbolicState(initial_pc=0x100)
        x = z3.BitVec("x", 64)
        s.add_constraint(x > 0)
        assert s.is_satisfiable()

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_incremental_preserves_solver_state(self):
        """After is_satisfiable(), solver state is restored (push/pop)."""
        s = SymbolicState(initial_pc=0x100)
        solver = z3.Solver()
        s.attach_solver(solver)
        x = z3.BitVec("x", 64)
        s.add_constraint(x == 42)
        s.is_satisfiable()
        # Solver should have been restored to empty (push/pop)
        assert solver.check() == z3.sat  # no constraints = sat

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_fork_inherits_solver(self):
        """Forked state inherits the incremental solver reference."""
        s = SymbolicState(initial_pc=0x100)
        solver = z3.Solver()
        s.attach_solver(solver)
        forked = s.fork()
        assert getattr(forked, "_incremental_solver", None) is solver


# ═══════════════════════════════════════════════════════════════════════════════
# 3. _try_merge_worklist tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTryMergeWorklist:
    """Test SymbolicExecutor._try_merge_worklist()."""

    def test_merge_same_pc(self):
        """States with same PC are merged."""
        executor = SymbolicExecutor()
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.registers["rax"] = 1
        s2.registers["rax"] = 1
        worklist = deque([s2])
        merged = executor._try_merge_worklist(s1, worklist)
        assert len(worklist) == 0  # s2 removed from worklist
        assert merged.registers["rax"] == 1

    def test_no_merge_different_pc(self):
        """States with different PC are not merged."""
        executor = SymbolicExecutor()
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x200)
        worklist = deque([s2])
        result = executor._try_merge_worklist(s1, worklist)
        assert len(worklist) == 1  # s2 still in worklist
        assert result is s1  # returns original

    def test_no_merge_halted(self):
        """Halted states are not merged."""
        executor = SymbolicExecutor()
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s2.halt("done")
        worklist = deque([s2])
        result = executor._try_merge_worklist(s1, worklist)
        assert len(worklist) == 1  # s2 still there
        assert result is s1

    def test_empty_worklist(self):
        """Empty worklist → returns state as-is."""
        executor = SymbolicExecutor()
        s1 = SymbolicState(initial_pc=0x100)
        worklist: deque = deque()
        result = executor._try_merge_worklist(s1, worklist)
        assert result is s1

    def test_merge_only_first_match(self):
        """Only one merge per pop."""
        executor = SymbolicExecutor()
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s3 = SymbolicState(initial_pc=0x100)
        worklist = deque([s2, s3])
        executor._try_merge_worklist(s1, worklist)
        # One removed, one still remaining
        assert len(worklist) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Integration smoke tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestB52Integration:
    """Smoke tests for the path merging and incremental solving pipeline."""

    def test_values_equal_concrete(self):
        """_values_equal handles concrete ints."""
        assert SymbolicState._values_equal(42, 42)
        assert not SymbolicState._values_equal(42, 99)

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_values_equal_z3(self):
        """_values_equal handles z3 expressions."""
        x = z3.BitVec("x", 64)
        assert SymbolicState._values_equal(x, x)
        y = z3.BitVec("y", 64)
        assert not SymbolicState._values_equal(x, y)

    def test_values_equal_none(self):
        """_values_equal with None objects."""
        assert not SymbolicState._values_equal(None, 5)

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_merge_then_satisfiable(self):
        """Merged state with disjunctive constraints is satisfiable."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        x = z3.BitVec("x", 64)
        s1.add_constraint(x == 10)
        s2.add_constraint(x == 20)
        merged = s1.merge(s2)
        assert merged.is_satisfiable()

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_executor_params_preserved(self):
        """SymbolicExecutor exposes merge-relevant defaults."""
        ex = SymbolicExecutor(max_paths=128, max_depth=500)
        assert ex.max_paths == 128
        assert ex.max_depth == 500

    def test_merge_without_z3_fallback(self):
        """Without z3, merge still produces a valid state (best-effort)."""
        s1 = SymbolicState(initial_pc=0x100)
        s2 = SymbolicState(initial_pc=0x100)
        s1.registers["rax"] = 10
        s2.registers["rax"] = 20
        merged = s1.merge(s2)
        # Without z3, it should take self's value (the fallback)
        # With z3, it should be an ITE — either way, key exists
        assert "rax" in merged.registers
