"""
Tests for B54 — Symbolic Execution Depth.

Covers:
  1. Coverage-guided priority worklist (heapq scheduling)
  2. Symbolic call/return tracking
  3. Veritesting (inline merge for short straight-line branches)
  4. State priority computation
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from dragonslayer.analysis.symbolic_execution.state import SymbolicState

try:
    import z3
    _Z3 = True
except ImportError:
    _Z3 = False


# ═══════════════════════════════════════════════════════════════════════════════
# 1. State priority & ordering
# ═══════════════════════════════════════════════════════════════════════════════

class TestStatePriority:
    """Verify SymbolicState has priority support for heapq."""

    def test_default_priority(self):
        s = SymbolicState()
        assert s.priority == 0.0

    def test_default_seq(self):
        s = SymbolicState()
        assert s._seq == 0

    def test_compute_priority_basic(self):
        s = SymbolicState()
        s.compute_priority()
        # No visited PCs, no depth → priority = 0
        assert s.priority == 0.0

    def test_compute_priority_with_coverage(self):
        s = SymbolicState()
        # Visit 5 unique PCs
        for addr in [0x100, 0x104, 0x108, 0x10C, 0x110]:
            s.visit(addr)
        s.compute_priority()
        # More coverage → lower (better) priority
        assert s.priority < 0

    def test_lt_ordering(self):
        s1 = SymbolicState()
        s2 = SymbolicState()
        s1.priority = -5.0
        s2.priority = -3.0
        s1._seq = 1
        s2._seq = 2
        # s1 has lower priority number → should be "less than" (explored first)
        assert s1 < s2

    def test_lt_tiebreak_by_seq(self):
        s1 = SymbolicState()
        s2 = SymbolicState()
        s1.priority = -5.0
        s2.priority = -5.0
        s1._seq = 1
        s2._seq = 2
        assert s1 < s2

    def test_heapq_compatible(self):
        """States can be used in a heapq."""
        import heapq
        states = []
        for i in range(5):
            s = SymbolicState()
            s.priority = float(-i)
            s._seq = i
            heapq.heappush(states, s)
        # Should pop in priority order (lowest first = largest i)
        popped = heapq.heappop(states)
        assert popped._seq == 4  # -4 is the lowest

    def test_fork_preserves_priority(self):
        s = SymbolicState()
        s.priority = -10.0
        s._seq = 42
        f = s.fork()
        assert f.priority == -10.0
        assert f._seq == 42


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Call stack
# ═══════════════════════════════════════════════════════════════════════════════

class TestCallStack:
    """Verify symbolic call/return tracking."""

    def test_empty_call_stack(self):
        s = SymbolicState()
        assert s.call_stack == []

    def test_push_call(self):
        s = SymbolicState()
        s.push_call(0x401050)
        assert s.call_stack == [0x401050]

    def test_pop_call(self):
        s = SymbolicState()
        s.push_call(0x401050)
        ret = s.pop_call()
        assert ret == 0x401050
        assert s.call_stack == []

    def test_pop_empty_returns_none(self):
        s = SymbolicState()
        assert s.pop_call() is None

    def test_nested_calls(self):
        s = SymbolicState()
        s.push_call(0x1000)
        s.push_call(0x2000)
        s.push_call(0x3000)
        assert s.pop_call() == 0x3000
        assert s.pop_call() == 0x2000
        assert s.pop_call() == 0x1000
        assert s.pop_call() is None

    def test_fork_preserves_call_stack(self):
        s = SymbolicState()
        s.push_call(0x1000)
        s.push_call(0x2000)
        f = s.fork()
        assert f.call_stack == [0x1000, 0x2000]
        # Modifications are independent
        f.push_call(0x3000)
        assert len(s.call_stack) == 2
        assert len(f.call_stack) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Executor — priority worklist
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecutorPriorityWorklist:
    """Verify the executor uses a priority-based worklist."""

    def test_executor_has_state_seq(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        assert hasattr(ex, "_state_seq")
        assert ex._state_seq == 0

    def test_explore_paths_uses_heapq(self):
        """Verify explore_paths references heapq, not deque for the worklist."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        import inspect
        src = inspect.getsource(SymbolicExecutor._explore_paths)
        assert "heapq" in src
        assert "heappop" in src
        assert "heappush" in src

    def test_state_seq_increments(self):
        """After analysis, the seq counter should have incremented."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        # Simple code: nop, ret
        code = bytes([0x90, 0xC3])
        ex.analyze(code, entry_point=0)
        assert ex._state_seq > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Executor — call/return tracking
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecutorCallReturn:
    """Verify CALL/RET handling in the executor."""

    def test_explore_paths_has_call_handling(self):
        """Source code references CALL handling."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        import inspect
        src = inspect.getsource(SymbolicExecutor._explore_paths)
        assert "push_call" in src
        assert "pop_call" in src

    def test_explore_paths_has_return_continuation(self):
        """RET pops call stack before halting."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        import inspect
        src = inspect.getsource(SymbolicExecutor._explore_paths)
        assert "pop_call" in src
        assert "ret_addr" in src


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Veritesting
# ═══════════════════════════════════════════════════════════════════════════════

class TestVeritesting:
    """Verify veritesting infrastructure."""

    def test_try_veritest_exists(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert hasattr(SymbolicExecutor, "_try_veritest")

    def test_trace_straight_line_exists(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert hasattr(SymbolicExecutor, "_trace_straight_line")

    def test_trace_straight_line_empty_map(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        result = ex._trace_straight_line({}, 0x100, 6)
        assert result == []

    def test_trace_straight_line_basic(self):
        """Trace a short straight-line sequence."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import (
            LiftedInstruction, InstructionCategory,
        )
        ex = SymbolicExecutor()

        # Create 3 non-branch instructions
        insns = {}
        for i, addr in enumerate([0x100, 0x102, 0x104]):
            insn = LiftedInstruction(
                address=addr, size=2, mnemonic="nop", operands="",
                category=InstructionCategory.NOP, is_branch=False,
                reads=[], writes=[], raw_bytes=b"\x90\x90",
            )
            insns[addr] = insn

        trace = ex._trace_straight_line(insns, 0x100, 6)
        assert len(trace) == 3

    def test_trace_straight_line_stops_at_branch(self):
        """Trace stops when hitting a branch instruction."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import (
            LiftedInstruction, InstructionCategory,
        )
        ex = SymbolicExecutor()

        insns = {}
        # nop at 0x100
        insns[0x100] = LiftedInstruction(
            address=0x100, size=2, mnemonic="nop", operands="",
            category=InstructionCategory.NOP, is_branch=False,
            reads=[], writes=[], raw_bytes=b"\x90\x90",
        )
        # branch at 0x102
        insns[0x102] = LiftedInstruction(
            address=0x102, size=2, mnemonic="jnz", operands="0x200",
            category=InstructionCategory.BRANCH_COND, is_branch=True,
            branch_target=0x200,
            reads=[], writes=[], raw_bytes=b"\x75\x0a",
        )

        trace = ex._trace_straight_line(insns, 0x100, 6)
        # Should include the nop + the branch
        assert len(trace) == 2

    def test_trace_straight_line_empty_if_starts_with_branch(self):
        """Returns empty if the very first instruction is a branch."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import (
            LiftedInstruction, InstructionCategory,
        )
        ex = SymbolicExecutor()

        insns = {0x100: LiftedInstruction(
            address=0x100, size=2, mnemonic="jnz", operands="0x200",
            category=InstructionCategory.BRANCH_COND, is_branch=True,
            branch_target=0x200,
            reads=[], writes=[], raw_bytes=b"\x75\x0a",
        )}
        trace = ex._trace_straight_line(insns, 0x100, 6)
        assert trace == []

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_try_veritest_no_constraint_returns_false(self):
        """Veritesting bails if no branch constraint."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        s = SymbolicState()
        result = ex._try_veritest(s, MagicMock(), None, {})
        assert result is False

    @pytest.mark.skipif(not _Z3, reason="z3 not available")
    def test_try_veritest_no_merge_returns_false(self):
        """Veritesting bails if branches don't merge."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import (
            LiftedInstruction, InstructionCategory,
        )
        ex = SymbolicExecutor()
        s = SymbolicState()

        insn = LiftedInstruction(
            address=0x100, size=2, mnemonic="jnz", operands="0x200",
            category=InstructionCategory.BRANCH_COND, is_branch=True,
            branch_target=0x200,
            reads=[], writes=[], raw_bytes=b"\x75\x0a",
        )

        # Only fall-through exists, no taken target in map
        insn_map = {
            0x102: LiftedInstruction(
                address=0x102, size=2, mnemonic="nop", operands="",
                category=InstructionCategory.NOP, is_branch=False,
                reads=[], writes=[], raw_bytes=b"\x90\x90",
            )
        }

        cond = z3.Bool("cond")
        result = ex._try_veritest(s, insn, cond, insn_map)
        assert result is False  # taken target 0x200 not in map


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Integration — full analysis still works
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Verify that the executor still runs correctly after B54 changes."""

    def test_simple_analysis(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        # nop, nop, ret
        code = bytes([0x90, 0x90, 0xC3])
        result = ex.analyze(code, entry_point=0)
        assert result.success

    def test_analysis_with_branch(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        # Simple code with a branch pattern
        code = bytes([
            0x48, 0x85, 0xC0,  # test rax, rax
            0x74, 0x02,        # jz +2
            0x90,              # nop (taken fall-through)
            0x90,              # nop (merge point)
            0xC3,              # ret
        ])
        result = ex.analyze(code, entry_point=0)
        assert result.success
        assert result.paths_explored >= 1
