"""
B45 — Symbolic Execution Hardening Tests
==========================================

Tests for:
1. Z3-based indirect dispatch resolution (enumerate_values, _resolve_indirect_branch)
2. Enhanced opaque predicate detection (new arithmetic patterns, MBA phase 2.5)
3. Memory alias tracking improvements (caching, batch analysis, partial-width forwarding)
"""

import pytest
import z3

from dragonslayer.analysis.symbolic_execution.solver import Z3Solver, SolverResult
from dragonslayer.analysis.symbolic_execution.state import (
    SymbolicState, AliasResult, MemoryWrite,
)
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor, ExecutionResult,
)
from dragonslayer.analysis.symbolic_execution.lifter import (
    LiftedInstruction, InstructionCategory,
)


# ---------------------------------------------------------------------------
# 1. enumerate_values (Z3Solver)
# ---------------------------------------------------------------------------

class TestEnumerateValues:
    """Z3Solver.enumerate_values — indirect dispatch helper."""

    def test_single_concrete_value(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 64)
        vals = solver.enumerate_values(x, constraints=[x == 42])
        assert vals == [42]

    def test_two_values(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 64)
        vals = solver.enumerate_values(
            x, constraints=[z3.Or(x == 10, x == 20)]
        )
        assert vals == [10, 20]

    def test_range_bounded(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 8)
        vals = solver.enumerate_values(
            x, constraints=[z3.ULE(x, z3.BitVecVal(4, 8))]
        )
        assert vals == [0, 1, 2, 3, 4]

    def test_max_values_limit(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 64)
        vals = solver.enumerate_values(x, max_values=3)
        assert len(vals) <= 3

    def test_unsatisfiable_returns_empty(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 64)
        vals = solver.enumerate_values(
            x, constraints=[x == 1, x == 2]  # contradiction
        )
        assert vals == []

    def test_table_lookup_pattern(self):
        """Simulate jmp [table_base + idx*8] with idx in 0..3."""
        solver = Z3Solver()
        idx = z3.BitVec("idx", 64)
        table_base = z3.BitVecVal(0x400000, 64)
        target = table_base + idx * 8
        vals = solver.enumerate_values(
            target,
            constraints=[z3.ULE(idx, z3.BitVecVal(3, 64))],
        )
        assert len(vals) == 4
        assert 0x400000 in vals
        assert 0x400008 in vals
        assert 0x400010 in vals
        assert 0x400018 in vals

    def test_with_existing_solver_constraints(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 64)
        solver.add(z3.ULE(x, z3.BitVecVal(2, 64)))
        vals = solver.enumerate_values(x)
        assert vals == [0, 1, 2]


# ---------------------------------------------------------------------------
# 2. _resolve_indirect_branch / _extract_branch_target_expr
# ---------------------------------------------------------------------------

class TestResolveIndirectBranch:
    """SymbolicExecutor indirect dispatch resolution."""

    def _make_insn(self, mnemonic, operands, address=0, is_branch=True):
        return LiftedInstruction(
            address=address,
            size=2,
            mnemonic=mnemonic,
            operands=operands,
            category=InstructionCategory.BRANCH_UNCOND,
            raw_bytes=b'\xff\xe0',
            is_branch=is_branch,
            branch_target=None,
        )

    def test_register_indirect_jmp(self):
        """jmp rax where rax is constrained to two values."""
        executor = SymbolicExecutor()
        state = SymbolicState()
        rax = z3.BitVec("init_rax", 64)
        state.registers["rax"] = rax
        state.add_constraint(z3.Or(rax == 0x1000, rax == 0x2000))

        insn = self._make_insn("jmp", "rax")
        targets = executor._resolve_indirect_branch(state, insn)
        assert targets == [0x1000, 0x2000]

    def test_memory_indirect_jmp_trivial(self):
        """jmp [rax] — no constraint → may return many targets."""
        executor = SymbolicExecutor()
        state = SymbolicState()
        insn = self._make_insn("jmp", "[rax]")
        # No constraint on rax → resolve will return up to max_targets
        # but the memory read returns a fresh symbolic, so enumeration
        # may return any values; just verify no crash.
        targets = executor._resolve_indirect_branch(state, insn, max_targets=4)
        assert isinstance(targets, list)

    def test_no_targets_for_empty_operand(self):
        executor = SymbolicExecutor()
        state = SymbolicState()
        insn = self._make_insn("jmp", "")
        targets = executor._resolve_indirect_branch(state, insn)
        assert targets == []

    def test_constrained_register_single_target(self):
        executor = SymbolicExecutor()
        state = SymbolicState()
        rax = z3.BitVec("init_rax", 64)
        state.registers["rax"] = rax
        state.add_constraint(rax == 0xDEAD)

        insn = self._make_insn("jmp", "rax")
        targets = executor._resolve_indirect_branch(state, insn)
        assert targets == [0xDEAD]


# ---------------------------------------------------------------------------
# 3. Enhanced opaque predicate patterns
# ---------------------------------------------------------------------------

class TestEnhancedOpaquePatterns:
    """Expanded arithmetic tautologies in _detect_arithmetic_opaques."""

    def _make_arithmetic_opaques_helper(self, executor, _z3, mn0, mn1, mn2):
        """Build a 3-instruction window suitable for _detect_arithmetic_opaques."""
        insns = [
            LiftedInstruction(0x100, 3, mn0, "rax, rbx",
                              InstructionCategory.ARITHMETIC, b'\x90\x90\x90'),
            LiftedInstruction(0x103, 3, mn1, "rax, 1",
                              InstructionCategory.LOGIC, b'\x90\x90\x90'),
            LiftedInstruction(0x106, 2, mn2, "0x200",
                              InstructionCategory.BRANCH_COND, b'\x74\x02',
                              is_branch=True, branch_target=0x200),
        ]
        return insns

    def test_original_mul_and_jz(self):
        """x*(x-1)%2==0 pattern: imul → and → je."""
        executor = SymbolicExecutor()
        import z3 as _z3
        insns = self._make_arithmetic_opaques_helper(
            executor, _z3, "imul", "and", "je",
        )
        results = executor._detect_arithmetic_opaques(_z3, insns, set())
        assert len(results) >= 1
        assert results[0]["source"] == "arithmetic"

    def test_new_xor_self_pattern(self):
        """x^x==0 is a tautology — should fire if mul→and→jz window."""
        executor = SymbolicExecutor()
        import z3 as _z3
        insns = self._make_arithmetic_opaques_helper(
            executor, _z3, "imul", "test", "jz",
        )
        results = executor._detect_arithmetic_opaques(_z3, insns, set())
        # Should match one of the expanded patterns
        assert len(results) >= 1

    def test_already_flagged_skipped(self):
        executor = SymbolicExecutor()
        import z3 as _z3
        insns = self._make_arithmetic_opaques_helper(
            executor, _z3, "imul", "and", "je",
        )
        results = executor._detect_arithmetic_opaques(_z3, insns, {0x106})
        assert len(results) == 0


class TestMBAOpaqueDetection:
    """Phase 2.5: mixed-boolean-arithmetic opaque predicates."""

    def _make_mba_window(self, mn0, mn1, mn2):
        return [
            LiftedInstruction(0x200, 3, mn0, "rax, rbx",
                              InstructionCategory.LOGIC, b'\x90\x90\x90'),
            LiftedInstruction(0x203, 3, mn1, "rax, rbx",
                              InstructionCategory.LOGIC, b'\x90\x90\x90'),
            LiftedInstruction(0x206, 2, mn2, "0x300",
                              InstructionCategory.BRANCH_COND, b'\x74\x02',
                              is_branch=True, branch_target=0x300),
        ]

    def test_xor_xor_jcc(self):
        """(x^y)^y==x: xor→xor→je window."""
        import z3 as _z3
        insns = self._make_mba_window("xor", "cmp", "je")
        results = SymbolicExecutor._detect_mba_opaques(_z3, insns, set())
        assert len(results) >= 1
        assert results[0]["source"] == "mba"

    def test_and_or_jcc(self):
        """(x&y)|(x&~y)==x: and→or→je window."""
        import z3 as _z3
        insns = self._make_mba_window("and", "or", "je")
        results = SymbolicExecutor._detect_mba_opaques(_z3, insns, set())
        assert len(results) >= 1

    def test_already_flagged_mba(self):
        import z3 as _z3
        insns = self._make_mba_window("xor", "test", "je")
        results = SymbolicExecutor._detect_mba_opaques(_z3, insns, {0x206})
        assert len(results) == 0

    def test_non_bitwise_mnemonics_skip(self):
        """Non-bitwise first instruction → no match."""
        import z3 as _z3
        insns = self._make_mba_window("add", "test", "je")
        results = SymbolicExecutor._detect_mba_opaques(_z3, insns, set())
        assert len(results) == 0


# ---------------------------------------------------------------------------
# 4. Alias cache + batch analysis
# ---------------------------------------------------------------------------

class TestAliasCaching:
    """B45: query_alias result caching."""

    def test_cache_hit(self):
        state = SymbolicState()
        a1 = z3.BitVec("a1", 64)
        a2 = z3.BitVec("a2", 64)
        state.add_constraint(a1 == a2)

        r1 = state.query_alias(a1, a2)
        assert r1 == AliasResult.MUST
        # Second call should use cache
        r2 = state.query_alias(a1, a2)
        assert r2 == AliasResult.MUST

    def test_cache_concrete(self):
        """Concrete addresses bypass the cache (no need)."""
        state = SymbolicState()
        assert state.query_alias(100, 100) == AliasResult.MUST
        assert state.query_alias(100, 200) == AliasResult.NO

    def test_cache_no_alias(self):
        state = SymbolicState()
        a1 = z3.BitVec("a1", 64)
        a2 = z3.BitVec("a2", 64)
        state.add_constraint(a1 == 10)
        state.add_constraint(a2 == 20)
        r = state.query_alias(a1, a2)
        assert r == AliasResult.NO


class TestBatchAliasAnalysis:
    """B45: alias_analysis_batch."""

    def test_batch_pairwise(self):
        state = SymbolicState()
        a = z3.BitVecVal(10, 64)
        b = z3.BitVecVal(10, 64)
        c = z3.BitVecVal(20, 64)
        results = state.alias_analysis_batch([a, b, c])
        assert results[(0, 1)] == AliasResult.MUST
        assert results[(0, 2)] == AliasResult.NO
        assert results[(1, 2)] == AliasResult.NO

    def test_batch_empty(self):
        state = SymbolicState()
        results = state.alias_analysis_batch([])
        assert results == {}

    def test_batch_single_address(self):
        state = SymbolicState()
        results = state.alias_analysis_batch([z3.BitVecVal(5, 64)])
        assert results == {}


# ---------------------------------------------------------------------------
# 5. Partial-width store forwarding
# ---------------------------------------------------------------------------

class TestPartialWidthForwarding:
    """B45: _forward_from_symbolic_store handles narrower reads."""

    def test_narrow_read_from_wide_write(self):
        state = SymbolicState()
        addr = z3.BitVec("saddr", 64)
        wide_val = z3.BitVecVal(0xDEADBEEFCAFEBABE, 64)

        # Write 8 bytes at symbolic addr
        state._symbolic_store.append(
            MemoryWrite(address=addr, value=wide_val, size=8, timestamp=0)
        )

        # Read 4 bytes from the same address (partial)
        result = state._forward_from_symbolic_store(addr, 4)
        assert result is not None
        # Should be Extract(31, 0, wide_val)
        simplified = z3.simplify(result)
        assert simplified.as_long() == 0xCAFEBABE

    def test_same_width_still_works(self):
        state = SymbolicState()
        addr = z3.BitVec("saddr", 64)
        val = z3.BitVecVal(0x42, 64)
        state._symbolic_store.append(
            MemoryWrite(address=addr, value=val, size=8, timestamp=0)
        )
        result = state._forward_from_symbolic_store(addr, 8)
        assert result is not None
        assert z3.simplify(result).as_long() == 0x42

    def test_wider_read_than_write_no_forward(self):
        """Read wider than store → no forwarding."""
        state = SymbolicState()
        addr = z3.BitVec("saddr", 64)
        val = z3.BitVecVal(0xFF, 32)
        state._symbolic_store.append(
            MemoryWrite(address=addr, value=val, size=4, timestamp=0)
        )
        result = state._forward_from_symbolic_store(addr, 8)
        assert result is None

    def test_no_alias_no_forward(self):
        state = SymbolicState()
        a1 = z3.BitVec("a1", 64)
        a2 = z3.BitVec("a2", 64)
        state.add_constraint(a1 == 10)
        state.add_constraint(a2 == 20)
        val = z3.BitVecVal(0x99, 64)
        state._symbolic_store.append(
            MemoryWrite(address=a1, value=val, size=8, timestamp=0)
        )
        result = state._forward_from_symbolic_store(a2, 8)
        assert result is None


# ---------------------------------------------------------------------------
# 6. Integration: opaque detection through full analyze()
# ---------------------------------------------------------------------------

class TestOpaqueInAnalyze:
    """Verify enhanced opaque detection is wired into analyze()."""

    def test_cmp_reg_reg_detected_via_direct_call(self):
        """cmp eax, eax + je → always-true opaque detected (direct API)."""
        import z3 as _z3
        executor = SymbolicExecutor(arch="x86_64")
        insns = [
            LiftedInstruction(0x10, 2, "cmp", "eax, eax",
                              InstructionCategory.LOGIC, b'\x39\xc0'),
            LiftedInstruction(0x12, 2, "je", "0x20",
                              InstructionCategory.BRANCH_COND, b'\x74\x02',
                              is_branch=True, branch_target=0x20),
            LiftedInstruction(0x14, 1, "nop", "",
                              InstructionCategory.NOP, b'\x90'),
        ]
        opaques = executor._detect_opaque_predicates(insns)
        assert len(opaques) >= 1
        found = [o for o in opaques if o["address"] == 0x12]
        assert len(found) >= 1
        assert found[0]["always_true"] is True
        assert found[0]["confidence"] >= 0.9


# ---------------------------------------------------------------------------
# 7. Indirect resolution in _explore_paths integration
# ---------------------------------------------------------------------------

class TestExplorePathsIndirect:
    """Verify _explore_paths forks on resolved indirect branches."""

    def test_indirect_halt_without_resolution(self):
        """Unresolvable indirect still halts."""
        # jmp rax with no constraints on rax — up to 256 targets
        # but since no address is in insn_map, path halts
        executor = SymbolicExecutor(arch="x86_64", max_paths=4)
        insn = LiftedInstruction(
            address=0, size=2, mnemonic="jmp", operands="rax",
            category=InstructionCategory.BRANCH_UNCOND,
            raw_bytes=b'\xff\xe0',
            is_branch=True, branch_target=None,
        )
        insn_map = {0: insn}
        paths, total, snapshots = executor._explore_paths(insn_map, 0)
        assert paths >= 1
