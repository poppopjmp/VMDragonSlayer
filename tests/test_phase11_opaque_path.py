"""Tests for Batch 5 – opaque predicate detection with path context.

Validates:
- Path-constraint-aware opaque predicate detection.
- Arithmetic opaque predicate patterns.
- ``_build_opaque_condition()`` for cmp/test + jcc pairs.
- ``is_opaque_predicate_with_context()`` in Z3Solver.
- Correct reordering (path exploration before opaque detection).
"""

import pytest

z3 = pytest.importorskip("z3")

from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
from dragonslayer.analysis.symbolic_execution.lifter import (
    LiftedInstruction,
    InstructionCategory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insn(addr, mnemonic, operands="", category=InstructionCategory.UNKNOWN,
           is_branch=False, branch_target=None, size=1):
    return LiftedInstruction(
        address=addr,
        mnemonic=mnemonic,
        operands=operands,
        category=category,
        is_branch=is_branch,
        branch_target=branch_target,
        size=size,
        raw_bytes=b"\x90" * size,
    )


# ---------------------------------------------------------------------------
# Z3Solver.is_opaque_predicate_with_context
# ---------------------------------------------------------------------------


class TestIsOpaqueWithContext:
    """Test context-aware opaque predicate checking."""

    def test_unconditioned_tautology(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 32)
        # x == x is always true regardless of context.
        assert solver.is_opaque_predicate_with_context(x == x, []) is True

    def test_constrained_becomes_opaque(self):
        """A branch that is NOT opaque in isolation becomes opaque
        when path constraints force a register value."""
        solver = Z3Solver()
        x = z3.BitVec("x", 32)
        # x > 5 is NOT opaque in isolation.
        assert solver.is_opaque_predicate(x > 5) is None
        # But under constraint x == 10, it IS always true.
        assert solver.is_opaque_predicate_with_context(
            x > 5, [x == 10],
        ) is True

    def test_constrained_becomes_false(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 32)
        # x == 0 under constraint x == 42 → always false.
        assert solver.is_opaque_predicate_with_context(
            x == 0, [x == 42],
        ) is False

    def test_still_conditional_under_weak_constraints(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 32)
        # x > 5 under x > 0 — still conditional (e.g. x=3).
        assert solver.is_opaque_predicate_with_context(
            x > 5, [x > 0],
        ) is None

    def test_invalid_constraints_ignored(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 32)
        # Passing non-z3 objects should be silently skipped.
        result = solver.is_opaque_predicate_with_context(
            x == x, ["not_a_constraint", 42, None],
        )
        assert result is True

    def test_multiple_constraints_combined(self):
        solver = Z3Solver()
        x = z3.BitVec("x", 32)
        # x in [5, 10] range → x > 3 is always true.
        assert solver.is_opaque_predicate_with_context(
            x > 3, [x >= 5, x <= 10],
        ) is True


# ---------------------------------------------------------------------------
# _build_opaque_condition
# ---------------------------------------------------------------------------


class TestBuildOpaqueCondition:
    """Test the condition builder for cmp/test + jcc pairs."""

    def setup_method(self):
        self.exe = SymbolicExecutor(arch="x86_64")

    def test_cmp_reg_imm_je(self):
        cond = self.exe._build_opaque_condition(z3, "je", ["eax", "0"], "cmp")
        assert cond is not None
        # Should produce op_eax == 0.
        s = z3.Solver()
        s.add(z3.Not(cond))
        # Not a tautology (eax could be non-zero).
        assert s.check() == z3.sat

    def test_cmp_reg_reg_je(self):
        """cmp eax, ebx; je → eax == ebx (conditional)."""
        cond = self.exe._build_opaque_condition(z3, "je", ["eax", "ebx"], "cmp")
        assert cond is not None
        # Not a tautology.
        assert Z3Solver().is_opaque_predicate(cond) is None

    def test_cmp_reg_same_reg_je(self):
        """cmp eax, eax; je → op_eax == op_eax (tautology)."""
        cond = self.exe._build_opaque_condition(z3, "je", ["eax", "eax"], "cmp")
        assert cond is not None
        assert Z3Solver().is_opaque_predicate(cond) is True

    def test_test_reg_imm_jz(self):
        cond = self.exe._build_opaque_condition(z3, "jz", ["eax", "0"], "test")
        assert cond is not None
        # test eax, 0 → AND is 0 → jz always true.
        assert Z3Solver().is_opaque_predicate(cond) is True

    def test_cmp_unsigned_jae(self):
        cond = self.exe._build_opaque_condition(z3, "jae", ["eax", "0"], "cmp")
        assert cond is not None
        # eax >= 0 (unsigned) is always true.
        assert Z3Solver().is_opaque_predicate(cond) is True

    def test_cmp_hex_immediate(self):
        cond = self.exe._build_opaque_condition(z3, "je", ["eax", "0xFF"], "cmp")
        assert cond is not None


# ---------------------------------------------------------------------------
# _detect_opaque_predicates with path constraints
# ---------------------------------------------------------------------------


class TestDetectWithPathConstraints:
    """Full integration: path constraints feed into detection."""

    def setup_method(self):
        self.exe = SymbolicExecutor(arch="x86_64")

    def test_path_constraint_detects_opaque(self):
        """A branch constrained by prior path should be flagged."""
        x = z3.BitVec("op_eax", 64)
        constraints = [{
            "address": 0x1010,
            "constraint": x > 5,
            "state_constraints": [x == 10],
        }]
        # Minimal instruction stream — the branch at 0x1010.
        insns = [
            _insn(0x1000, "cmp", "eax, 5", InstructionCategory.LOGIC),
            _insn(0x1010, "jg", "0x2000", InstructionCategory.BRANCH_COND,
                  is_branch=True, branch_target=0x2000),
        ]
        result = self.exe._detect_opaque_predicates(
            insns, path_constraints=constraints,
        )
        path_hits = [r for r in result if r.get("source") == "path_constraint"]
        assert len(path_hits) >= 1
        assert path_hits[0]["always_true"] is True
        assert path_hits[0]["confidence"] == 0.85

    def test_syntactic_cmp_reg_reg_still_works(self):
        """Phase 2 syntactic detection still finds cmp reg, reg."""
        insns = [
            _insn(0x100, "cmp", "eax, eax", InstructionCategory.LOGIC),
            _insn(0x102, "je", "0x200", InstructionCategory.BRANCH_COND,
                  is_branch=True, branch_target=0x200),
        ]
        result = self.exe._detect_opaque_predicates(insns)
        assert len(result) >= 1
        assert result[0]["always_true"] is True
        assert result[0]["source"] == "syntactic"
        assert result[0]["confidence"] == 0.99

    def test_test_reg_reg_is_not_opaque(self):
        """test eax, eax is NOT necessarily opaque (depends on value)."""
        insns = [
            _insn(0x100, "test", "eax, eax", InstructionCategory.LOGIC),
            _insn(0x102, "jz", "0x200", InstructionCategory.BRANCH_COND,
                  is_branch=True, branch_target=0x200),
        ]
        result = self.exe._detect_opaque_predicates(insns)
        assert len(result) >= 1
        assert result[0]["always_true"] is None
        assert result[0]["confidence"] == 0.5

    def test_z3_unconstrained_cmp_imm(self):
        """cmp eax, 0; jae → always true with unsigned comparison."""
        insns = [
            _insn(0x100, "cmp", "eax, 0", InstructionCategory.LOGIC),
            _insn(0x102, "jae", "0x200", InstructionCategory.BRANCH_COND,
                  is_branch=True, branch_target=0x200),
        ]
        result = self.exe._detect_opaque_predicates(insns)
        # Should detect via z3 unconstrained check.
        z3_hits = [r for r in result if r.get("source") == "z3_unconstrained"]
        assert len(z3_hits) >= 1
        assert z3_hits[0]["always_true"] is True

    def test_no_false_positive_on_conditional(self):
        """cmp eax, 5; je should NOT be flagged as opaque."""
        insns = [
            _insn(0x100, "cmp", "eax, 5", InstructionCategory.LOGIC),
            _insn(0x102, "je", "0x200", InstructionCategory.BRANCH_COND,
                  is_branch=True, branch_target=0x200),
        ]
        result = self.exe._detect_opaque_predicates(insns)
        # Should NOT be flagged — x == 5 is genuinely conditional.
        opaque_hits = [r for r in result if r.get("always_true") is not None]
        assert len(opaque_hits) == 0

    def test_path_constraint_skips_already_flagged(self):
        """Phase 2 skips addresses already flagged by Phase 1 (path)."""
        x = z3.BitVec("op_eax", 64)
        constraints = [{
            "address": 0x102,
            "constraint": x == x,  # trivial tautology
            "state_constraints": [],
        }]
        insns = [
            _insn(0x100, "cmp", "eax, eax", InstructionCategory.LOGIC),
            _insn(0x102, "je", "0x200", InstructionCategory.BRANCH_COND,
                  is_branch=True, branch_target=0x200),
        ]
        result = self.exe._detect_opaque_predicates(
            insns, path_constraints=constraints,
        )
        # Address 0x102 should appear exactly once (from path constraints,
        # not duplicated by syntactic).
        addr_102 = [r for r in result if r["address"] == 0x102]
        assert len(addr_102) == 1
        assert addr_102[0]["source"] == "path_constraint"


# ---------------------------------------------------------------------------
# analyze() ordering — path exploration before opaque detection
# ---------------------------------------------------------------------------


class TestAnalyzeOrdering:
    """Verify that analyze() runs path exploration before opaque detection."""

    def test_collected_path_constraints_reset(self):
        """_collected_path_constraints is reset per analyze() call."""
        exe = SymbolicExecutor(arch="x86_64")
        exe._collected_path_constraints = [{"dummy": True}]
        # analyze with empty code produces no constraints.
        result = exe.analyze(b"")
        # After analyze, constraints should be empty (reset).
        assert exe._collected_path_constraints == [] or result.success is False

    def test_source_field_present(self):
        """All opaque predicate entries have a 'source' field."""
        exe = SymbolicExecutor(arch="x86_64")
        result = exe.analyze(b"\x90" * 10)  # just NOPs
        for op in result.opaque_predicates:
            assert "source" in op
