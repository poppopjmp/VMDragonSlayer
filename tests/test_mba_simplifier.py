"""Tests for the MBA (Mixed Boolean-Arithmetic) simplifier."""

from __future__ import annotations

import z3
import pytest

from dragonslayer.analysis.mba_simplifier import (
    MBAResult,
    MBAStats,
    simplify_mba,
    simplify_expr,
    simplify_batch,
    simplify_handler_operands,
    verify_equivalence,
    _known_rules,
    _known_rules_3,
)


# ---------------------------------------------------------------------------
# verify_equivalence
# ---------------------------------------------------------------------------

class TestVerifyEquivalence:
    def test_identical(self):
        x = z3.BitVec("x", 64)
        assert verify_equivalence(x + 1, x + 1) is True

    def test_different(self):
        x = z3.BitVec("x", 64)
        assert verify_equivalence(x + 1, x + 2) is False

    def test_mba_identity(self):
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        # (x & y) + (x | y) == x + y
        assert verify_equivalence((x & y) + (x | y), x + y) is True


# ---------------------------------------------------------------------------
# Known rules soundness
# ---------------------------------------------------------------------------

class TestKnownRules:
    """Verify every built-in rewrite rule is semantically correct."""

    def test_all_rules_are_proven(self):
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        rules = _known_rules(x, y)
        assert len(rules) >= 10, "Should have at least 10 rewrite rules"
        for name, pattern, replacement in rules:
            ok = verify_equivalence(pattern, replacement, timeout_ms=10000)
            assert ok, f"Rule {name!r} failed equivalence proof"


# ---------------------------------------------------------------------------
# simplify_expr
# ---------------------------------------------------------------------------

class TestSimplifyExpr:
    def test_and_or_to_add(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = (x & y) + (x | y)
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, x + y)

    def test_xor_and_to_add(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = (x ^ y) + 2 * (x & y)
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, x + y)

    def test_no_simplification(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = x + y  # Already simple
        simplified, rule = simplify_expr(expr, 64)
        # May or may not match a rule, but equivalence must hold
        assert verify_equivalence(simplified, x + y)


# ---------------------------------------------------------------------------
# simplify_mba (text interface)
# ---------------------------------------------------------------------------

class TestSimplifyMBA:
    def test_basic_identity(self):
        r = simplify_mba("(x & y) + (x | y)", bit_width=32)
        assert isinstance(r, MBAResult)
        assert r.proven is True
        assert r.rule_name is not None
        assert "+" in r.simplified or "x" in r.simplified

    def test_unparseable(self):
        r = simplify_mba("???invalid!!!", bit_width=64)
        assert r.proven is False
        assert r.simplified == "???invalid!!!"

    def test_constant_fold(self):
        r = simplify_mba("(x ^ x)", bit_width=64)
        # x ^ x == 0 — z3 should simplify to 0
        assert "0" in r.simplified

    def test_bit_width_preserved(self):
        r = simplify_mba("(x & y) + (x | y)", bit_width=32)
        assert r.bit_width == 32


# ---------------------------------------------------------------------------
# simplify_batch
# ---------------------------------------------------------------------------

class TestSimplifyBatch:
    def test_batch(self):
        exprs = [
            "(x & y) + (x | y)",
            "(x ^ y) + 2 * (x & y)",
            "x + y",
        ]
        results, stats = simplify_batch(exprs, bit_width=64)
        assert len(results) == 3
        assert isinstance(stats, MBAStats)
        assert stats.total == 3
        assert stats.simplified >= 2  # At least the two MBA expressions

    def test_empty_batch(self):
        results, stats = simplify_batch([])
        assert results == []
        assert stats.total == 0


# ---------------------------------------------------------------------------
# simplify_handler_operands
# ---------------------------------------------------------------------------

class TestSimplifyHandlerOperands:
    def test_replaces_mba_in_line(self):
        lines = [
            "mov rax, (rcx & rdx) + (rcx | rdx)",
            "push rbx",
        ]
        # The MBA regex looks for (expr1) op (expr2).
        # This won't match real register names against z3 vars,
        # but tests the regex pipeline doesn't crash.
        out = simplify_handler_operands(lines, bit_width=64)
        assert len(out) == 2
        assert "push rbx" in out[1]

    def test_passthrough_no_mba(self):
        lines = ["nop", "ret"]
        out = simplify_handler_operands(lines)
        assert out == lines


# ---------------------------------------------------------------------------
# 3-variable MBA rules
# ---------------------------------------------------------------------------

class TestKnownRules3:
    """Verify every 3-variable rewrite rule is semantically correct."""

    def test_all_3var_rules_proven(self):
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        w = z3.BitVec("w", 64)
        rules = _known_rules_3(x, y, w)
        assert len(rules) >= 4, "Should have at least 4 three-variable rules"
        for name, pattern, replacement in rules:
            ok = verify_equivalence(pattern, replacement, timeout_ms=10000)
            assert ok, f"3-var rule {name!r} failed equivalence proof"


class TestSimplifyExpr3Var:
    """simplify_expr should handle 3-variable MBA expressions."""

    def test_and_or_sub_third(self):
        a = z3.BitVec("a", 64)
        b = z3.BitVec("b", 64)
        c = z3.BitVec("c", 64)
        expr = (a & b) + (a | b) - c  # should simplify to a + b - c
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, a + b - c)

    def test_xor_and_add_third(self):
        a = z3.BitVec("a", 64)
        b = z3.BitVec("b", 64)
        c = z3.BitVec("c", 64)
        expr = (a ^ b) + 2 * (a & b) + c
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, a + b + c)


class TestSimplifyMBA3Var:
    """simplify_mba text interface with 3+ variables."""

    def test_three_var_text(self):
        r = simplify_mba("(x & y) + (x | y) - z", bit_width=64)
        assert isinstance(r, MBAResult)
        # Should detect variables x, y, z and simplify
        assert r.rule_name is not None
        assert r.proven is True


# ---------------------------------------------------------------------------
# Phase 10: Tests for expanded MBA rules
# ---------------------------------------------------------------------------

class TestExpandedRules2Var:
    """Verify new 2-variable rules added in Phase 10."""

    def test_demorgan_nor(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = ~(x | y)
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, ~x & ~y)

    def test_demorgan_nand(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = ~(x & y)
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, ~x | ~y)

    def test_or_and_to_add(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = (x | y) + (x & y)
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, x + y)

    def test_add_complement_all_ones(self):
        x = z3.BitVec("a", 64)
        expr = x + ~x
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, z3.BitVecVal(-1, 64))

    def test_and_complement_zero(self):
        x = z3.BitVec("a", 64)
        expr = x & ~x
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, z3.BitVecVal(0, 64))

    def test_and_xor_or_to_xor(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = (x & y) ^ (x | y)
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, x ^ y)

    def test_complement_to_neg(self):
        x = z3.BitVec("a", 64)
        expr = ~x + 1
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, -x)

    def test_xor_xor_and_to_or(self):
        x = z3.BitVec("a", 64)
        y = z3.BitVec("b", 64)
        expr = (x ^ y) ^ (x & y)
        simplified, rule = simplify_expr(expr, 64)
        assert verify_equivalence(simplified, x | y)

    def test_all_new_2var_rules_proven(self):
        """Every rule in _known_rules must be semantically correct."""
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        rules = _known_rules(x, y)
        assert len(rules) >= 20, f"Expected >= 20 rules, got {len(rules)}"
        for name, pattern, replacement in rules:
            ok = verify_equivalence(pattern, replacement, timeout_ms=10000)
            assert ok, f"Rule {name!r} failed equivalence proof"

    def test_32bit_complement_to_neg(self):
        """Rules work at 32-bit width too."""
        x = z3.BitVec("a", 32)
        expr = ~x + 1
        simplified, rule = simplify_expr(expr, 32)
        assert verify_equivalence(simplified, -x)


class TestExpandedRules3Var:
    """Verify new 3-variable rules added in Phase 10."""

    def test_or_xor_to_and_add3(self):
        a = z3.BitVec("a", 64)
        b = z3.BitVec("b", 64)
        c = z3.BitVec("c", 64)
        expr = (a | b) - (a ^ b) + c
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, (a & b) + c)

    def test_or_and_add_sub3(self):
        a = z3.BitVec("a", 64)
        b = z3.BitVec("b", 64)
        c = z3.BitVec("c", 64)
        expr = (a | b) + (a & b) - c
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, a + b - c)

    def test_neg_add_3(self):
        a = z3.BitVec("a", 64)
        b = z3.BitVec("b", 64)
        c = z3.BitVec("c", 64)
        expr = (~a + 1) + b + c
        simplified, rule = simplify_expr(expr, 64)
        assert rule is not None
        assert verify_equivalence(simplified, b + c - a)

    def test_all_new_3var_rules_proven(self):
        """Every rule in _known_rules_3 must be semantically correct."""
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        w = z3.BitVec("w", 64)
        rules = _known_rules_3(x, y, w)
        assert len(rules) >= 10, f"Expected >= 10 3-var rules, got {len(rules)}"
        for name, pattern, replacement in rules:
            ok = verify_equivalence(pattern, replacement, timeout_ms=10000)
            assert ok, f"3-var rule {name!r} failed equivalence proof"
