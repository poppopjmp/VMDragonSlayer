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
