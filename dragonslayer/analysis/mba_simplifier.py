"""
MBA Simplification — Mixed Boolean-Arithmetic Expression Reducer
================================================================

VM protectors frequently obfuscate simple operations using mixed
boolean-arithmetic (MBA) identities, e.g.::

    (x & y) + (x | y)  →  x + y
    (x ^ y) + 2*(x & y)  →  x + y
    (x | y) - (x & ~y)  →  y

This module uses z3 to:

1. **Verify** that a candidate simplification is semantically
   equivalent to the original expression (bit-accurate proof).
2. **Rewrite** known MBA patterns into their simpler equivalents.
3. **Canonicalise** arbitrary bit-vector expressions via z3's
   built-in simplifier augmented with custom rewrite rules.

Usage::

    from dragonslayer.analysis.mba_simplifier import simplify_mba, MBAResult

    result = simplify_mba("(x & y) + (x | y)")
    assert result.simplified == "(x + y)"
    assert result.proven

Integration with the devirtualisation pipeline happens in
:mod:`handler_semantics` and :mod:`pseudocode` — after handler
instructions are lifted, constant sub-expressions and MBA-obfuscated
operands are fed through :func:`simplify_expr` before emission.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import z3

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class MBAResult:
    """Outcome of an MBA simplification attempt."""
    original: str
    simplified: str
    proven: bool = False
    rule_name: Optional[str] = None
    bit_width: int = 64


@dataclass
class MBAStats:
    """Aggregate statistics for a batch of simplifications."""
    total: int = 0
    simplified: int = 0
    proven: int = 0
    failed: int = 0
    rules_applied: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rewrite rules — known MBA identities
# ---------------------------------------------------------------------------

def _known_rules(
    x: z3.BitVecRef, y: z3.BitVecRef
) -> List[Tuple[str, z3.BitVecRef, z3.BitVecRef]]:
    """Return ``(rule_name, pattern_expr, simplified_expr)`` triples.

    Each rule asserts that ``pattern_expr`` is semantically identical to
    ``simplified_expr`` for all values of *x* and *y*.
    """
    return [
        # (x & y) + (x | y) == x + y
        ("and_or_to_add", (x & y) + (x | y), x + y),
        # (x ^ y) + 2*(x & y) == x + y
        ("xor_and_to_add", (x ^ y) + 2 * (x & y), x + y),
        # (x | y) - (x ^ y) == x & y
        ("or_xor_to_and", (x | y) - (x ^ y), x & y),
        # (x | y) - y == x & ~y   (masking)
        ("or_sub_to_mask", (x | y) - y, x & ~y),
        # x ^ (x & y) == x & ~y
        ("xor_and_to_mask", x ^ (x & y), x & ~y),
        # (x & ~y) | (~x & y) == x ^ y
        ("masked_or_to_xor", (x & ~y) | (~x & y), x ^ y),
        # (x | y) - (x & y) == x ^ y
        ("or_and_to_xor", (x | y) - (x & y), x ^ y),
        # ~x + y + 1 == y - x   (two's complement subtraction)
        ("complement_sub", ~x + y + 1, y - x),
        # (x + y) - (x ^ y) == 2*(x & y)
        ("add_xor_to_double_and", (x + y) - (x ^ y), 2 * (x & y)),
        # (x + y) - 2*(x & y) == x ^ y
        ("add_and_to_xor", (x + y) - 2 * (x & y), x ^ y),
        # ~(x ^ y) == (x & y) | (~x & ~y)  — XNOR
        ("xnor_expand", ~(x ^ y), (x & y) | (~x & ~y)),
    ]


def _known_rules_3(
    x: z3.BitVecRef, y: z3.BitVecRef, w: z3.BitVecRef,
) -> List[Tuple[str, z3.BitVecRef, z3.BitVecRef]]:
    """MBA rules involving three variables.

    VMProtect commonly generates 3-variable obfuscations such as::

        (x ^ y) + 2*(x & y) - z  →  x + y - z

    We include both standalone 3-var identities and compositions of
    simpler 2-var rules that involve a third additive/subtractive term.
    """
    return [
        # --- Composed: 2-var MBA ± third variable ---
        ("and_or_add_sub3", (x & y) + (x | y) - w, x + y - w),
        ("and_or_add_add3", (x & y) + (x | y) + w, x + y + w),
        ("xor_and_add_sub3", (x ^ y) + 2 * (x & y) - w, x + y - w),
        ("xor_and_add_add3", (x ^ y) + 2 * (x & y) + w, x + y + w),
        # --- x + y + z obfuscation via masks ---
        ("triple_xor_and_carries", (x ^ y ^ w) + 2 * ((x & y) | ((x ^ y) & w)), x + y + w),
    ]


# ---------------------------------------------------------------------------
# Core simplification
# ---------------------------------------------------------------------------

def verify_equivalence(
    expr_a: z3.BitVecRef,
    expr_b: z3.BitVecRef,
    timeout_ms: int = 5000,
) -> bool:
    """Prove that *expr_a* ≡ *expr_b* for all inputs (returns True if proven)."""
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    s.add(expr_a != expr_b)
    return s.check() == z3.unsat


def simplify_expr(
    expr: z3.BitVecRef,
    bit_width: int = 64,
    timeout_ms: int = 5000,
) -> Tuple[z3.BitVecRef, Optional[str]]:
    """Try known rewrite rules, then fall back to z3 ``simplify()``.

    Supports expressions with 2 *or* 3 free variables.  For 3-variable
    expressions the function tries all ordered permutations of the
    expression's free variables against the 3-variable rule templates.

    Returns ``(simplified_expr, rule_name_or_None)``.
    """
    from itertools import permutations as _perms

    x = z3.BitVec("__x", bit_width)
    y = z3.BitVec("__y", bit_width)
    w = z3.BitVec("__w", bit_width)

    # Collect free variables in the expression.
    free_vars = _free_bitvec_vars(expr)

    # --- 2-variable expressions: try every ordered pair ---
    if len(free_vars) >= 2:
        for va, vb in _perms(free_vars, 2):
            for rule_name, pattern, replacement in _known_rules(x, y):
                candidate = z3.substitute(replacement, (x, va), (y, vb))
                pattern_inst = z3.substitute(pattern, (x, va), (y, vb))
                if _z3_eq(z3.simplify(pattern_inst), z3.simplify(expr)):
                    if verify_equivalence(expr, candidate, timeout_ms):
                        return candidate, rule_name

    # --- 3-variable expressions: try every ordered triple ---
    if len(free_vars) >= 3:
        for va, vb, vc in _perms(free_vars, 3):
            for rule_name, pattern, replacement in _known_rules_3(x, y, w):
                candidate = z3.substitute(replacement, (x, va), (y, vb), (w, vc))
                pattern_inst = z3.substitute(pattern, (x, va), (y, vb), (w, vc))
                if _z3_eq(z3.simplify(pattern_inst), z3.simplify(expr)):
                    if verify_equivalence(expr, candidate, timeout_ms):
                        return candidate, rule_name

    # Fallback: z3 built-in simplifier with aggressive tactics.
    simplified = z3.simplify(
        expr,
        som=True,         # sum-of-monomials
        pull_cheap_ite=True,
        local_ctx=True,
    )
    if not _z3_eq(simplified, expr):
        return simplified, "z3_simplify"

    return expr, None


def simplify_mba(
    text: str,
    bit_width: int = 64,
    timeout_ms: int = 5000,
) -> MBAResult:
    """Simplify a textual MBA expression.

    Accepts a C-style expression string with variables ``x``, ``y``, ``z``,
    ``w`` (or any single-letter names found in the text) and returns an
    :class:`MBAResult`.
    """
    # Auto-detect variable names (single-letter identifiers) in the text.
    _VAR_RE = re.compile(r"\b([a-zA-Z])\b")
    var_names = sorted(set(_VAR_RE.findall(text)))
    # Fall back to the standard set if nothing detected.
    if not var_names:
        var_names = ["x", "y"]

    variables = {name: z3.BitVec(name, bit_width) for name in var_names}

    try:
        expr = _parse_expr(text, variables, bit_width)
    except Exception as exc:
        logger.debug("Failed to parse MBA expression %r: %s", text, exc)
        return MBAResult(original=text, simplified=text, proven=False, bit_width=bit_width)

    simplified, rule_name = simplify_expr(expr, bit_width, timeout_ms)

    proven = False
    if rule_name is not None:
        proven = verify_equivalence(expr, simplified, timeout_ms)

    return MBAResult(
        original=text,
        simplified=str(simplified),
        proven=proven,
        rule_name=rule_name,
        bit_width=bit_width,
    )


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def simplify_batch(
    expressions: List[str],
    bit_width: int = 64,
    timeout_ms: int = 5000,
) -> Tuple[List[MBAResult], MBAStats]:
    """Simplify a list of MBA expression strings.

    Returns ``(results, stats)``.
    """
    stats = MBAStats()
    results: List[MBAResult] = []

    for text in expressions:
        stats.total += 1
        r = simplify_mba(text, bit_width, timeout_ms)
        results.append(r)
        if r.rule_name:
            stats.simplified += 1
            stats.rules_applied[r.rule_name] = stats.rules_applied.get(r.rule_name, 0) + 1
        if r.proven:
            stats.proven += 1
        if not r.rule_name and r.original == r.simplified:
            stats.failed += 1

    return results, stats


# ---------------------------------------------------------------------------
# Handler-level integration
# ---------------------------------------------------------------------------

def simplify_handler_operands(
    disassembly_lines: List[str],
    bit_width: int = 64,
    timeout_ms: int = 3000,
) -> List[str]:
    """Best-effort MBA simplification on operand sub-expressions.

    Scans each line for ``0x``-prefixed hex constants combined with
    boolean/arithmetic operators that look like MBA obfuscation and
    attempts to simplify them in-place.

    Returns a new list of (possibly simplified) lines.
    """
    # Match patterns like:  (reg1 & reg2) + (reg1 | reg2)
    # We look for balanced parenthesised sub-expressions with mixed ops.
    _MBA_LIKE = re.compile(
        r"\(([^()]+)\)\s*([+\-])\s*\(([^()]+)\)",
    )

    out: List[str] = []
    for line in disassembly_lines:
        m = _MBA_LIKE.search(line)
        if m:
            full_match = m.group(0)
            r = simplify_mba(full_match, bit_width, timeout_ms)
            if r.rule_name and r.proven:
                line = line.replace(full_match, r.simplified)
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_bitvec_vars(expr: z3.ExprRef) -> List[z3.BitVecRef]:
    """Collect free BitVec variables in *expr*."""
    seen: set[str] = set()
    result: List[z3.BitVecRef] = []

    def _walk(e: z3.ExprRef) -> None:
        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            name = str(e)
            if name not in seen:
                seen.add(name)
                result.append(e)  # type: ignore[arg-type]
        else:
            for child in e.children():
                _walk(child)

    _walk(expr)
    return result


def _z3_eq(a: z3.ExprRef, b: z3.ExprRef) -> bool:
    """Structural equality check via z3's ``eq``."""
    return z3.eq(a, b)


def _parse_expr(
    text: str,
    variables: Dict[str, z3.BitVecRef],
    bit_width: int,
) -> z3.BitVecRef:
    """Parse a simple C-style expression into a z3 BitVec expression.

    Supports: ``+  -  &  |  ^  ~  *  ()`` and integer literals.
    Variable names are looked up in *variables*.
    """
    # Tokenise
    tokens = _tokenize(text)
    pos = [0]  # mutable index

    def _peek() -> Optional[str]:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def _consume(expected: Optional[str] = None) -> str:
        tok = tokens[pos[0]]
        if expected is not None and tok != expected:
            raise ValueError(f"Expected {expected!r}, got {tok!r}")
        pos[0] += 1
        return tok

    def _parse_or() -> z3.BitVecRef:
        left = _parse_xor()
        while _peek() == "|":
            _consume("|")
            left = left | _parse_xor()
        return left

    def _parse_xor() -> z3.BitVecRef:
        left = _parse_and()
        while _peek() == "^":
            _consume("^")
            left = left ^ _parse_and()
        return left

    def _parse_and() -> z3.BitVecRef:
        left = _parse_add()
        while _peek() == "&":
            _consume("&")
            left = left & _parse_add()
        return left

    def _parse_add() -> z3.BitVecRef:
        left = _parse_mul()
        while _peek() in ("+", "-"):
            op = _consume()
            right = _parse_mul()
            left = (left + right) if op == "+" else (left - right)
        return left

    def _parse_mul() -> z3.BitVecRef:
        left = _parse_unary()
        while _peek() == "*":
            _consume("*")
            left = left * _parse_unary()
        return left

    def _parse_unary() -> z3.BitVecRef:
        if _peek() == "~":
            _consume("~")
            return ~_parse_unary()
        if _peek() == "-":
            _consume("-")
            return -_parse_unary()
        return _parse_atom()

    def _parse_atom() -> z3.BitVecRef:
        tok = _peek()
        if tok == "(":
            _consume("(")
            expr = _parse_or()
            _consume(")")
            return expr
        tok = _consume()
        # Integer literal
        if tok.startswith("0x") or tok.startswith("0X"):
            return z3.BitVecVal(int(tok, 16), bit_width)
        if tok.isdigit():
            return z3.BitVecVal(int(tok), bit_width)
        # Variable
        if tok in variables:
            return variables[tok]
        raise ValueError(f"Unknown variable {tok!r}")

    result = _parse_or()
    if pos[0] != len(tokens):
        raise ValueError(f"Unexpected token {tokens[pos[0]]!r}")
    return result


_TOKEN_RE = re.compile(
    r"0[xX][0-9a-fA-F]+|[0-9]+|[a-zA-Z_]\w*|[+\-*&|^~()]"
)


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text)
