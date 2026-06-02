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

try:
    import z3
    _Z3_AVAILABLE = True
except ImportError:
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False

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
    rule_name: str | None = None
    bit_width: int = 64
    iterations: int = 1


@dataclass
class MBAStats:
    """Aggregate statistics for a batch of simplifications."""
    total: int = 0
    simplified: int = 0
    proven: int = 0
    failed: int = 0
    rules_applied: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rewrite rules — known MBA identities
# ---------------------------------------------------------------------------

def _known_rules(
    x: z3.BitVecRef, y: z3.BitVecRef
) -> list[tuple[str, z3.BitVecRef, z3.BitVecRef]]:
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

        # --- Phase 10: additional common MBA patterns ---

        # ~(x | y) == ~x & ~y   (De Morgan)
        ("demorgan_nor", ~(x | y), ~x & ~y),
        # ~(x & y) == ~x | ~y   (De Morgan)
        ("demorgan_nand", ~(x & y), ~x | ~y),
        # (x | y) + (x & y) == x + y   (variant of rule 1)
        ("or_and_to_add", (x | y) + (x & y), x + y),
        # x + ~x == -1   (all-ones constant)
        ("add_complement_all_ones", x + ~x, z3.BitVecVal(-1, x.size())),
        # x ^ ~x == -1   (all-ones constant)
        ("xor_complement_all_ones", x ^ ~x, z3.BitVecVal(-1, x.size())),
        # x & ~x == 0   (annihilation)
        ("and_complement_zero", x & ~x, z3.BitVecVal(0, x.size())),
        # x | ~x == -1   (tautology)
        ("or_complement_all_ones", x | ~x, z3.BitVecVal(-1, x.size())),
        # (x & y) ^ (x | y) == x ^ y
        ("and_xor_or_to_xor", (x & y) ^ (x | y), x ^ y),
        # ~x + 1 == -x   (two's complement negation)
        ("complement_to_neg", ~x + 1, -x),
        # x ^ y ^ (x & y) == x | y
        ("xor_xor_and_to_or", (x ^ y) ^ (x & y), x | y),
    ]


def _known_rules_3(
    x: z3.BitVecRef, y: z3.BitVecRef, w: z3.BitVecRef,
) -> list[tuple[str, z3.BitVecRef, z3.BitVecRef]]:
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

        # --- Phase 10: additional 3-variable patterns ---
        # (x | y) - (x ^ y) + w == (x & y) + w
        ("or_xor_to_and_add3", (x | y) - (x ^ y) + w, (x & y) + w),
        # (x | y) - (x ^ y) - w == (x & y) - w
        ("or_xor_to_and_sub3", (x | y) - (x ^ y) - w, (x & y) - w),
        # (x | y) + (x & y) - w == x + y - w   (or_and variant)
        ("or_and_add_sub3", (x | y) + (x & y) - w, x + y - w),
        # (x | y) + (x & y) + w == x + y + w   (or_and variant)
        ("or_and_add_add3", (x | y) + (x & y) + w, x + y + w),
        # (~x + 1) + y + w == y + w - x
        ("neg_add_3", (~x + 1) + y + w, y + w - x),
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


def _ast_size(expr: z3.ExprRef) -> int:
    """Count nodes in a z3 AST — used as a complexity metric."""
    if z3.is_const(expr):
        return 1
    return 1 + sum(_ast_size(c) for c in expr.children())


def simplify_expr(
    expr: z3.BitVecRef,
    bit_width: int = 64,
    timeout_ms: int = 5000,
) -> tuple[z3.BitVecRef, str | None]:
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
                if _z3_eq(
                    z3.simplify(pattern_inst), z3.simplify(expr)
                ) and verify_equivalence(expr, candidate, timeout_ms):
                    return candidate, rule_name

    # --- 3-variable expressions: try every ordered triple ---
    if len(free_vars) >= 3:
        for va, vb, vc in _perms(free_vars, 3):
            for rule_name, pattern, replacement in _known_rules_3(x, y, w):
                candidate = z3.substitute(replacement, (x, va), (y, vb), (w, vc))
                pattern_inst = z3.substitute(pattern, (x, va), (y, vb), (w, vc))
                if _z3_eq(
                    z3.simplify(pattern_inst), z3.simplify(expr)
                ) and verify_equivalence(expr, candidate, timeout_ms):
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


# ---------------------------------------------------------------------------
# Deep canonicalization — linear MBA decomposition & iterative simplify
# ---------------------------------------------------------------------------

# Coefficient → operation lookup tables for 1- and 2-variable linear MBAs.
# Tuple index maps to corner-point bitmask: bit *i* set ⇒ var[i] = −1.
_COEFF_SIGS_1VAR: dict[tuple[int, ...], str] = {
    (0, 0): "zero",
    (0, 1): "x",
    (1, 0): "~x",
    (0, -1): "-x",
    (1, 1): "-1",
}

_COEFF_SIGS_2VAR: dict[tuple[int, ...], str] = {
    (0, 0, 0, 0): "zero",
    (0, 1, 0, 1): "x",
    (0, 0, 1, 1): "y",
    (0, 1, 1, 2): "x + y",
    (0, 1, -1, 0): "x - y",
    (0, -1, 1, 0): "y - x",
    (0, 0, 0, 1): "x & y",
    (0, 1, 1, 1): "x | y",
    (0, 1, 1, 0): "x ^ y",
    (1, 0, 1, 0): "~x",
    (1, 1, 0, 0): "~y",
    (0, -1, 0, -1): "-x",
    (0, 0, -1, -1): "-y",
    (1, 1, 1, 0): "~(x & y)",
    (1, 0, 0, 0): "~(x | y)",
    (1, 0, 0, 1): "~(x ^ y)",
    (1, 1, 1, 1): "-1",
    (0, -1, -1, -2): "-(x + y)",
    (0, 1, 0, 0): "x & ~y",
    (0, 0, 1, 0): "~x & y",
}


def _linear_mba_coefficients(
    expr: z3.BitVecRef,
    free_vars: list[z3.BitVecRef],
    bit_width: int,
) -> list[int] | None:
    """Extract linear MBA coefficients via corner-point evaluation.

    For *n* free variables, evaluates the expression at the 2^n points
    where each variable is either 0 or −1 (all ones).  Each such point
    activates exactly one minterm (value −1), so the coefficient for
    that minterm equals ``−f(point)``.

    Returns a list of 2^n signed coefficients, or ``None`` when the
    expression cannot be evaluated concretely or has > 4 variables.
    A quick non-corner-point probe guards against false positives for
    non-linear expressions (e.g. ``x * y``).
    """
    n = len(free_vars)
    if n == 0 or n > 4:
        return None

    modulus = 1 << bit_width
    half = modulus >> 1
    all_ones = modulus - 1
    coefficients: list[int] = []

    for mask in range(1 << n):
        subs = [
            (free_vars[i],
             z3.BitVecVal(all_ones if (mask >> i) & 1 else 0, bit_width))
            for i in range(n)
        ]
        evaluated = z3.simplify(z3.substitute(expr, *subs))
        if not z3.is_bv_value(evaluated):
            return None
        raw = evaluated.as_long()
        coeff = (-raw) & all_ones
        if coeff >= half:
            coeff -= modulus
        coefficients.append(coeff)

    # --- Probe verification: reject non-linear expressions -----------
    _PROBE_BASE = [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
                   0x3C6EF372FE94F82B]
    for pidx in range(min(2, 1 + n)):
        probe_subs = [
            (free_vars[i],
             z3.BitVecVal(
                 _PROBE_BASE[(pidx + i) % len(_PROBE_BASE)] & all_ones,
                 bit_width))
            for i in range(n)
        ]
        actual = z3.simplify(z3.substitute(expr, *probe_subs))
        if not z3.is_bv_value(actual):
            return None
        expected = 0
        for cmask in range(1 << n):
            c = coefficients[cmask]
            if c == 0:
                continue
            mval = all_ones
            for i in range(n):
                vi = probe_subs[i][1].as_long()
                mval &= (vi if (cmask >> i) & 1 else (~vi) & all_ones)
            expected = (expected + c * mval) & all_ones
        if actual.as_long() != expected:
            return None

    return coefficients


def _reconstruct_from_coefficients(
    coefficients: list[int],
    free_vars: list[z3.BitVecRef],
    bit_width: int,
) -> tuple[z3.BitVecRef, str] | None:
    """Reconstruct a minimal expression from its linear MBA coefficients.

    Uses lookup tables for 1- and 2-variable expressions and falls
    back to a minterm-sum construction for higher arities.
    """
    n = len(free_vars)
    key = tuple(coefficients)

    # --- 1-variable fast path ----------------------------------------
    if n == 1:
        label = _COEFF_SIGS_1VAR.get(key)
        if label is not None:
            (xv,) = free_vars
            _b1: dict[str, z3.BitVecRef] = {
                "zero": z3.BitVecVal(0, bit_width),
                "x": xv, "~x": ~xv, "-x": -xv,
                "-1": z3.BitVecVal(-1, bit_width),
            }
            return _b1[label], f"linear_mba_{label}"

    # --- 2-variable fast path ----------------------------------------
    if n == 2:
        label = _COEFF_SIGS_2VAR.get(key)
        if label is not None:
            x, y = free_vars
            _b2: dict[str, z3.BitVecRef] = {
                "zero": z3.BitVecVal(0, bit_width),
                "x": x, "y": y,
                "x + y": x + y, "x - y": x - y, "y - x": y - x,
                "x & y": x & y, "x | y": x | y, "x ^ y": x ^ y,
                "~x": ~x, "~y": ~y, "-x": -x, "-y": -y,
                "~(x & y)": ~(x & y), "~(x | y)": ~(x | y),
                "~(x ^ y)": ~(x ^ y),
                "-1": z3.BitVecVal(-1, bit_width),
                "-(x + y)": -(x + y),
                "x & ~y": x & ~y, "~x & y": ~x & y,
            }
            return _b2[label], f"linear_mba_{label.replace(' ', '_')}"

    # --- General: build minterm sum ----------------------------------
    return _build_minterm_sum(coefficients, free_vars, bit_width)


def _build_minterm_sum(
    coefficients: list[int],
    free_vars: list[z3.BitVecRef],
    bit_width: int,
) -> tuple[z3.BitVecRef, str] | None:
    """Construct ``Σ cᵢ · mintermᵢ`` and z3-simplify the result."""
    n = len(free_vars)
    terms: list[z3.BitVecRef] = []

    for mask in range(1 << n):
        c = coefficients[mask]
        if c == 0:
            continue
        mt: z3.BitVecRef | None = None
        for i in range(n):
            factor = free_vars[i] if (mask >> i) & 1 else ~free_vars[i]
            mt = factor if mt is None else (mt & factor)
        assert mt is not None
        if c == 1:
            terms.append(mt)
        elif c == -1:
            terms.append(-mt)
        else:
            terms.append(z3.BitVecVal(c, bit_width) * mt)

    if not terms:
        return z3.BitVecVal(0, bit_width), "linear_mba_zero"

    result = terms[0]
    for t in terms[1:]:
        result = result + t
    return z3.simplify(result), "linear_mba_decompose"


def _simplify_children(
    expr: z3.BitVecRef,
    bit_width: int,
    timeout_ms: int,
    _depth: int = 0,
) -> z3.BitVecRef:
    """Bottom-up z3 simplification of each sub-expression.

    Re-builds the AST with simplified children, then applies
    ``z3.simplify`` at each node.  Depth capped at 8.
    """
    if _depth > 8 or z3.is_const(expr):
        return expr
    children = expr.children()
    if not children:
        return expr
    new_children = [
        _simplify_children(c, bit_width, timeout_ms, _depth + 1)
        for c in children
    ]
    try:
        rebuilt = expr.decl()(*new_children)
        return z3.simplify(rebuilt)
    except z3.Z3Exception:
        return expr


def simplify_expr_deep(
    expr: z3.BitVecRef,
    bit_width: int = 64,
    timeout_ms: int = 5000,
    max_rounds: int = 5,
) -> tuple[z3.BitVecRef, str | None, int]:
    """Iterative deep simplification combining all available techniques.

    Each round applies (in order):

    1. **Bottom-up sub-expression simplification** — simplifies children
       before the parent, enabling cascading reductions.
    2. **Pattern-based rewrite rules** — the 31 static MBA templates from
       :func:`simplify_expr`.
    3. **Linear MBA decomposition** — evaluates at corner points to extract
       minterm coefficients, then reconstructs a minimal equivalent.
    4. **z3 aggressive built-in simplify** — ``som=True`` etc.

    Iteration stops at a fixed point or after *max_rounds*.  The
    smallest expression (by AST node count) seen is returned.

    Returns ``(simplified_expr, rule_name_or_None, num_iterations)``.
    """
    best = expr
    best_size = _ast_size(expr)
    rule_name: str | None = None
    iterations = 0

    for _ in range(max_rounds):
        iterations += 1
        prev = best

        # --- 1. bottom-up sub-expression ---
        candidate = _simplify_children(best, bit_width, timeout_ms)
        cand_size = _ast_size(candidate)
        if cand_size < best_size and verify_equivalence(best, candidate, timeout_ms):
            best, best_size = candidate, cand_size
            rule_name = rule_name or "subexpr_simplify"

        # --- 2. static rewrite rules ---
        result, rname = simplify_expr(best, bit_width, timeout_ms)
        if rname is not None:
            r_size = _ast_size(result)
            if r_size <= best_size:
                best, best_size = result, r_size
                rule_name = rname

        # --- 3. linear MBA decomposition ---
        free_vars = _free_bitvec_vars(best)
        if 1 <= len(free_vars) <= 4:
            actual_bw = free_vars[0].size()
            coeffs = _linear_mba_coefficients(best, free_vars, actual_bw)
            if coeffs is not None:
                recon = _reconstruct_from_coefficients(
                    coeffs, free_vars, actual_bw,
                )
                if recon is not None:
                    recon_expr, recon_name = recon
                    recon_size = _ast_size(recon_expr)
                    if recon_size < best_size and verify_equivalence(
                        best, recon_expr, timeout_ms
                    ):
                        best, best_size = recon_expr, recon_size
                        rule_name = recon_name

        # --- 4. z3 aggressive simplify ---
        z3s = z3.simplify(
            best, som=True, pull_cheap_ite=True, local_ctx=True,
        )
        z3s_size = _ast_size(z3s)
        if (
            z3s_size < best_size
            and not _z3_eq(z3s, best)
            and verify_equivalence(best, z3s, timeout_ms)
        ):
            best, best_size = z3s, z3s_size
            rule_name = rule_name or "z3_simplify"

        # Fixed-point?
        if _z3_eq(best, prev):
            break

    return best, rule_name, iterations


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
    except (ValueError, TypeError, KeyError, z3.Z3Exception, SyntaxError) as exc:
        logger.debug("Failed to parse MBA expression %r: %s", text, exc)
        return MBAResult(original=text, simplified=text, proven=False, bit_width=bit_width)

    simplified, rule_name, iters = simplify_expr_deep(expr, bit_width, timeout_ms)

    proven = False
    if rule_name is not None:
        proven = verify_equivalence(expr, simplified, timeout_ms)

    return MBAResult(
        original=text,
        simplified=str(simplified),
        proven=proven,
        rule_name=rule_name,
        bit_width=bit_width,
        iterations=iters,
    )


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def simplify_batch(
    expressions: list[str],
    bit_width: int = 64,
    timeout_ms: int = 5000,
) -> tuple[list[MBAResult], MBAStats]:
    """Simplify a list of MBA expression strings.

    Returns ``(results, stats)``.
    """
    stats = MBAStats()
    results: list[MBAResult] = []

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
    disassembly_lines: list[str],
    bit_width: int = 64,
    timeout_ms: int = 3000,
) -> list[str]:
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

    out: list[str] = []
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

def _free_bitvec_vars(expr: z3.ExprRef) -> list[z3.BitVecRef]:
    """Collect free BitVec variables in *expr*."""
    seen: set[str] = set()
    result: list[z3.BitVecRef] = []

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
    variables: dict[str, z3.BitVecRef],
    bit_width: int,
) -> z3.BitVecRef:
    """Parse a simple C-style expression into a z3 BitVec expression.

    Supports: ``+  -  &  |  ^  ~  *  ()`` and integer literals.
    Variable names are looked up in *variables*.
    """
    # Tokenise
    tokens = _tokenize(text)
    pos = [0]  # mutable index

    def _peek() -> str | None:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def _consume(expected: str | None = None) -> str:
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


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text)
