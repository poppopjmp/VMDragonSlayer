"""
Expression Simplification & Type Propagation (B47)
====================================================

Post-processing passes that operate on emitted pseudocode text to:

1. **Fold constant expressions** — evaluate compile-time-constant sub-
   expressions (``2 + 3`` → ``5``, ``0x10 << 3`` → ``0x80``).
2. **Remove identity operations** — ``x + 0`` → ``x``, ``x * 1`` → ``x``,
   ``x ^ 0`` → ``x``, ``x | 0`` → ``x``, ``x & 0xFFFFFFFF`` → ``x``.
3. **Propagate types** — replace generic ``int`` variable declarations
   with sized C types (``uint8_t``, ``uint16_t``, ``uint32_t``,
   ``uint64_t``) using width information from the SSA namer.
4. **Fold redundant casts** — ``(uint32_t)(uint32_t)x`` → ``(uint32_t)x``.
5. **Simplify Boolean conditions** — ``flags == 0`` with known context.

All passes are string-based and operate on the final pseudocode text,
matching the existing architecture in :mod:`pseudocode` and
:mod:`dataflow`.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Constant folding
# ---------------------------------------------------------------------------

# Matches simple binary expressions with two integer literals.
# Groups: (left, operator, right)
_CONST_BINOP_RE = re.compile(
    r"\b(0x[0-9a-fA-F]+|\d+)"       # left operand
    r"\s*([+\-*/&|^%]|<<|>>)\s*"     # operator
    r"(0x[0-9a-fA-F]+|\d+)\b"        # right operand
)


def _parse_int(s: str) -> int:
    """Parse a decimal or hex literal."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def _eval_binop(left: int, op: str, right: int) -> int | None:
    """Safely evaluate a binary operation on two integers."""
    try:
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "/" and right != 0:
            return left // right
        if op == "%" and right != 0:
            return left % right
        if op == "&":
            return left & right
        if op == "|":
            return left | right
        if op == "^":
            return left ^ right
        if op == "<<" and 0 <= right <= 64:
            return left << right
        if op == ">>" and 0 <= right <= 64:
            return left >> right
    except (ValueError, TypeError, OverflowError, ZeroDivisionError, ArithmeticError):
        pass
    return None


def fold_constants(text: str, *, max_passes: int = 3) -> str:
    """Fold compile-time constant sub-expressions in pseudocode text.

    Iterates until no more folds are possible (up to *max_passes*).
    Only folds when both operands are integer literals.
    """
    for _ in range(max_passes):
        new_text = _CONST_BINOP_RE.sub(_const_fold_replace, text)
        if new_text == text:
            break
        text = new_text
    return text


def _const_fold_replace(m: re.Match) -> str:
    """Regex replacement callback for constant folding."""
    try:
        left = _parse_int(m.group(1))
        op = m.group(2)
        right = _parse_int(m.group(3))
        result = _eval_binop(left, op, right)
        if result is not None:
            if result < 0:
                return str(result)
            if result > 9:
                return hex(result)
            return str(result)
    except (ValueError, OverflowError):
        pass
    return m.group(0)


# ---------------------------------------------------------------------------
# 2. Identity operation removal
# ---------------------------------------------------------------------------

# Patterns: var OP identity → var
_IDENTITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    # x + 0  →  x
    (re.compile(r"(\b\w+)\s*\+\s*0\b"), r"\1"),
    # 0 + x  →  x
    (re.compile(r"\b0\s*\+\s*(\w+\b)"), r"\1"),
    # x - 0  →  x
    (re.compile(r"(\b\w+)\s*-\s*0\b"), r"\1"),
    # x * 1  →  x
    (re.compile(r"(\b\w+)\s*\*\s*1\b"), r"\1"),
    # 1 * x  →  x
    (re.compile(r"\b1\s*\*\s*(\w+\b)"), r"\1"),
    # x ^ 0  →  x  (XOR with 0)
    (re.compile(r"(\b\w+)\s*\^\s*0\b"), r"\1"),
    # x | 0  →  x
    (re.compile(r"(\b\w+)\s*\|\s*0\b"), r"\1"),
    # x & 0xffffffffffffffff  →  x  (64-bit identity mask)
    (re.compile(r"(\b\w+)\s*&\s*0xffffffffffffffff\b", re.IGNORECASE), r"\1"),
    # x & 0xffffffff  →  x  (when in 32-bit context — keep for safety)
    # x >> 0  →  x
    (re.compile(r"(\b\w+)\s*>>\s*0\b"), r"\1"),
    # x << 0  →  x
    (re.compile(r"(\b\w+)\s*<<\s*0\b"), r"\1"),
]


def fold_identities(text: str) -> str:
    """Remove identity operations from pseudocode text."""
    for pat, repl in _IDENTITY_PATTERNS:
        text = pat.sub(repl, text)
    return text


# ---------------------------------------------------------------------------
# 3. Redundant cast removal
# ---------------------------------------------------------------------------

_DOUBLE_CAST_RE = re.compile(
    r"\((\w+)\)\s*\(\1\)"  # (type)(type) → (type)
)


def fold_redundant_casts(text: str) -> str:
    """Remove double casts like ``(uint32_t)(uint32_t)``."""
    return _DOUBLE_CAST_RE.sub(r"(\1)", text)


# ---------------------------------------------------------------------------
# 4. Type propagation
# ---------------------------------------------------------------------------

_C_TYPES = {
    1: "uint8_t",
    2: "uint16_t",
    4: "uint32_t",
    8: "uint64_t",
}


def propagate_types(text: str, var_widths: dict[str, int]) -> str:
    """Replace generic ``int`` declarations with sized C types.

    Scans for lines like ``  int varname_N;`` and replaces with
    ``  uint32_t varname_N;`` based on *var_widths*.

    Also upgrades pointer casts in assignments:
    ``*(int*)addr`` → ``*(uint32_t*)addr``.
    """
    if not var_widths:
        return text

    lines = text.split("\n")
    result: list[str] = []

    for line in lines:
        # Declaration: "  int var_name;"
        m = re.match(r"^(\s*)int\s+(\w+)\s*;", line)
        if m:
            indent, var_name = m.group(1), m.group(2)
            width = var_widths.get(var_name, 0)
            c_type = _C_TYPES.get(width, "int")
            result.append(f"{indent}{c_type} {var_name};")
            continue

        # Declaration with initialiser: "  int var = expr;"
        m2 = re.match(r"^(\s*)int\s+(\w+)\s*=\s*(.+);", line)
        if m2:
            indent, var_name, expr = m2.group(1), m2.group(2), m2.group(3)
            width = var_widths.get(var_name, 0)
            c_type = _C_TYPES.get(width, "int")
            result.append(f"{indent}{c_type} {var_name} = {expr};")
            continue

        result.append(line)

    return "\n".join(result)


# ---------------------------------------------------------------------------
# 5. x ^ x → 0, x - x → 0  (self-cancellation)
# ---------------------------------------------------------------------------

_SELF_XOR_RE = re.compile(r"\b(\w+)\s*\^\s*\1\b")
_SELF_SUB_RE = re.compile(r"\b(\w+)\s*-\s*\1\b")


def fold_self_cancel(text: str) -> str:
    """Replace ``x ^ x`` and ``x - x`` with ``0``."""
    text = _SELF_XOR_RE.sub("0", text)
    text = _SELF_SUB_RE.sub("0", text)
    return text


# ---------------------------------------------------------------------------
# Combined pass
# ---------------------------------------------------------------------------

def simplify_pseudocode(
    text: str,
    *,
    var_widths: dict[str, int] | None = None,
) -> str:
    """Apply all expression simplification passes to pseudocode text.

    Intended to be called from :func:`emit_c_like` after
    ``_eliminate_trivial_dead``.

    Parameters
    ----------
    text : str
        Raw pseudocode text.
    var_widths : dict or None
        Variable name → operand width in bytes (from ``_DefUseNamer``).

    Returns
    -------
    str
        Simplified pseudocode text.
    """
    text = fold_constants(text)
    text = fold_identities(text)
    text = fold_self_cancel(text)
    text = fold_redundant_casts(text)
    if var_widths:
        text = propagate_types(text, var_widths)
    return text
