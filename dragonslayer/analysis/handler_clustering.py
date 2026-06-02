"""
Handler Semantic Equivalence Clustering
========================================

Clusters VM handlers that perform the **same logical operation** regardless
of register allocation, instruction ordering, or junk-code insertion.

VMProtect generates many-to-one opcode → operation mappings: a single
logical operation (e.g. "add two 64-bit values from the VM stack") may
have 5–15 different native implementations.  This module groups those
variants into *semantic clusters*, each representing a canonical
VM operation.

Pipeline position::

    handler_extraction  →  handler_semantics  →  **handler_clustering**
    (struct dedup)          (classify each)       (group equivalents)

Usage::

    from dragonslayer.analysis.handler_clustering import (
        cluster_handlers_by_semantics,
        normalize_symbolic_effect,
        ClusteringResult,
        SemanticCluster,
    )

    result = cluster_handlers_by_semantics(semantics, summaries)
    for cluster in result.clusters:
        print(f"{cluster.operation}  ({len(cluster.members)} variants)")
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

# Canonical VM operation labels (re-exported for convenience).
# These match handler_semantics.VMOperation string constants.
_OP_ADD = "vm_add"
_OP_SUB = "vm_sub"
_OP_MUL = "vm_mul"
_OP_DIV = "vm_div"
_OP_AND = "vm_and"
_OP_OR = "vm_or"
_OP_XOR = "vm_xor"
_OP_NOT = "vm_not"
_OP_NEG = "vm_neg"
_OP_SHL = "vm_shl"
_OP_SHR = "vm_shr"
_OP_ROL = "vm_rol"
_OP_ROR = "vm_ror"
_OP_LOAD = "vm_load"
_OP_STORE = "vm_store"
_OP_PUSH = "vm_push"
_OP_POP = "vm_pop"
_OP_CMP = "vm_cmp"
_OP_TEST = "vm_test"
_OP_JMP = "vm_jmp"
_OP_JCC = "vm_jcc"
_OP_CALL = "vm_call"
_OP_RET = "vm_ret"
_OP_NOP = "vm_nop"
_OP_UNKNOWN = "vm_unknown"

# Commutative operations – operand order doesn't affect behaviour.
_COMMUTATIVE: frozenset[str] = frozenset({
    _OP_ADD, _OP_MUL, _OP_AND, _OP_OR, _OP_XOR, _OP_CMP, _OP_TEST,
})

# Regex to recognise ``init_<regname>`` symbolic names emitted by the
# symbolic executor.
_INIT_RE = re.compile(r"\binit_(\w+)\b")

# All x86 GP register names (64/32/16/8) used to detect register
# references in symbolic expressions.
_ALL_REGS: frozenset[str] = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
    "al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl",
    "ah", "bh", "ch", "dh",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
})

# Mapping from sub-register to canonical 64-bit name for width detection.
_REG_WIDTH: dict[str, int] = {}
for _r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
    _REG_WIDTH[_r] = 8
for _r in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
           "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"):
    _REG_WIDTH[_r] = 4
for _r in ("ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
           "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"):
    _REG_WIDTH[_r] = 2
for _r in ("al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl",
           "ah", "bh", "ch", "dh",
           "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"):
    _REG_WIDTH[_r] = 1


# ═══════════════════════════════════════════════════════════════════════════
# Symbolic-expression normalization patterns
# ═══════════════════════════════════════════════════════════════════════════

# Each tuple: (regex over *slot*-replaced expression, VMOperation, confidence)
_NORM_PATTERNS: list[tuple[str, str, float]] = [
    # Arithmetic - binary
    (r"^slot_\d+\s*\+\s*slot_\d+$", _OP_ADD, 0.95),
    (r"slot_\d+\s*\+\s*slot_\d+", _OP_ADD, 0.90),
    (r"^slot_\d+\s*-\s*slot_\d+$", _OP_SUB, 0.95),
    (r"slot_\d+\s*-\s*slot_\d+", _OP_SUB, 0.88),
    (r"^slot_\d+\s*\*\s*slot_\d+$", _OP_MUL, 0.93),
    (r"slot_\d+\s*\*\s*slot_\d+", _OP_MUL, 0.88),
    (r"UDiv|udiv|SDiv|sdiv", _OP_DIV, 0.90),
    # Bitwise - binary
    (r"^slot_\d+\s*&\s*slot_\d+$", _OP_AND, 0.95),
    (r"slot_\d+\s*&\s*slot_\d+", _OP_AND, 0.90),
    (r"^slot_\d+\s*\|\s*slot_\d+$", _OP_OR, 0.95),
    (r"slot_\d+\s*\|\s*slot_\d+", _OP_OR, 0.90),
    (r"^slot_\d+\s*\^\s*slot_\d+$", _OP_XOR, 0.95),
    (r"Xor\(slot_\d+", _OP_XOR, 0.92),
    (r"slot_\d+\s*\^\s*slot_\d+", _OP_XOR, 0.88),
    # Unary
    (r"^~slot_\d+$", _OP_NOT, 0.95),
    (r"~slot_\d+", _OP_NOT, 0.88),
    (r"^-slot_\d+$", _OP_NEG, 0.95),
    (r"-slot_\d+", _OP_NEG, 0.85),
    # Shifts
    (r"slot_\d+\s*<<\s*slot_\d+", _OP_SHL, 0.93),
    (r"slot_\d+\s*<<\s*\d+", _OP_SHL, 0.90),
    (r"LShR\(slot_\d+", _OP_SHR, 0.93),
    (r"slot_\d+\s*>>\s*", _OP_SHR, 0.88),
    (r"RotateLeft\(slot_\d+", _OP_ROL, 0.93),
    (r"RotateRight\(slot_\d+", _OP_ROR, 0.93),
    # Memory
    (r"mem_", _OP_LOAD, 0.80),
]


# ═══════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NormalizedEffect:
    """Register-agnostic canonical form of a handler's effect.

    Concrete register names (``init_rax``, ``init_rbx``, …) are replaced
    by positional slots (``slot_0``, ``slot_1``, …) ordered by first
    appearance in the symbolic expression.  Commutative operands are
    sorted so that ``slot_0 + slot_1`` and ``slot_1 + slot_0`` produce
    the same canonical string.
    """
    operation: str = _OP_UNKNOWN
    operand_width: int = 0          # bytes: 1, 2, 4, 8
    input_slots: int = 0            # distinct input values consumed
    output_slots: int = 0           # distinct output values produced
    canonical_expression: str = ""  # e.g. "slot_0 + slot_1"
    side_effects: frozenset[str] = field(default_factory=frozenset)
    confidence: float = 0.0
    # Bookkeeping: slot → original register name
    slot_map: dict[int, str] = field(default_factory=dict)

    def signature(self) -> str:
        """Return a hashable clustering key."""
        return f"{self.operation}:{self.operand_width}:{self.canonical_expression}"


@dataclass
class SemanticCluster:
    """A group of handler addresses that implement the same VM operation."""
    cluster_id: int
    operation: str
    operand_width: int
    members: list[int] = field(default_factory=list)       # handler addresses
    normalized_effect: NormalizedEffect | None = None
    confidence: float = 0.0
    # per-member operand binding: handler_addr → {slot_idx: native_register}
    operand_bindings: dict[int, dict[int, str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the semantic cluster to a JSON-compatible dict."""
        return {
            "cluster_id": self.cluster_id,
            "operation": self.operation,
            "operand_width": self.operand_width,
            "member_count": len(self.members),
            "members": [hex(a) for a in self.members],
            "confidence": round(self.confidence, 3),
            "canonical_expression": (
                self.normalized_effect.canonical_expression
                if self.normalized_effect else ""
            ),
        }


@dataclass
class ClusteringResult:
    """Output of :func:`cluster_handlers_by_semantics`."""
    clusters: list[SemanticCluster] = field(default_factory=list)
    unclustered: list[int] = field(default_factory=list)  # handler addrs
    operation_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the clustering result to a JSON-compatible dict."""
        return {
            "cluster_count": len(self.clusters),
            "unclustered_count": len(self.unclustered),
            "operation_counts": self.operation_counts,
            "clusters": [c.to_dict() for c in self.clusters],
        }

    def find_cluster(self, handler_address: int) -> SemanticCluster | None:
        """Return the cluster containing *handler_address*, or ``None``."""
        for c in self.clusters:
            if handler_address in c.members:
                return c
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Core normalization
# ═══════════════════════════════════════════════════════════════════════════

def _extract_summary_fields(summary: Any) -> dict[str, Any] | None:
    """Accept both dataclass and dict forms of HandlerSymbolicSummary."""
    if hasattr(summary, "to_dict"):
        return summary.to_dict()
    if isinstance(summary, dict):
        return summary
    return None


def _detect_width_from_regs(reg_names: list[str]) -> int:
    """Infer operand width from the concrete register names used."""
    widths: list[int] = []
    for r in reg_names:
        w = _REG_WIDTH.get(r.lower(), 0)
        if w:
            widths.append(w)
    if not widths:
        return 0
    # Use the most common non-zero width
    c = Counter(widths)
    return c.most_common(1)[0][0]


def normalize_symbolic_effect(
    summary: Any,
    *,
    handler_address: int = 0,
) -> NormalizedEffect:
    """Normalize a :class:`HandlerSymbolicSummary` into a register-agnostic
    canonical effect.

    The algorithm:

    1.  Identify *interesting* outputs — registers whose final symbolic
        value differs from their initial symbol.
    2.  Collect all ``init_<reg>`` references from the interesting
        expressions and assign them positional ``slot_N`` indices in
        order of first appearance (left-to-right, top-to-bottom).
    3.  Replace every ``init_<reg>`` with its slot identifier.
    4.  For commutative operations, sort the binary operands so that
        the lower-numbered slot appears first.
    5.  Pattern-match the canonical expression to assign the VM operation
        and confidence.

    Args:
        summary: A ``HandlerSymbolicSummary`` (dataclass or dict).
        handler_address: Address of the handler (for diagnostics).

    Returns:
        A :class:`NormalizedEffect` with all fields populated.
    """
    s = _extract_summary_fields(summary)
    if s is None or s.get("error"):
        return NormalizedEffect()

    # Prefer simplified (MBA-reduced) expressions.
    regs = s.get("simplified_registers") or s.get("final_registers") or {}
    input_syms = s.get("input_symbols") or {}
    mem_writes = s.get("memory_writes") or []

    # 1. Find interesting (non-identity) outputs.
    interesting: dict[str, str] = {}
    for rname, expr_str in regs.items():
        init_sym = input_syms.get(rname, "")
        if expr_str and expr_str != init_sym and expr_str != "0":
            interesting[rname] = expr_str

    if not interesting and not mem_writes:
        return NormalizedEffect()

    # 2. Collect init_<reg> references in appearance order.
    combined = " ; ".join(interesting.values())
    # Also include memory write expressions
    for mw in mem_writes:
        combined += f" ; {mw.get('address', '')} ; {mw.get('value', '')}"

    init_refs = _INIT_RE.findall(combined)
    # Deduplicate while preserving order
    seen: set[str] = set()
    ordered_regs: list[str] = []
    for r in init_refs:
        if r not in seen:
            seen.add(r)
            ordered_regs.append(r)

    # 3. Build slot mapping: register_name → slot_N
    slot_map: dict[str, int] = {}
    reverse_map: dict[int, str] = {}
    for idx, r in enumerate(ordered_regs):
        slot_map[r] = idx
        reverse_map[idx] = r

    # Replace init_<reg> with slot_N
    def _replace_inits(expr: str) -> str:
        def _sub(m: re.Match) -> str:
            rn = m.group(1)
            if rn in slot_map:
                return f"slot_{slot_map[rn]}"
            return m.group(0)
        return _INIT_RE.sub(_sub, expr)

    canonical_parts: list[str] = []
    for expr_str in interesting.values():
        canonical_parts.append(_replace_inits(expr_str))

    canonical = " ; ".join(canonical_parts)

    # Memory write effects
    has_mem_write = len(mem_writes) > 0
    has_stack_write = any(
        re.search(r"init_[re]?sp", str(mw.get("address", "")), re.IGNORECASE)
        for mw in mem_writes
    )

    side_effects: set[str] = set()
    if has_mem_write:
        side_effects.add("mem_write")
    if has_stack_write:
        side_effects.add("stack_write")

    # 4. Detect operation from canonical expression.
    operation = _OP_UNKNOWN
    confidence = 0.0

    # Check for push/store via memory writes first
    if has_stack_write and not canonical_parts:
        operation = _OP_PUSH
        confidence = 0.85
    elif has_mem_write and not has_stack_write and not canonical_parts:
        operation = _OP_STORE
        confidence = 0.85
    else:
        # Pattern-match against _NORM_PATTERNS
        for pattern, op, conf in _NORM_PATTERNS:
            if re.search(pattern, canonical) and conf > confidence:
                operation = op
                confidence = conf

    # 5. Commutative normalization
    if operation in _COMMUTATIVE:
        canonical = _normalize_commutative(canonical)

    # Width detection
    width = _detect_width_from_regs(ordered_regs)
    if width == 0:
        # Fall back: check output register names
        width = _detect_width_from_regs(list(interesting.keys()))

    return NormalizedEffect(
        operation=operation,
        operand_width=width,
        input_slots=len(ordered_regs),
        output_slots=len(interesting),
        canonical_expression=canonical,
        side_effects=frozenset(side_effects),
        confidence=confidence,
        slot_map=reverse_map,
    )


def _normalize_commutative(expr: str) -> str:
    """For commutative binary operations, sort operands lexically so that
    ``slot_1 + slot_0`` becomes ``slot_0 + slot_1``.

    Handles multiple sub-expressions separated by `` ; ``.
    """
    parts = expr.split(" ; ")
    normalized: list[str] = []
    for part in parts:
        part = part.strip()
        # Match binary ops: <lhs> <op> <rhs>
        m = re.match(
            r"^(slot_\d+(?:\S*)?)\s*([+*&|^])\s*(slot_\d+(?:\S*)?)$",
            part,
        )
        if m:
            lhs, op, rhs = m.group(1), m.group(2), m.group(3)
            if lhs > rhs:
                lhs, rhs = rhs, lhs
            normalized.append(f"{lhs} {op} {rhs}")
        else:
            # Try z3-style Xor(a, b) → Xor(min, max)
            m2 = re.match(
                r"^(Xor|And|Or)\((slot_\d+),\s*(slot_\d+)\)$",
                part,
            )
            if m2:
                fn, a, b = m2.group(1), m2.group(2), m2.group(3)
                if a > b:
                    a, b = b, a
                normalized.append(f"{fn}({a}, {b})")
            else:
                normalized.append(part)
    return " ; ".join(normalized)


# ═══════════════════════════════════════════════════════════════════════════
# Equivalence comparison
# ═══════════════════════════════════════════════════════════════════════════

def are_semantically_equivalent(
    a: NormalizedEffect,
    b: NormalizedEffect,
    *,
    strict_width: bool = True,
) -> tuple[bool, float]:
    """Decide whether two normalized effects represent the same VM operation.

    Returns ``(is_equivalent, confidence)`` where confidence is the
    minimum of the two individual confidences (conservative).

    Args:
        a, b: Normalized effects to compare.
        strict_width: If True, require matching operand width.
    """
    if a.operation == _OP_UNKNOWN or b.operation == _OP_UNKNOWN:
        return False, 0.0

    if a.operation != b.operation:
        return False, 0.0

    if strict_width and a.operand_width != b.operand_width:
        # Width mismatch → different operations (vm_add_32 ≠ vm_add_64)
        return False, 0.0

    if a.input_slots != b.input_slots:
        return False, 0.0

    # Compare canonical expressions
    conf = min(a.confidence, b.confidence)

    if a.canonical_expression == b.canonical_expression:
        return True, conf

    # Fuzzy match: same structure after whitespace normalization
    a_norm = re.sub(r"\s+", " ", a.canonical_expression.strip())
    b_norm = re.sub(r"\s+", " ", b.canonical_expression.strip())
    if a_norm == b_norm:
        return True, conf * 0.95

    # Structural match: same slot pattern (ignoring slot numbering)
    a_abstract = re.sub(r"slot_\d+", "S", a_norm)
    b_abstract = re.sub(r"slot_\d+", "S", b_norm)
    if a_abstract == b_abstract:
        # Same algebraic structure, just different slot assignment
        return True, conf * 0.90

    return False, 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Operand binding
# ═══════════════════════════════════════════════════════════════════════════

def extract_operand_binding(
    summary: Any,
    normalized: NormalizedEffect,
) -> dict[int, str]:
    """Determine which native register maps to which abstract slot.

    Returns ``{slot_index: register_name}`` so downstream pseudocode
    emission can say "slot_0 came from VM stack pop #1 via rbx".
    """
    return dict(normalized.slot_map)


# ═══════════════════════════════════════════════════════════════════════════
# Clustering algorithm
# ═══════════════════════════════════════════════════════════════════════════

def cluster_handlers_by_semantics(
    semantics: list[Any],
    symbolic_summaries: dict[int, Any] | None = None,
) -> ClusteringResult:
    """Group handlers into clusters of semantically-equivalent operations.

    This is the main entry point.  It accepts a list of
    :class:`~handler_semantics.HandlerSemantic` objects (or dicts with
    ``handler_address`` and ``operation`` keys) and an optional mapping
    from handler address to :class:`HandlerSymbolicSummary`.

    Algorithm:

    1.  For every handler with a symbolic summary, compute a
        :class:`NormalizedEffect` and group by its signature
        (``operation:width:canonical_expression``).
    2.  Handlers without symbolic summaries fall back to grouping by
        ``(operation, operand_width)`` from the heuristic classification.
    3.  Assign sequential cluster IDs.
    4.  Record per-member operand bindings.

    Args:
        semantics: List of ``HandlerSemantic`` objects (or dicts).
        symbolic_summaries: Optional mapping ``{handler_address: summary}``.

    Returns:
        A :class:`ClusteringResult`.
    """
    if symbolic_summaries is None:
        symbolic_summaries = {}

    # Step 1: Normalize symbolic effects for every handler that has one.
    effects: dict[int, NormalizedEffect] = {}
    for addr, summary in symbolic_summaries.items():
        ne = normalize_symbolic_effect(summary, handler_address=addr)
        if ne.operation != _OP_UNKNOWN:
            effects[addr] = ne

    # Step 2: Build handler info from semantics list.
    handler_info: dict[int, dict[str, Any]] = {}
    for sem in semantics:
        if isinstance(sem, dict):
            addr = sem.get("handler_address", 0)
            op = sem.get("operation", _OP_UNKNOWN)
            width = sem.get("operand_width", 0)
            conf = sem.get("confidence", 0.0)
        else:
            addr = getattr(sem, "handler_address", 0)
            op = getattr(sem, "operation", _OP_UNKNOWN)
            width = getattr(sem, "operand_width", 0)
            conf = getattr(sem, "confidence", 0.0)
        handler_info[addr] = {"operation": op, "operand_width": width, "confidence": conf}

    # Step 3: Group by signature.
    # Handlers WITH symbolic normalization → precise grouping.
    sig_groups: dict[str, list[int]] = defaultdict(list)
    sig_effects: dict[str, NormalizedEffect] = {}
    sym_clustered: set[int] = set()

    for addr, ne in effects.items():
        sig = ne.signature()
        sig_groups[sig].append(addr)
        sig_effects[sig] = ne
        sym_clustered.add(addr)

    # Handlers WITHOUT symbolic normalization → fallback grouping.
    fallback_groups: dict[tuple[str, int], list[int]] = defaultdict(list)
    for addr, info in handler_info.items():
        if addr in sym_clustered:
            continue
        op = info["operation"]
        width = info["operand_width"]
        if op == _OP_UNKNOWN:
            continue  # unclustered
        fallback_groups[(op, width)].append(addr)

    # Step 4: Merge symbolic groups.  Within each signature group all
    # handlers are already equivalent (same canonical expression).
    # Between groups with the same (operation, width), attempt pairwise
    # comparison to merge further.
    merged_sig_groups = _merge_compatible_groups(sig_groups, sig_effects)

    # Step 5: Build SemanticCluster objects.
    clusters: list[SemanticCluster] = []
    cluster_id = 0

    for sig, addrs in sorted(merged_sig_groups.items()):
        ne = sig_effects.get(sig)
        op = ne.operation if ne else _OP_UNKNOWN
        width = ne.operand_width if ne else 0
        conf = ne.confidence if ne else 0.0

        bindings: dict[int, dict[int, str]] = {}
        for addr in addrs:
            if addr in effects:
                bindings[addr] = extract_operand_binding(None, effects[addr])

        clusters.append(SemanticCluster(
            cluster_id=cluster_id,
            operation=op,
            operand_width=width,
            members=sorted(addrs),
            normalized_effect=ne,
            confidence=round(conf, 3),
            operand_bindings=bindings,
        ))
        cluster_id += 1

    # Fallback clusters
    for (op, width), addrs in sorted(fallback_groups.items()):
        # Use the best confidence from handler_info
        best_conf = max(
            (handler_info.get(a, {}).get("confidence", 0.0) for a in addrs),
            default=0.0,
        )
        clusters.append(SemanticCluster(
            cluster_id=cluster_id,
            operation=op,
            operand_width=width,
            members=sorted(addrs),
            normalized_effect=None,
            confidence=round(best_conf * 0.8, 3),  # discount for heuristic
        ))
        cluster_id += 1

    # Unclustered: handlers with unknown operation and no symbolic summary
    unclustered: list[int] = []
    all_clustered: set[int] = set()
    for c in clusters:
        all_clustered.update(c.members)
    for addr in handler_info:
        if addr not in all_clustered:
            unclustered.append(addr)

    # Operation counts
    op_counts: dict[str, int] = Counter()
    for c in clusters:
        op_counts[c.operation] += len(c.members)

    return ClusteringResult(
        clusters=clusters,
        unclustered=sorted(unclustered),
        operation_counts=dict(op_counts.most_common()),
    )


def _merge_compatible_groups(
    sig_groups: dict[str, list[int]],
    sig_effects: dict[str, NormalizedEffect],
) -> dict[str, list[int]]:
    """Attempt to merge signature groups that are semantically equivalent
    but ended up with different canonical expressions (e.g. due to
    minor z3 formatting differences).

    Returns a new mapping from representative signature → member list.
    """
    if len(sig_groups) <= 1:
        return dict(sig_groups)

    # Group signatures by (operation, width)
    by_key: dict[tuple[str, int], list[str]] = defaultdict(list)
    for sig, ne in sig_effects.items():
        by_key[(ne.operation, ne.operand_width)].append(sig)

    merged: dict[str, list[int]] = {}
    for (_op, _width), sigs in by_key.items():
        if len(sigs) <= 1:
            for sig in sigs:
                merged[sig] = list(sig_groups[sig])
            continue

        # Pairwise equivalence → union-find merge
        parent: dict[str, str] = {s: s for s in sigs}

        def find(x: str, parent: dict[str, str] = parent) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: str, y: str, parent: dict[str, str] = parent) -> None:
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[ry] = rx

        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                ne_i = sig_effects[sigs[i]]
                ne_j = sig_effects[sigs[j]]
                eq, _ = are_semantically_equivalent(ne_i, ne_j)
                if eq:
                    union(sigs[i], sigs[j])

        # Collect groups
        roots: dict[str, list[int]] = defaultdict(list)
        for sig in sigs:
            root = find(sig)
            roots[root].extend(sig_groups[sig])

        for root, members in roots.items():
            merged[root] = members

    return merged


# ═══════════════════════════════════════════════════════════════════════════
# Opcode table refinement
# ═══════════════════════════════════════════════════════════════════════════

def refine_opcode_table(
    table: Any,
    clustering: ClusteringResult,
) -> Any:
    """Annotate / update a :class:`SemanticOpcodeTable` with cluster info.

    For every entry whose handler is in a cluster, the entry's operation
    is replaced with the cluster's canonical operation name and the
    confidence is updated.  The original entry's ``detail`` field is
    annotated with the cluster ID.

    Args:
        table: A ``SemanticOpcodeTable`` (duck-typed to avoid import).
        clustering: The clustering result.

    Returns:
        The same ``table`` (mutated in-place for efficiency).
    """
    entries = getattr(table, "entries", [])
    for entry in entries:
        addr = getattr(entry, "handler_address", 0)
        cluster = clustering.find_cluster(addr)
        if cluster is None:
            continue

        semantic = getattr(entry, "semantic", None)
        if semantic is None:
            continue

        # Update operation to cluster's canonical operation
        semantic.operation = cluster.operation
        if cluster.confidence > semantic.confidence:
            semantic.confidence = round(cluster.confidence, 3)

        # Annotate detail
        old_detail = semantic.detail or ""
        semantic.detail = (
            f"cluster={cluster.cluster_id} "
            f"(members={len(cluster.members)}) {old_detail}"
        ).strip()

    # Update unique_operations count
    if entries:
        table.unique_operations = len({
            getattr(e, "semantic", e).operation
            for e in entries
            if hasattr(getattr(e, "semantic", e), "operation")
        })

    return table
