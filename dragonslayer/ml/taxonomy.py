"""
Canonical Handler Category Taxonomy
====================================

Single-source-of-truth category labels for all VM handler classifiers.

Every model (:class:`VMHandlerModel`, :class:`SymbolicClassifierModel`,
:class:`TrainedHandlerModel`) **must** produce labels from
:data:`CANONICAL_CATEGORIES`.  Legacy label sets are mapped via
:func:`canonicalize`.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List

# ---------------------------------------------------------------------------
# Canonical label set — aligned with vmprotect_handlers.json handler_type
# ---------------------------------------------------------------------------

CANONICAL_CATEGORIES: List[str] = [
    "arithmetic",       # ADD, SUB, MUL, DIV, NEG, INC, DEC
    "bitwise",          # AND, OR, XOR, NOT, SHL, SHR, ROL, ROR
    "memory",           # MOV [mem], LOAD/STORE
    "stack",            # PUSH, POP
    "control_flow",     # JMP, JCC, CALL, RET
    "comparison",       # CMP, TEST
    "crypto",           # DECRYPT_OPCODE, KEY_UPDATE, rotate-based mixing
    "vm_control",       # VM_ENTER, VM_EXIT, CONTEXT save/restore, FETCH_OPCODE
    "conversion",       # MOVSX, MOVZX, type widening/narrowing
    "system",           # CPUID, RDTSC, privileged ops
    "nop",              # NOP / junk
    "unknown",          # fallback
]

CANONICAL_SET: FrozenSet[str] = frozenset(CANONICAL_CATEGORIES)


# ---------------------------------------------------------------------------
# Legacy → canonical mappings
# ---------------------------------------------------------------------------

_LEGACY_MAP: Dict[str, str] = {
    # model.py VMHandlerModel heuristic
    "logic":         "bitwise",
    "load_store":    "memory",
    "branch":        "control_flow",
    "vm_entry_exit": "vm_control",
    "context":       "vm_control",
    # handler_classifier.py
    "call":          "control_flow",
    "compare":       "comparison",
    # any ad-hoc aliases seen in tests / plugin code
    "load":          "memory",
    "store":         "memory",
    "jmp":           "control_flow",
    "jcc":           "control_flow",
    "ret":           "control_flow",
    "shift":         "bitwise",
    "rotate":        "crypto",
}


def canonicalize(label: str) -> str:
    """Map *label* to its canonical form.

    Returns the label unchanged if it's already canonical or genuinely
    unknown.
    """
    low = label.lower().strip()
    if low in CANONICAL_SET:
        return low
    return _LEGACY_MAP.get(low, "unknown")


def is_canonical(label: str) -> bool:
    """Return ``True`` if *label* belongs to the canonical set."""
    return label.lower().strip() in CANONICAL_SET
