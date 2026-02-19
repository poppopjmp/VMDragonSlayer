"""
Handler Semantics Analysis
===========================

Given:

* An :class:`~..trace_ingestion.ExecutionTrace`
* A list of :class:`~..vm_discovery.handler_boundaries.HandlerBoundary`
  records

…this module analyses the native instructions **inside** each handler
to determine its *semantic operation* — what the handler does from the
virtual machine's perspective (e.g. "add two stack operands", "load
from virtual memory", "conditional branch").

The result is a :class:`SemanticOpcodeTable` — the central artefact
needed for pseudocode emission.

Usage::

    from dragonslayer.analysis.handler_semantics import (
        analyse_handler_semantics,
        SemanticOpcodeTable,
    )

    table = analyse_handler_semantics(trace, boundaries)
    for entry in table.entries:
        print(f"handler 0x{entry.handler_address:X}  →  {entry.operation}")
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semantic categories
# ---------------------------------------------------------------------------

class VMOperation:
    """Known VM semantic operation names (string constants)."""

    ADD = "vm_add"
    SUB = "vm_sub"
    MUL = "vm_mul"
    DIV = "vm_div"
    AND = "vm_and"
    OR = "vm_or"
    XOR = "vm_xor"
    NOT = "vm_not"
    NEG = "vm_neg"
    SHL = "vm_shl"
    SHR = "vm_shr"
    ROL = "vm_rol"
    ROR = "vm_ror"
    LOAD = "vm_load"
    STORE = "vm_store"
    PUSH = "vm_push"
    POP = "vm_pop"
    CMP = "vm_cmp"
    TEST = "vm_test"
    JMP = "vm_jmp"
    JCC = "vm_jcc"
    CALL = "vm_call"
    RET = "vm_ret"
    NOP = "vm_nop"
    UNKNOWN = "vm_unknown"


# Map native x86 mnemonics → VM semantic operations.
_MNEMONIC_MAP: Dict[str, str] = {
    "add": VMOperation.ADD,
    "adc": VMOperation.ADD,
    "sub": VMOperation.SUB,
    "sbb": VMOperation.SUB,
    "imul": VMOperation.MUL,
    "mul": VMOperation.MUL,
    "idiv": VMOperation.DIV,
    "div": VMOperation.DIV,
    "and": VMOperation.AND,
    "or": VMOperation.OR,
    "xor": VMOperation.XOR,
    "not": VMOperation.NOT,
    "neg": VMOperation.NEG,
    "shl": VMOperation.SHL,
    "sal": VMOperation.SHL,
    "shr": VMOperation.SHR,
    "sar": VMOperation.SHR,
    "rol": VMOperation.ROL,
    "ror": VMOperation.ROR,
    "push": VMOperation.PUSH,
    "pop": VMOperation.POP,
    "cmp": VMOperation.CMP,
    "test": VMOperation.TEST,
    "call": VMOperation.CALL,
    "ret": VMOperation.RET,
    "retn": VMOperation.RET,
    "jmp": VMOperation.JMP,
    "nop": VMOperation.NOP,
}

# Conditional jumps all map to JCC.
_JCC_PREFIXES = {"je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl",
                 "jae", "jbe", "jge", "jle", "jo", "jno", "js", "jns",
                 "jp", "jnp", "jecxz", "jrcxz", "loop", "loope", "loopne"}


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class HandlerSemantic:
    """Semantic analysis result for one handler."""

    handler_address: int
    operation: str = VMOperation.UNKNOWN
    confidence: float = 0.0
    operand_count: int = 0
    operand_width: int = 0        # in bytes (4 = dword, 8 = qword)
    reads_memory: bool = False
    writes_memory: bool = False
    modifies_flags: bool = False
    mnemonic_histogram: Dict[str, int] = field(default_factory=dict)
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handler_address": hex(self.handler_address),
            "operation": self.operation,
            "confidence": self.confidence,
            "operand_count": self.operand_count,
            "operand_width": self.operand_width,
            "reads_memory": self.reads_memory,
            "writes_memory": self.writes_memory,
            "modifies_flags": self.modifies_flags,
            "detail": self.detail,
        }


@dataclass
class OpcodeTableEntry:
    """Combines VM opcode value, handler address, and semantics."""

    opcode: int
    handler_address: int
    semantic: HandlerSemantic
    vip_delta: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "opcode": hex(self.opcode),
            "handler_address": hex(self.handler_address),
            "operation": self.semantic.operation,
            "confidence": self.semantic.confidence,
            "vip_delta": self.vip_delta,
        }


@dataclass
class SemanticOpcodeTable:
    """The fully-analysed VM opcode table with semantic annotations."""

    entries: List[OpcodeTableEntry] = field(default_factory=list)
    handler_count: int = 0
    unique_operations: int = 0

    def lookup_opcode(self, opcode: int) -> Optional[OpcodeTableEntry]:
        for e in self.entries:
            if e.opcode == opcode:
                return e
        return None

    def lookup_handler(self, address: int) -> Optional[OpcodeTableEntry]:
        for e in self.entries:
            if e.handler_address == address:
                return e
        return None

    def operations_summary(self) -> Dict[str, int]:
        """Count how many opcodes map to each semantic operation."""
        counter: Counter = Counter()
        for e in self.entries:
            counter[e.semantic.operation] += 1
        return dict(counter.most_common())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handler_count": self.handler_count,
            "unique_operations": self.unique_operations,
            "operations_summary": self.operations_summary(),
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse_handler_semantics(
    trace: ExecutionTrace,
    boundaries: List[HandlerBoundary],
    *,
    opcode_assignments: Optional[Dict[int, int]] = None,
) -> SemanticOpcodeTable:
    """Analyse handler semantics from trace instruction slices.

    For each :class:`HandlerBoundary`, extracts the native instructions
    in that slice, builds a mnemonic histogram, and applies heuristic
    rules to classify the handler's VM-level operation.

    Args:
        trace: The execution trace.
        boundaries: Handler boundaries from segmentation.
        opcode_assignments: Optional mapping
            ``{handler_address: opcode_value}`` from bytecode extraction.
            If not provided, opcodes are assigned sequentially.

    Returns:
        A :class:`SemanticOpcodeTable` with one entry per unique handler.
    """
    # Deduplicate by handler address — same native handler = same semantics.
    seen_handlers: Dict[int, HandlerSemantic] = {}
    boundary_by_handler: Dict[int, HandlerBoundary] = {}

    for boundary in boundaries:
        addr = boundary.handler_address
        if addr in seen_handlers:
            continue

        # Extract the trace slice for this handler.
        start = boundary.trace_start
        end = boundary.trace_end
        handler_insns = trace.instructions[start:end] if trace.instructions else []

        semantic = _classify_handler(addr, handler_insns)
        seen_handlers[addr] = semantic
        boundary_by_handler[addr] = boundary

    # Build opcode table.
    if opcode_assignments is None:
        # Generate sequential opcode values.
        opcode_assignments = {
            addr: idx for idx, addr in enumerate(sorted(seen_handlers.keys()))
        }

    entries: List[OpcodeTableEntry] = []
    for addr, semantic in sorted(seen_handlers.items()):
        opcode = opcode_assignments.get(addr, 0)
        boundary = boundary_by_handler[addr]
        entries.append(OpcodeTableEntry(
            opcode=opcode,
            handler_address=addr,
            semantic=semantic,
            vip_delta=boundary.vip_delta,
        ))

    unique_ops = len({e.semantic.operation for e in entries})

    return SemanticOpcodeTable(
        entries=entries,
        handler_count=len(entries),
        unique_operations=unique_ops,
    )


def _classify_handler(
    address: int,
    instructions: List[TraceInstruction],
) -> HandlerSemantic:
    """Classify a single handler from its native instruction trace."""

    if not instructions:
        return HandlerSemantic(
            handler_address=address,
            operation=VMOperation.NOP,
            confidence=0.5,
            detail="empty handler",
        )

    # Build mnemonic histogram.
    mnemonics: List[str] = []
    for ti in instructions:
        mnem = _extract_mnemonic(ti.disassembly)
        if mnem:
            mnemonics.append(mnem)

    hist = Counter(mnemonics)
    total = len(mnemonics) or 1

    # Check for memory access patterns.
    reads_mem = any(_accesses_memory(ti.disassembly, "read") for ti in instructions)
    writes_mem = any(_accesses_memory(ti.disassembly, "write") for ti in instructions)

    # Check for flag-modifying instructions.
    flag_modifiers = {"add", "sub", "and", "or", "xor", "cmp", "test",
                      "inc", "dec", "neg", "shl", "shr", "sal", "sar",
                      "imul", "mul"}
    modifies_flags = any(m in flag_modifiers for m in mnemonics)

    # ---- Heuristic classification ----

    # Score each potential VM operation by how well the mnemonic
    # histogram matches expected patterns.
    scores: Dict[str, float] = {}

    # push/pop are VM stack infrastructure — de-weight them so the
    # "core" operation dominates.
    infra_ops = {VMOperation.PUSH, VMOperation.POP}

    for mnem, count in hist.items():
        vm_op = _mnemonic_to_vm_op(mnem)
        if vm_op and vm_op != VMOperation.UNKNOWN:
            weight = 0.3 if vm_op in infra_ops else 1.0
            scores[vm_op] = scores.get(vm_op, 0) + (count / total) * weight

    # Memory load pattern: mov with memory source, no store.
    if reads_mem and not writes_mem and "mov" in hist:
        scores[VMOperation.LOAD] = scores.get(VMOperation.LOAD, 0) + 0.4

    # Memory store pattern: mov with memory destination.
    if writes_mem and "mov" in hist:
        scores[VMOperation.STORE] = scores.get(VMOperation.STORE, 0) + 0.4

    # Pure memory ops (both read and write) → could be LOAD or STORE.
    if reads_mem and writes_mem:
        # Prefer store if there's a push or write-heavy pattern.
        if hist.get("push", 0) > hist.get("pop", 0):
            scores[VMOperation.PUSH] = scores.get(VMOperation.PUSH, 0) + 0.2
        elif hist.get("pop", 0) > hist.get("push", 0):
            scores[VMOperation.POP] = scores.get(VMOperation.POP, 0) + 0.2

    if not scores:
        # Can't determine — check if it's a nop (very short, no
        # meaningful operations).
        if len(instructions) <= 3:
            return HandlerSemantic(
                handler_address=address,
                operation=VMOperation.NOP,
                confidence=0.6,
                mnemonic_histogram=dict(hist),
                detail="short handler, no classifiable operations",
            )
        return HandlerSemantic(
            handler_address=address,
            operation=VMOperation.UNKNOWN,
            confidence=0.3,
            reads_memory=reads_mem,
            writes_memory=writes_mem,
            modifies_flags=modifies_flags,
            mnemonic_histogram=dict(hist),
            detail="unrecognised pattern",
        )

    # Pick the highest-scoring operation.
    best_op = max(scores, key=lambda k: scores[k])
    best_score = scores[best_op]
    confidence = min(best_score + 0.3, 0.95)  # base boost + cap

    # Estimate operand count from push/pop pairs.
    operand_count = _estimate_operands(hist)

    # Estimate operand width from register names in instructions.
    operand_width = _estimate_width(instructions)

    return HandlerSemantic(
        handler_address=address,
        operation=best_op,
        confidence=round(confidence, 3),
        operand_count=operand_count,
        operand_width=operand_width,
        reads_memory=reads_mem,
        writes_memory=writes_mem,
        modifies_flags=modifies_flags,
        mnemonic_histogram=dict(hist),
        detail=f"scores={dict(sorted(scores.items(), key=lambda x: -x[1]))}",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_mnemonic(disasm: str) -> str:
    """Extract the mnemonic from a disassembly string."""
    if not disasm:
        return ""
    parts = disasm.strip().split(None, 1)
    return parts[0].lower() if parts else ""


def _mnemonic_to_vm_op(mnem: str) -> str:
    """Map a native mnemonic to a VM operation."""
    if mnem in _MNEMONIC_MAP:
        return _MNEMONIC_MAP[mnem]
    if mnem in _JCC_PREFIXES:
        return VMOperation.JCC
    # mov is context-dependent — handled separately.
    return VMOperation.UNKNOWN


def _accesses_memory(disasm: str, mode: str) -> bool:
    """Check if a disassembly line accesses memory.

    Mode 'read' checks source operand, 'write' checks destination.
    """
    if not disasm:
        return False
    # Memory operands use [] in Intel syntax.
    parts = disasm.split(",")
    if mode == "write" and parts:
        return "[" in parts[0]
    if mode == "read" and len(parts) > 1:
        return "[" in parts[-1]
    # Single-operand check.
    return "[" in disasm


def _estimate_operands(hist: Dict[str, int]) -> int:
    """Estimate the number of VM operands from push/pop usage."""
    pushes = hist.get("push", 0)
    pops = hist.get("pop", 0)
    return max(pushes, pops, 1)


def _estimate_width(instructions: List[TraceInstruction]) -> int:
    """Estimate operand width from register names in disassembly."""
    for ti in instructions:
        text = ti.disassembly.lower()
        if any(r in text for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                     "rsp", "rbp", "r8", "r9")):
            return 8
        if any(r in text for r in ("eax", "ebx", "ecx", "edx", "esi", "edi")):
            return 4
    return 4  # default to 32-bit
