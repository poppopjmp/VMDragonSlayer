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
    # --- Data-movement instructions (context-dependent resolution) ------
    # mov is the most common instruction in VM handlers; its VM
    # operation depends on whether the destination or source is a
    # memory operand.  _mnemonic_to_vm_op resolves this dynamically.
    "mov": VMOperation.LOAD,      # default; overridden per-instruction
    "movzx": VMOperation.LOAD,
    "movsx": VMOperation.LOAD,
    "movsxd": VMOperation.LOAD,
    "lea": VMOperation.LOAD,
    # Conditional moves
    "cmove": VMOperation.LOAD,  "cmovne": VMOperation.LOAD,
    "cmova": VMOperation.LOAD,  "cmovae": VMOperation.LOAD,
    "cmovb": VMOperation.LOAD,  "cmovbe": VMOperation.LOAD,
    "cmovg": VMOperation.LOAD,  "cmovge": VMOperation.LOAD,
    "cmovl": VMOperation.LOAD,  "cmovle": VMOperation.LOAD,
    # Byte-set instructions
    "sete": VMOperation.CMP,  "setne": VMOperation.CMP,
    "seta": VMOperation.CMP,  "setae": VMOperation.CMP,
    "setb": VMOperation.CMP,  "setbe": VMOperation.CMP,
    "setg": VMOperation.CMP,  "setge": VMOperation.CMP,
    "setl": VMOperation.CMP,  "setle": VMOperation.CMP,
    # Exchange (common in handlers) — map to LOAD as it's data movement
    "xchg": VMOperation.LOAD,
    "bswap": VMOperation.LOAD,
}

# Instructions that are typically VM infrastructure / junk code.
# Used by junk-code filter to down-weight noise instructions.
_JUNK_MNEMONICS: Set[str] = {
    "nop", "int3", "ud2", "hlt",
    # Opaque predicate building blocks
    "pushf", "pushfd", "pushfq", "popf", "popfd", "popfq",
    "clc", "stc", "cmc", "cld", "std",
    # Often used as NOPs or alignment
    "xchg",  # when source == dest
    "fnop", "fwait", "wait",
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

    # Apply junk-code filter: remove instructions that are likely noise
    # (opaque predicates, alignment nops, etc.).
    filtered = _filter_junk(instructions)
    effective = filtered if filtered else instructions

    # Build mnemonic histogram.
    mnemonics: List[str] = []
    for ti in effective:
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
        # Pass disasm context for mov resolution — use first instruction
        # with this mnemonic to determine memory direction.
        sample_disasm = ""
        for ti in effective:
            if _extract_mnemonic(ti.disassembly) == mnem:
                sample_disasm = ti.disassembly
                break
        vm_op = _mnemonic_to_vm_op(mnem, sample_disasm)
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
    # Handle prefix-annotated lines like "lock add ..."
    parts = disasm.strip().split(None, 1)
    if not parts:
        return ""
    mnem = parts[0].lower()
    # Skip address prefixes (e.g. "0x401000:")
    if mnem.endswith(":"):
        parts = parts[1].split(None, 1) if len(parts) > 1 else []
        mnem = parts[0].lower() if parts else ""
    # Skip lock/rep prefixes
    if mnem in ("lock", "rep", "repe", "repne", "repz", "repnz"):
        sub = parts[1].split(None, 1) if len(parts) > 1 else []
        mnem = sub[0].lower() if sub else mnem
    return mnem


def _filter_junk(
    instructions: List[TraceInstruction],
) -> List[TraceInstruction]:
    """Remove likely junk / opaque-predicate code from a handler slice.

    Junk-code patterns common in VM-protected binaries:
    * ``xor reg, reg`` followed by branch (opaque predicate)
    * Pure flag manipulation (pushf/popf/clc/stc) sequences
    * ``nop``-equivalent instructions (``xchg reg, reg``, ``lea reg, [reg]``)
    * Unreachable dead code after unconditional jumps

    Returns the filtered list, or the original list if filtering would
    remove everything (safety net).
    """
    if not instructions:
        return instructions

    filtered: List[TraceInstruction] = []
    skip_until_label = False

    for i, ti in enumerate(instructions):
        mnem = _extract_mnemonic(ti.disassembly)
        disasm = ti.disassembly.lower().strip()

        # Skip known junk mnemonics
        if mnem in _JUNK_MNEMONICS:
            # Exception: xchg is only junk when source == dest
            if mnem == "xchg":
                ops = disasm.split(None, 1)
                operands = ops[1] if len(ops) > 1 else ""
                op_parts = [p.strip() for p in operands.split(",")]
                if len(op_parts) == 2 and op_parts[0] == op_parts[1]:
                    continue  # Skip xchg reg, reg
                # else: keep it, it's meaningful data exchange
            else:
                continue

        # Skip dead code after unconditional jump
        if skip_until_label:
            # A label / new basic block starts at branch targets
            # Heuristic: next handler instruction or a target of a jmp
            if mnem and mnem not in _JUNK_MNEMONICS:
                skip_until_label = False
            else:
                continue

        # Detect opaque-predicate pattern: xor reg, reg → jz/jnz
        if mnem == "xor":
            ops = disasm.split(None, 1)
            operands = ops[1] if len(ops) > 1 else ""
            op_parts = [p.strip() for p in operands.split(",")]
            if len(op_parts) == 2 and op_parts[0] == op_parts[1]:
                # xor reg, reg is opaque predicate setup — skip it
                # and the following conditional branch
                if i + 1 < len(instructions):
                    next_mnem = _extract_mnemonic(instructions[i + 1].disassembly)
                    if next_mnem in _JCC_PREFIXES:
                        continue
                continue

        # Detect nop-equivalents: lea reg, [reg] (no displacement)
        if mnem == "lea":
            # lea rax, [rax] is a nop-equivalent
            ops = disasm.split(None, 1)
            operands = ops[1] if len(ops) > 1 else ""
            match = re.match(r"(\w+),\s*\[\1\]$", operands)
            if match:
                continue

        # After unconditional jmp, mark dead code
        if mnem == "jmp":
            skip_until_label = True

        filtered.append(ti)

    # Safety net: never return empty
    return filtered if filtered else instructions


def _mnemonic_to_vm_op(mnem: str, disasm: str = "") -> str:
    """Map a native mnemonic to a VM operation.

    For ``mov`` and variants, resolves to LOAD or STORE based on
    whether the destination operand is a memory reference.
    """
    if mnem in _MNEMONIC_MAP:
        vm_op = _MNEMONIC_MAP[mnem]
        # Context-dependent resolution for mov/movzx/movsx
        if mnem in ("mov", "movzx", "movsx", "movsxd") and disasm:
            if _accesses_memory(disasm, "write"):
                return VMOperation.STORE
            return VMOperation.LOAD
        return vm_op
    if mnem in _JCC_PREFIXES:
        return VMOperation.JCC
    if mnem.startswith("cmov"):
        return VMOperation.LOAD
    if mnem.startswith("set"):
        return VMOperation.CMP
    return VMOperation.UNKNOWN


def _accesses_memory(disasm: str, mode: str) -> bool:
    """Check if a disassembly line accesses memory.

    Mode 'read' checks source operand, 'write' checks destination.
    Supports both Intel syntax (``[...]``) and AT&T syntax (``(...)``
    with ``%`` register prefix).
    """
    if not disasm:
        return False

    # Detect syntax: AT&T uses %reg and (reg) for memory
    is_att = "%" in disasm

    if is_att:
        # AT&T: source is first, destination is last
        parts = disasm.split(",")
        has_mem = lambda s: "(" in s and ")" in s
        if mode == "write" and parts:
            return has_mem(parts[-1])  # AT&T dest is last
        if mode == "read" and parts:
            return has_mem(parts[0])   # AT&T source is first
        return any(has_mem(p) for p in parts)
    else:
        # Intel: destination is first, source is last
        parts = disasm.split(",")
        if mode == "write" and parts:
            return "[" in parts[0]
        if mode == "read" and len(parts) > 1:
            return "[" in parts[-1]
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
