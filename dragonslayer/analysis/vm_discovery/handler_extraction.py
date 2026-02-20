"""
Handler Extraction from Execution Traces
==========================================

Extracts per-handler instruction bodies from a segmented execution trace,
computes concrete register deltas and operand bytes, fingerprints handlers
for deduplication, and bridges trace data into the symbolic executor for
per-handler summaries.

This module sits between :mod:`handler_boundaries` (which identifies
*where* handlers begin/end in a trace) and :mod:`handler_semantics`
(which classifies what each handler *does*).

Usage::

    from dragonslayer.analysis.vm_discovery.handler_extraction import (
        extract_handler_bodies,
        fingerprint_handler,
        deduplicate_handlers,
        HandlerBody,
    )

    # From a segmented trace
    bodies = extract_handler_bodies(trace, segmentation, vip_register="rsi")
    groups = deduplicate_handlers(bodies)
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RegisterDelta:
    """Observed register change during a single handler invocation."""
    register: str
    value_before: int
    value_after: int

    @property
    def delta(self) -> int:
        return self.value_after - self.value_before

    def to_dict(self) -> Dict[str, Any]:
        return {
            "register": self.register,
            "before": hex(self.value_before),
            "after": hex(self.value_after),
            "delta": self.delta,
        }


@dataclass
class HandlerOperand:
    """An operand consumed by a handler from the bytecode stream.

    The operand bytes are those fetched from the bytecode at the vIP
    position corresponding to this handler invocation.
    """
    offset: int  # byte offset from the start of the VM bytecode
    raw_bytes: bytes = b""
    value: int = 0
    width: int = 0  # in bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "raw_bytes": self.raw_bytes.hex(),
            "value": self.value,
            "width": self.width,
        }


@dataclass
class HandlerBody:
    """A concrete handler extraction from one trace invocation.

    Contains the instruction slice, register snapshots at entry/exit,
    computed deltas, operand bytes, and a structural fingerprint.
    """
    handler_address: int
    vip_value: int
    trace_start: int
    trace_end: int  # exclusive

    # Raw instruction data from the trace
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    raw_bytes: bytes = b""

    # Register snapshots
    registers_at_entry: Dict[str, int] = field(default_factory=dict)
    registers_at_exit: Dict[str, int] = field(default_factory=dict)
    register_deltas: List[RegisterDelta] = field(default_factory=list)

    # Operand extraction
    operand: Optional[HandlerOperand] = None
    vip_delta: int = 0  # how much vIP advanced

    # Fingerprint and classification
    fingerprint: str = ""  # structural hash
    mnemonic_sequence: List[str] = field(default_factory=list)
    category: str = ""
    handler_id: Optional[int] = None

    # Memory access patterns
    memory_reads: List[Dict[str, Any]] = field(default_factory=list)
    memory_writes: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handler_address": hex(self.handler_address),
            "vip_value": hex(self.vip_value),
            "trace_start": self.trace_start,
            "trace_end": self.trace_end,
            "instruction_count": self.instruction_count,
            "raw_bytes": self.raw_bytes.hex(),
            "registers_at_entry": {k: hex(v) for k, v in self.registers_at_entry.items()},
            "registers_at_exit": {k: hex(v) for k, v in self.registers_at_exit.items()},
            "register_deltas": [d.to_dict() for d in self.register_deltas],
            "operand": self.operand.to_dict() if self.operand else None,
            "vip_delta": self.vip_delta,
            "fingerprint": self.fingerprint,
            "mnemonic_sequence": self.mnemonic_sequence,
            "category": self.category,
            "memory_reads": self.memory_reads,
            "memory_writes": self.memory_writes,
        }


@dataclass
class HandlerGroup:
    """A deduplicated handler — multiple invocations with the same address
    and structural fingerprint, grouped for analysis."""
    handler_address: int
    fingerprint: str
    invocations: List[HandlerBody] = field(default_factory=list)
    canonical_mnemonics: List[str] = field(default_factory=list)
    category: str = ""
    observed_operand_widths: Set[int] = field(default_factory=set)
    register_effects: Dict[str, List[int]] = field(default_factory=dict)

    @property
    def visit_count(self) -> int:
        return len(self.invocations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handler_address": hex(self.handler_address),
            "fingerprint": self.fingerprint,
            "visit_count": self.visit_count,
            "canonical_mnemonics": self.canonical_mnemonics,
            "category": self.category,
            "observed_operand_widths": sorted(self.observed_operand_widths),
            "register_effects": {
                k: v[:5] for k, v in self.register_effects.items()
            },
        }


@dataclass
class ExtractionResult:
    """Output of :func:`extract_handler_bodies`."""
    bodies: List[HandlerBody] = field(default_factory=list)
    groups: List[HandlerGroup] = field(default_factory=list)
    vip_register: str = ""
    total_invocations: int = 0
    unique_handlers: int = 0
    bytecode_bytes_consumed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vip_register": self.vip_register,
            "total_invocations": self.total_invocations,
            "unique_handlers": self.unique_handlers,
            "bytecode_bytes_consumed": self.bytecode_bytes_consumed,
            "groups": [g.to_dict() for g in self.groups],
        }


# ═══════════════════════════════════════════════════════════════════════════
# Core extraction
# ═══════════════════════════════════════════════════════════════════════════

def extract_handler_bodies(
    trace_instructions: Sequence[Any],
    boundaries: Sequence[Any],
    vip_register: str,
    *,
    dispatcher_addresses: Sequence[int] = (),
    bytecode_base: int = 0,
) -> ExtractionResult:
    """Extract concrete handler bodies from a segmented trace.

    Parameters
    ----------
    trace_instructions :
        The full list of :class:`TraceInstruction` (or dicts with at
        least ``address``, ``disassembly``, ``registers``, ``raw_bytes``
        / ``size`` fields).
    boundaries :
        List of :class:`HandlerBoundary` from :func:`segment_trace`.
    vip_register :
        Name of the virtual instruction pointer register (e.g. ``"rsi"``).
    dispatcher_addresses :
        Set of known dispatcher instruction addresses (used to strip
        dispatcher instructions from handler bodies).
    bytecode_base :
        Base address of the VM bytecode stream (for operand offset
        computation).  If 0, the first vIP value is used.

    Returns
    -------
    ExtractionResult
        With extracted bodies and deduplicated groups.
    """
    if not trace_instructions or not boundaries:
        return ExtractionResult(vip_register=vip_register)

    dispatcher_set = set(dispatcher_addresses)

    # Auto-detect bytecode base from first boundary's vIP
    if bytecode_base == 0 and boundaries:
        bytecode_base = _get_vip_value(boundaries[0])

    bodies: List[HandlerBody] = []
    total_bytecode = 0

    for boundary in boundaries:
        body = _extract_single_handler(
            trace_instructions=trace_instructions,
            boundary=boundary,
            vip_register=vip_register,
            dispatcher_set=dispatcher_set,
            bytecode_base=bytecode_base,
        )
        if body is not None:
            bodies.append(body)
            total_bytecode += abs(body.vip_delta)

    # Fingerprint and deduplicate
    for body in bodies:
        body.fingerprint = fingerprint_handler(body)

    groups = deduplicate_handlers(bodies)

    return ExtractionResult(
        bodies=bodies,
        groups=groups,
        vip_register=vip_register,
        total_invocations=len(bodies),
        unique_handlers=len(groups),
        bytecode_bytes_consumed=total_bytecode,
    )


def _extract_single_handler(
    trace_instructions: Sequence[Any],
    boundary: Any,
    vip_register: str,
    dispatcher_set: Set[int],
    bytecode_base: int,
) -> Optional[HandlerBody]:
    """Extract one handler body from a boundary specification."""
    start = _get_trace_start(boundary)
    end = _get_trace_end(boundary)

    if start < 0 or end <= start or start >= len(trace_instructions):
        return None

    end = min(end, len(trace_instructions))

    # Collect instruction data, skipping dispatcher instructions
    insn_dicts: List[Dict[str, Any]] = []
    raw_bytes = b""
    mnemonic_seq: List[str] = []
    mem_reads: List[Dict[str, Any]] = []
    mem_writes: List[Dict[str, Any]] = []

    for idx in range(start, end):
        insn = trace_instructions[idx]
        addr = _get_insn_address(insn)

        # Skip instructions that belong to the dispatcher itself
        if dispatcher_set and addr in dispatcher_set:
            continue

        insn_dict = _insn_to_dict(insn)
        insn_dicts.append(insn_dict)

        # Collect raw bytes
        rbytes = _get_raw_bytes(insn)
        raw_bytes += rbytes

        # Extract mnemonic
        disasm = _get_disassembly(insn)
        mnem = disasm.split()[0].lower() if disasm else ""
        if mnem:
            mnemonic_seq.append(mnem)

        # Classify memory accesses from disassembly
        _classify_memory_access(disasm, mnem, addr, mem_reads, mem_writes)

    if not insn_dicts:
        return None

    # Register snapshots
    regs_entry = _get_registers(trace_instructions[start])
    regs_exit = _get_registers(trace_instructions[end - 1]) if end - 1 < len(trace_instructions) else {}

    # Compute register deltas
    deltas = _compute_register_deltas(regs_entry, regs_exit)

    # Compute vIP delta
    vip_before = regs_entry.get(vip_register, 0)
    vip_after = regs_exit.get(vip_register, vip_before)
    vip_delta = _get_vip_delta(boundary)
    if vip_delta == 0:
        vip_delta = vip_after - vip_before

    # Extract operand bytes from the bytecode stream
    operand = _extract_operand(
        vip_value=_get_vip_value(boundary),
        vip_delta=vip_delta,
        bytecode_base=bytecode_base,
    )

    # Infer handler category from mnemonic histogram
    category = _infer_category(mnemonic_seq)

    handler_addr = _get_handler_address(boundary)

    return HandlerBody(
        handler_address=handler_addr,
        vip_value=_get_vip_value(boundary),
        trace_start=start,
        trace_end=end,
        instructions=insn_dicts,
        raw_bytes=raw_bytes,
        registers_at_entry=regs_entry,
        registers_at_exit=regs_exit,
        register_deltas=deltas,
        operand=operand,
        vip_delta=vip_delta,
        fingerprint="",
        mnemonic_sequence=mnemonic_seq,
        category=category,
        handler_id=getattr(boundary, "handler_id", None),
        memory_reads=mem_reads,
        memory_writes=mem_writes,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Fingerprinting & deduplication
# ═══════════════════════════════════════════════════════════════════════════

_OPERAND_REGS = {
    "rax", "eax", "ax", "al", "rbx", "ebx", "bx", "bl",
    "rcx", "ecx", "cx", "cl", "rdx", "edx", "dx", "dl",
}

# Registers that carry VM state (opaque to fingerprint)
_VM_STATE_REGS = {
    "rsi", "esi", "rdi", "edi", "rbp", "ebp",
    "r12", "r13", "r14", "r15",
}


def fingerprint_handler(body: HandlerBody) -> str:
    """Compute a structural fingerprint for a handler body.

    The fingerprint is based on the mnemonic sequence with operand
    concrete values abstracted away.  Two handler invocations with the
    same address but different operands should produce the *same*
    fingerprint (unless the instruction stream genuinely differs due
    to polymorphism).

    Returns a hex-digest string.
    """
    parts: List[str] = []
    for insn in body.instructions:
        disasm = insn.get("disassembly", "")
        normalised = _normalize_disassembly(disasm)
        parts.append(normalised)

    canonical = "\n".join(parts)
    h = hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:16]
    return h


def _normalize_disassembly(disasm: str) -> str:
    """Normalize a disassembly string for fingerprinting.

    - Keeps mnemonic and register names
    - Replaces immediate hex/decimal values with 'IMM'
    - Replaces memory displacement values with 'DISP'
    """
    import re

    if not disasm:
        return ""

    parts = disasm.strip().split(None, 1)
    mnemonic = parts[0].lower() if parts else ""
    operands = parts[1] if len(parts) > 1 else ""

    # Replace hex immediates (0x...) with IMM
    operands = re.sub(r'0x[0-9a-fA-F]+', 'IMM', operands)
    # Replace decimal immediates  (standalone numbers)
    operands = re.sub(r'\b\d+\b', 'IMM', operands)

    return f"{mnemonic} {operands}".strip()


def deduplicate_handlers(
    bodies: Sequence[HandlerBody],
) -> List[HandlerGroup]:
    """Group handler bodies by (address, fingerprint) and compute aggregate info."""
    # Group by (handler_address, fingerprint)
    groups_map: Dict[Tuple[int, str], List[HandlerBody]] = defaultdict(list)
    for body in bodies:
        key = (body.handler_address, body.fingerprint)
        groups_map[key].append(body)

    groups: List[HandlerGroup] = []
    for (addr, fp), invocations in groups_map.items():
        # Use the first invocation's mnemonic sequence as canonical
        canonical_mnemonics = invocations[0].mnemonic_sequence if invocations else []

        # Determine category by majority vote
        cat_counter: Counter = Counter()
        for inv in invocations:
            if inv.category:
                cat_counter[inv.category] += 1
        category = cat_counter.most_common(1)[0][0] if cat_counter else ""

        # Collect operand widths
        operand_widths: Set[int] = set()
        for inv in invocations:
            if inv.operand and inv.operand.width > 0:
                operand_widths.add(inv.operand.width)

        # Aggregate register effects (delta values per register)
        reg_effects: Dict[str, List[int]] = defaultdict(list)
        for inv in invocations:
            for delta in inv.register_deltas:
                if delta.delta != 0:
                    reg_effects[delta.register].append(delta.delta)

        groups.append(HandlerGroup(
            handler_address=addr,
            fingerprint=fp,
            invocations=invocations,
            canonical_mnemonics=canonical_mnemonics,
            category=category,
            observed_operand_widths=operand_widths,
            register_effects=dict(reg_effects),
        ))

    # Sort groups by visit count (most-visited first)
    groups.sort(key=lambda g: g.visit_count, reverse=True)
    return groups


# ═══════════════════════════════════════════════════════════════════════════
# Handler category inference
# ═══════════════════════════════════════════════════════════════════════════

_ARITH_MNEMONICS = {"add", "sub", "imul", "mul", "idiv", "div", "neg", "adc", "sbb"}
_LOGIC_MNEMONICS = {"and", "or", "xor", "not", "shl", "shr", "sar", "sal", "rol", "ror"}
_STACK_MNEMONICS = {"push", "pop"}
_MEMORY_MNEMONICS = {"mov", "movzx", "movsx", "movsxd", "lea", "xchg"}
_BRANCH_MNEMONICS = {"jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl",
                     "jge", "jle", "jae", "jbe", "call", "ret"}
_CMP_MNEMONICS = {"cmp", "test"}


def _infer_category(mnemonics: Sequence[str]) -> str:
    """Infer a handler's semantic category from its mnemonic histogram."""
    if not mnemonics:
        return "unknown"

    counts: Counter = Counter()
    for m in mnemonics:
        m = m.lower()
        if m in _ARITH_MNEMONICS:
            counts["arithmetic"] += 1
        elif m in _LOGIC_MNEMONICS:
            counts["logic"] += 1
        elif m in _STACK_MNEMONICS:
            counts["stack"] += 1
        elif m in _MEMORY_MNEMONICS:
            counts["memory"] += 1
        elif m in _BRANCH_MNEMONICS:
            counts["branch"] += 1
        elif m in _CMP_MNEMONICS:
            counts["comparison"] += 1

    if not counts:
        return "unknown"

    # Handlers doing mostly push/pop are stack operations (vm_push / vm_pop)
    total = len(mnemonics)
    top_cat, top_count = counts.most_common(1)[0]

    # Special cases for VMProtect handler patterns:
    if counts.get("stack", 0) >= 2 and counts.get("memory", 0) >= 1:
        # push/pop with mov → likely vm_push or vm_pop
        stack_ratio = counts["stack"] / total
        if stack_ratio > 0.3:
            return "stack_op"

    if counts.get("branch", 0) >= 1 and total <= 3:
        return "vm_exit" if "ret" in mnemonics else "vm_branch"

    return top_cat


# ═══════════════════════════════════════════════════════════════════════════
# Operand extraction
# ═══════════════════════════════════════════════════════════════════════════

def _extract_operand(
    vip_value: int,
    vip_delta: int,
    bytecode_base: int,
) -> Optional[HandlerOperand]:
    """Infer the operand consumed by a handler from vIP movement.

    In VMProtect, the opcode byte is at vIP[0] and any immediate operand
    follows at vIP[1..delta-1].  The first byte is the opcode; the
    remaining bytes are the operand.
    """
    if vip_delta == 0:
        return None

    abs_delta = abs(vip_delta)
    if abs_delta <= 1:
        # Only an opcode byte, no operand
        return None

    operand_width = abs_delta - 1  # opcode byte consumed first
    offset = vip_value - bytecode_base
    if vip_delta > 0:
        operand_offset = offset + 1  # byte after the opcode
    else:
        operand_offset = offset - abs_delta + 1

    return HandlerOperand(
        offset=operand_offset,
        width=operand_width,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Register delta computation
# ═══════════════════════════════════════════════════════════════════════════

_SKIP_REGS = {"rip", "eip", "rflags", "eflags"}


def _compute_register_deltas(
    regs_entry: Dict[str, int],
    regs_exit: Dict[str, int],
) -> List[RegisterDelta]:
    """Compute register deltas between handler entry and exit."""
    deltas: List[RegisterDelta] = []
    for reg, before in regs_entry.items():
        if reg.lower() in _SKIP_REGS:
            continue
        after = regs_exit.get(reg)
        if after is None:
            continue
        if not isinstance(before, int) or not isinstance(after, int):
            continue
        if before != after:
            deltas.append(RegisterDelta(
                register=reg,
                value_before=before,
                value_after=after,
            ))
    return deltas


# ═══════════════════════════════════════════════════════════════════════════
# Memory access classification
# ═══════════════════════════════════════════════════════════════════════════

def _classify_memory_access(
    disasm: str,
    mnemonic: str,
    address: int,
    reads: List[Dict[str, Any]],
    writes: List[Dict[str, Any]],
) -> None:
    """Heuristically classify memory accesses from disassembly."""
    import re

    if not disasm:
        return

    parts = disasm.strip().split(None, 1)
    if len(parts) < 2:
        return

    operands_str = parts[1]
    ops = [o.strip() for o in operands_str.split(",")]

    for i, op in enumerate(ops):
        if "[" not in op:
            continue
        mem_match = re.search(r'\[([^\]]+)\]', op)
        if not mem_match:
            continue
        mem_expr = mem_match.group(1)
        entry = {"insn_address": address, "memory_expr": mem_expr, "operand_index": i}

        if mnemonic in ("push",):
            writes.append(entry)
        elif mnemonic in ("pop",):
            reads.append(entry)
        elif i == 0:
            # First operand with [mem] is a write destination
            writes.append(entry)
        else:
            # Later operand with [mem] is a read source
            reads.append(entry)


# ═══════════════════════════════════════════════════════════════════════════
# Accessor helpers (duck-type both dataclass and dict trace records)
# ═══════════════════════════════════════════════════════════════════════════

def _get_insn_address(insn: Any) -> int:
    if isinstance(insn, dict):
        return insn.get("address", 0)
    return getattr(insn, "address", 0)


def _get_disassembly(insn: Any) -> str:
    if isinstance(insn, dict):
        return insn.get("disassembly", "")
    return getattr(insn, "disassembly", "")


def _get_raw_bytes(insn: Any) -> bytes:
    if isinstance(insn, dict):
        raw = insn.get("raw_bytes", b"")
        if isinstance(raw, str):
            try:
                return bytes.fromhex(raw)
            except ValueError:
                return b""
        return raw
    raw = getattr(insn, "raw_bytes", b"")
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return b""
    return raw


def _get_registers(insn: Any) -> Dict[str, int]:
    if isinstance(insn, dict):
        return dict(insn.get("registers", {}))
    return dict(getattr(insn, "registers", {}))


def _insn_to_dict(insn: Any) -> Dict[str, Any]:
    if isinstance(insn, dict):
        return dict(insn)
    if hasattr(insn, "to_dict"):
        return insn.to_dict()
    return {
        "address": getattr(insn, "address", 0),
        "disassembly": getattr(insn, "disassembly", ""),
        "registers": dict(getattr(insn, "registers", {})),
        "raw_bytes": getattr(insn, "raw_bytes", b""),
        "size": getattr(insn, "size", 0),
    }


# -- Boundary accessors ---

def _get_vip_value(boundary: Any) -> int:
    if isinstance(boundary, dict):
        return boundary.get("vip_value", 0)
    return getattr(boundary, "vip_value", 0)


def _get_handler_address(boundary: Any) -> int:
    if isinstance(boundary, dict):
        return boundary.get("handler_address", 0)
    return getattr(boundary, "handler_address", 0)


def _get_trace_start(boundary: Any) -> int:
    if isinstance(boundary, dict):
        return boundary.get("trace_start", 0)
    return getattr(boundary, "trace_start", 0)


def _get_trace_end(boundary: Any) -> int:
    if isinstance(boundary, dict):
        return boundary.get("trace_end", 0)
    return getattr(boundary, "trace_end", 0)


def _get_vip_delta(boundary: Any) -> int:
    if isinstance(boundary, dict):
        return boundary.get("vip_delta", 0)
    return getattr(boundary, "vip_delta", 0)
