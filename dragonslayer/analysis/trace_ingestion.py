"""
Trace Ingestion Module
=======================

Bridges the gap between **dynamic analysis plugins** (angr, Triton,
Qiling) and the **static analysis pipeline** (taint tracker, symbolic
executor).

Three ingestion paths:

1. **FORMAT.md text traces** — line-oriented ``i:/m:/c:/h:`` format.
2. **Dynamic plugin ``shared_data`` dicts** — angr, triton, qiling.
3. **Programmatic** — build an :class:`ExecutionTrace` incrementally.

All paths produce an :class:`ExecutionTrace` that can be converted to
:class:`~..symbolic_execution.lifter.LiftedInstruction` objects for
consumption by the taint tracker and symbolic executor.

Usage::

    from dragonslayer.analysis.trace_ingestion import (
        ExecutionTrace,
        parse_trace_text,
        from_shared_data,
    )

    # From pipeline shared_data after dynamic stage
    trace = from_shared_data(shared_data)

    # Convert to LiftedInstruction objects for taint tracker
    lifted = trace.to_lifted_instructions()
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Trace data classes
# ---------------------------------------------------------------------------

@dataclass
class TraceInstruction:
    """One executed instruction from a dynamic trace."""
    address: int
    size: int
    raw_bytes: bytes
    disassembly: str
    registers: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "size": self.size,
            "raw_bytes": self.raw_bytes.hex().upper(),
            "disassembly": self.disassembly,
            "registers": self.registers,
        }


@dataclass
class TraceMemoryAccess:
    """One memory read or write observed during execution."""
    type: str       # "R" or "W"
    address: int
    size: int
    value: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "address": self.address,
            "size": self.size,
            "value": self.value,
        }


@dataclass
class TraceControlFlow:
    """A control-flow edge captured during execution."""
    type: str       # "call", "jmp", "ret", "jcc"
    source: int
    target: int

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "source": self.source, "target": self.target}


@dataclass
class HandlerMarker:
    """Marker for an identified VM handler in the trace."""
    handler_id: int
    address: int
    handler_type: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handler_id": self.handler_id,
            "address": self.address,
            "handler_type": self.handler_type,
        }


@dataclass
class ExecutionTrace:
    """Unified trace representation from any dynamic source.

    Acts as the bridge between dynamic analysis output and the
    static analysis pipeline stages.
    """
    instructions: List[TraceInstruction] = field(default_factory=list)
    memory_accesses: List[TraceMemoryAccess] = field(default_factory=list)
    control_flow: List[TraceControlFlow] = field(default_factory=list)
    handlers: List[HandlerMarker] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"  # "angr", "triton", "qiling", "file", ...

    # ---- Conversion helpers --------------------------------------------

    def to_lifted_instructions(self) -> list:
        """Convert trace instructions to ``LiftedInstruction`` objects.

        Returns objects compatible with
        :meth:`~dragonslayer.analysis.taint_tracking.tracker.TaintTracker.analyze`
        and :class:`DTTExecutor`.

        Falls back to ``SimpleInstruction`` data-objects when the lifter /
        capstone is unavailable — they duck-type to the same interface.
        """
        try:
            from dragonslayer.analysis.symbolic_execution.lifter import (
                InstructionLifter,
                LiftedInstruction,
                _MNEMONIC_CATEGORIES,
                InstructionCategory,
            )
            lifter_available = InstructionLifter.available()
        except ImportError:
            lifter_available = False

        if lifter_available:
            return self._lift_with_capstone()
        return self._as_simple_instructions()

    def _lift_with_capstone(self) -> list:
        """Re-lift raw bytes through the InstructionLifter."""
        from dragonslayer.analysis.symbolic_execution.lifter import InstructionLifter

        arch = self.metadata.get("arch", "x86_64")
        lifter = InstructionLifter(arch=arch)

        results = []
        for ti in self.instructions:
            if ti.raw_bytes:
                lifted = lifter.lift(ti.raw_bytes, base_address=ti.address, max_instructions=1)
                results.extend(lifted)
            else:
                results.append(self._simple_from_trace(ti))
        return results

    @staticmethod
    def _simple_from_trace(ti: TraceInstruction) -> "_SimpleInstruction":
        """Build a duck-typed LiftedInstruction from disassembly text."""
        parts = ti.disassembly.split(None, 1)
        mnemonic = parts[0].lower() if parts else "nop"
        operands = parts[1] if len(parts) > 1 else ""

        reads: list[str] = []
        writes: list[str] = []
        # Rough heuristic: first operand is destination
        for reg in _COMMON_REGS:
            if reg in operands:
                # destination (first reference) goes into writes,
                # everything else into reads
                if not writes:
                    writes.append(reg)
                else:
                    reads.append(reg)

        return _SimpleInstruction(
            address=ti.address,
            size=ti.size,
            mnemonic=mnemonic,
            operands=operands,
            category=_guess_category(mnemonic),
            raw_bytes=ti.raw_bytes,
            reads=reads,
            writes=writes,
        )

    def _as_simple_instructions(self) -> list:
        return [self._simple_from_trace(ti) for ti in self.instructions]

    def extract_code_regions(self) -> Dict[int, bytes]:
        """Group consecutive trace instructions by address into code blobs.

        Returns ``{start_addr: bytes}`` for each contiguous region,
        suitable for feeding into ``SymbolicExecutor.analyze()``.
        """
        if not self.instructions:
            return {}

        regions: Dict[int, bytearray] = {}
        sorted_insts = sorted(self.instructions, key=lambda i: i.address)

        current_start = sorted_insts[0].address
        current_buf = bytearray(sorted_insts[0].raw_bytes)
        current_end = current_start + sorted_insts[0].size

        for inst in sorted_insts[1:]:
            if inst.address == current_end:
                current_buf.extend(inst.raw_bytes)
                current_end = inst.address + inst.size
            else:
                regions[current_start] = current_buf
                current_start = inst.address
                current_buf = bytearray(inst.raw_bytes)
                current_end = inst.address + inst.size

        regions[current_start] = current_buf
        return {addr: bytes(buf) for addr, buf in regions.items()}

    def unique_addresses(self) -> set:
        """Set of unique instruction addresses in the trace."""
        return {i.address for i in self.instructions}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "instruction_count": len(self.instructions),
            "memory_access_count": len(self.memory_accesses),
            "control_flow_edges": len(self.control_flow),
            "handler_count": len(self.handlers),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Simple duck-typed instruction (no capstone dependency)
# ---------------------------------------------------------------------------

_COMMON_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
}


def _guess_category(mnemonic: str) -> str:
    _CATS = {
        "add": "arithmetic", "sub": "arithmetic", "mul": "arithmetic",
        "imul": "arithmetic", "inc": "arithmetic", "dec": "arithmetic",
        "and": "logic", "or": "logic", "xor": "logic", "shl": "logic",
        "shr": "logic", "test": "logic", "cmp": "logic",
        "push": "stack_push", "pop": "stack_pop",
        "mov": "memory_read", "lea": "arithmetic",
        "jmp": "branch_unconditional", "call": "call", "ret": "return",
        "nop": "nop",
    }
    return _CATS.get(mnemonic, "unknown")


@dataclass
class _SimpleInstruction:
    """Lightweight duck-typed replacement for LiftedInstruction."""
    address: int
    size: int
    mnemonic: str
    operands: str
    category: str
    raw_bytes: bytes
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    is_branch: bool = False
    branch_target: Optional[int] = None


# ---------------------------------------------------------------------------
# TEXT TRACE PARSER  (FORMAT.md)
# ---------------------------------------------------------------------------

_TRACE_LINE_RE = re.compile(r"^([imch]):\s*(.+)$", re.IGNORECASE)


def parse_trace_text(text: str) -> ExecutionTrace:
    """Parse the FORMAT.md line-oriented trace format.

    Line types::

        i: <addr> | <size> | <bytes_hex> | <disasm> | <registers_csv>
        m: <R|W> | <addr> | <size> | <value>
        c: <type> | <source> | <target>
        h: <id> | <addr> | <type>

    Returns an :class:`ExecutionTrace`.
    """
    trace = ExecutionTrace(source="file")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("---"):
            continue
        m = _TRACE_LINE_RE.match(line)
        if not m:
            continue
        kind = m.group(1).lower()
        payload = m.group(2)
        parts = [p.strip() for p in payload.split("|")]

        try:
            if kind == "i" and len(parts) >= 4:
                addr = _parse_int(parts[0])
                size = _parse_int(parts[1])
                raw = bytes.fromhex(parts[2].replace(" ", "")) if parts[2] else b""
                disasm = parts[3]
                regs: Dict[str, int] = {}
                if len(parts) >= 5 and parts[4]:
                    for pair in parts[4].split(","):
                        kv = pair.split("=", 1)
                        if len(kv) == 2:
                            regs[kv[0].strip()] = _parse_int(kv[1].strip())
                trace.instructions.append(TraceInstruction(
                    address=addr, size=size, raw_bytes=raw,
                    disassembly=disasm, registers=regs,
                ))

            elif kind == "m" and len(parts) >= 4:
                trace.memory_accesses.append(TraceMemoryAccess(
                    type=parts[0].upper(),
                    address=_parse_int(parts[1]),
                    size=_parse_int(parts[2]),
                    value=_parse_int(parts[3]),
                ))

            elif kind == "c" and len(parts) >= 3:
                trace.control_flow.append(TraceControlFlow(
                    type=parts[0],
                    source=_parse_int(parts[1]),
                    target=_parse_int(parts[2]),
                ))

            elif kind == "h" and len(parts) >= 3:
                trace.handlers.append(HandlerMarker(
                    handler_id=_parse_int(parts[0]),
                    address=_parse_int(parts[1]),
                    handler_type=parts[2],
                ))
        except (ValueError, IndexError):
            logger.debug("Skipping malformed trace line: %s", line)
            continue

    logger.info(
        "Parsed trace: %d instructions, %d memory ops, %d CF edges, %d handlers",
        len(trace.instructions), len(trace.memory_accesses),
        len(trace.control_flow), len(trace.handlers),
    )
    return trace


def _parse_int(s: str) -> int:
    """Parse an integer that may be hex (``0x…``) or decimal."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


# ---------------------------------------------------------------------------
# DYNAMIC PLUGIN ADAPTERS
# ---------------------------------------------------------------------------

def from_shared_data(shared_data: Dict[str, Any]) -> ExecutionTrace:
    """Build an :class:`ExecutionTrace` from pipeline ``shared_data``.

    Merges output from ``triton``, ``angr``, and ``qiling`` keys.
    Priority: Triton taint_flow (richest per-instruction data) > angr
    function blocks > Qiling block ranges.
    """
    trace = ExecutionTrace(source="shared_data")

    # --- Triton (most detailed) -----------------------------------------
    triton_data = shared_data.get("triton", {})
    if triton_data:
        _ingest_triton(triton_data, trace)

    # --- Angr ------------------------------------------------------------
    angr_data = shared_data.get("angr", {})
    if angr_data:
        _ingest_angr(angr_data, trace)

    # --- Qiling ----------------------------------------------------------
    qiling_data = shared_data.get("qiling", {})
    if qiling_data:
        _ingest_qiling(qiling_data, trace)

    # --- Metadata from vm_discovery --------------------------------------
    vm_info = shared_data.get("vm_discovery", {})
    if vm_info:
        trace.metadata["protector"] = vm_info.get("protector", "unknown")
        trace.metadata["dispatcher_addresses"] = vm_info.get("dispatcher_addresses", [])
        trace.metadata["image_base"] = vm_info.get("image_base", 0)

    # Arch hint
    for src in (triton_data, angr_data):
        if "arch" in src:
            trace.metadata["arch"] = src["arch"]
            break

    logger.info(
        "Ingested shared_data: %d instructions, %d CF edges, source=%s",
        len(trace.instructions), len(trace.control_flow), trace.source,
    )
    return trace


def from_triton_result(data: Dict[str, Any]) -> ExecutionTrace:
    """Convert a Triton plugin's result dict to :class:`ExecutionTrace`."""
    trace = ExecutionTrace(source="triton")
    _ingest_triton(data, trace)
    trace.metadata["arch"] = data.get("arch", "x86_64")
    return trace


def from_angr_result(data: Dict[str, Any]) -> ExecutionTrace:
    """Convert an angr plugin's result dict to :class:`ExecutionTrace`."""
    trace = ExecutionTrace(source="angr")
    _ingest_angr(data, trace)
    trace.metadata["arch"] = data.get("arch", "x86_64")
    return trace


def from_qiling_result(data: Dict[str, Any]) -> ExecutionTrace:
    """Convert a Qiling plugin's result dict to :class:`ExecutionTrace`."""
    trace = ExecutionTrace(source="qiling")
    _ingest_qiling(data, trace)
    return trace


# ---------------------------------------------------------------------------
# Internal ingest helpers
# ---------------------------------------------------------------------------

def _ingest_triton(data: Dict[str, Any], trace: ExecutionTrace) -> None:
    """Ingest Triton's taint_flow and path_constraints."""
    seen_addrs = {inst.address for inst in trace.instructions}

    for entry in data.get("taint_flow", []):
        addr = entry.get("address", 0)
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)
        disasm = entry.get("disasm", "")
        trace.instructions.append(TraceInstruction(
            address=addr,
            size=0,  # Triton doesn't provide instruction size
            raw_bytes=b"",
            disassembly=disasm,
        ))

    # Path constraints → metadata
    trace.metadata["path_constraints"] = data.get("path_constraints", [])
    trace.metadata["tainted_registers_initial"] = data.get("tainted_registers_initial", [])

    if trace.source == "shared_data":
        trace.source = "shared_data+triton"


def _ingest_angr(data: Dict[str, Any], trace: ExecutionTrace) -> None:
    """Ingest angr's function and handler exploration data."""
    seen_addrs = {inst.address for inst in trace.instructions}

    for func in data.get("functions", []):
        addr = func.get("address", 0)
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)
        name = func.get("name", "")
        # angr reports block-level info; create a placeholder instruction
        trace.instructions.append(TraceInstruction(
            address=addr,
            size=0,
            raw_bytes=b"",
            disassembly=f"func:{name}",
        ))

    # Handler exploration → handler markers
    handler_details = data.get("handler_exploration", {}).get("handler_details", [])
    for hd in handler_details:
        disp = hd.get("dispatcher", 0)
        trace.handlers.append(HandlerMarker(
            handler_id=len(trace.handlers),
            address=disp,
            handler_type=hd.get("type", "unknown"),
        ))
        # Also record control-flow from dispatcher to handler
        trace.control_flow.append(TraceControlFlow(
            type="jmp",
            source=disp,
            target=disp,  # handler_details doesn't provide separate target
        ))

    if "shared_data" in trace.source:
        trace.source += "+angr"
    else:
        trace.source = "angr"


def _ingest_qiling(data: Dict[str, Any], trace: ExecutionTrace) -> None:
    """Ingest Qiling's executed_blocks as address ranges."""
    seen_addrs = {inst.address for inst in trace.instructions}

    for block in data.get("executed_blocks", []):
        start = block.get("start", 0) if isinstance(block, dict) else block
        end = block.get("end", start) if isinstance(block, dict) else start
        if start in seen_addrs:
            continue
        seen_addrs.add(start)
        trace.instructions.append(TraceInstruction(
            address=start,
            size=end - start if end > start else 0,
            raw_bytes=b"",
            disassembly=f"block:0x{start:x}",
        ))

    if "shared_data" in trace.source:
        trace.source += "+qiling"
    else:
        trace.source = "qiling"
