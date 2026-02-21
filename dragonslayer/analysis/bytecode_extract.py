"""
VM Bytecode Extraction
======================

Extracts the raw VM bytecode stream from an execution trace by
correlating:

* **vIP register values** from :class:`HandlerBoundary` records —
  tells us *where* in the virtual address-space the VM is reading.
* **Memory read accesses** from :class:`ExecutionTrace` — tells us
  *what bytes* the VM fetched at those addresses.
* **Handler dispatch information** — maps each fetched opcode byte(s)
  to the native handler that executed.

The result is a :class:`BytecodeStream` — a contiguous (or gapped)
representation of the VM program that was executed, along with an
:class:`OpcodeMap` linking VM opcodes to handler addresses.

Usage::

    from dragonslayer.analysis.bytecode_extract import (
        extract_bytecode,
        BytecodeStream,
        OpcodeMap,
    )

    stream = extract_bytecode(trace, boundaries)
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceMemoryAccess,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
    SegmentationResult,
)

# Lazy import for ParsedBinary to avoid circular deps
_ParsedBinary = None

def _get_parsed_binary_type():
    global _ParsedBinary
    if _ParsedBinary is None:
        try:
            from dragonslayer.analysis.binary_format import ParsedBinary
            _ParsedBinary = ParsedBinary
        except ImportError:
            _ParsedBinary = type(None)
    return _ParsedBinary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class VMOpcode:
    """One decoded VM opcode from the bytecode stream."""

    offset: int                # offset into the bytecode stream
    value: int                 # the opcode byte(s)
    size: int = 1              # number of bytes the opcode occupies
    handler_address: int = 0   # native handler that processes this opcode
    handler_category: str = ""
    operand_bytes: bytes = b"" # raw operand bytes following the opcode
    vip_value: int = 0         # the vIP value when this opcode was fetched

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the VM opcode to a JSON-compatible dict."""
        return {
            "offset": self.offset,
            "value": hex(self.value),
            "size": self.size,
            "handler_address": hex(self.handler_address),
            "handler_category": self.handler_category,
            "operand_size": len(self.operand_bytes),
            "vip_value": hex(self.vip_value),
        }


@dataclass
class OpcodeMap:
    """Maps VM opcode values → native handler addresses and categories."""

    entries: Dict[int, Tuple[int, str]] = field(default_factory=dict)
    # entries[opcode_value] = (handler_address, category)

    def add(self, opcode: int, handler_address: int, category: str = "") -> None:
        """Register an opcode-to-handler mapping, keeping the first seen on conflict."""
        existing = self.entries.get(opcode)
        if existing is None:
            self.entries[opcode] = (handler_address, category)
        elif existing[0] != handler_address:
            # Same opcode dispatched to different handlers — could be
            # context-dependent dispatch.  Keep the first seen.
            logger.debug(
                "Opcode 0x%02X maps to multiple handlers: 0x%X and 0x%X",
                opcode, existing[0], handler_address,
            )

    def handler_for(self, opcode: int) -> Optional[Tuple[int, str]]:
        """Return ``(handler_address, category)`` for *opcode*, or ``None``."""
        return self.entries.get(opcode)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the opcode map to a JSON-compatible dict keyed by hex opcode."""
        return {
            hex(k): {"handler": hex(v[0]), "category": v[1]}
            for k, v in sorted(self.entries.items())
        }


@dataclass
class BytecodeStream:
    """The reconstructed VM bytecode stream."""

    base_address: int = 0              # virtual address of the stream start
    raw_bytes: bytes = b""             # contiguous raw bytecode
    opcodes: List[VMOpcode] = field(default_factory=list)
    opcode_map: OpcodeMap = field(default_factory=OpcodeMap)
    gaps: List[Tuple[int, int]] = field(default_factory=list)  # (offset, size)
    vip_direction: int = 1             # +1 = ascending, -1 = descending

    @property
    def length(self) -> int:
        """Total byte length of the raw bytecode stream."""
        return len(self.raw_bytes)

    @property
    def opcode_count(self) -> int:
        """Number of decoded opcodes in the stream."""
        return len(self.opcodes)

    def opcode_at(self, offset: int) -> Optional[VMOpcode]:
        """Return the :class:`VMOpcode` at byte *offset*, or ``None``."""
        for op in self.opcodes:
            if op.offset == offset:
                return op
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the bytecode stream to a JSON-compatible dict."""
        return {
            "base_address": hex(self.base_address),
            "length": self.length,
            "opcode_count": self.opcode_count,
            "unique_opcodes": len(self.opcode_map.entries),
            "gap_count": len(self.gaps),
            "vip_direction": "ascending" if self.vip_direction > 0 else "descending",
            "opcodes": [op.to_dict() for op in self.opcodes],
            "opcode_map": self.opcode_map.to_dict(),
        }


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_bytecode(
    trace: ExecutionTrace,
    boundaries: List[HandlerBoundary],
    *,
    bytecode_width: int = 0,
    parsed_binary: Optional[Any] = None,
    binary_data: Optional[bytes] = None,
) -> BytecodeStream:
    """Extract the VM bytecode stream from a trace + handler boundaries.

    Strategy:

    1. **Determine vIP direction** — ascending or descending — from the
       sequence of ``vip_value`` in boundaries.
    2. **Collect memory reads near vIP** — for each handler, find memory
       reads whose address matches (or is close to) the handler's
       ``vip_value``.  The first byte(s) read are the opcode; subsequent
       reads are operands.
    3. **Build the contiguous stream** — order collected bytes by vIP
       and fill gaps with ``0xCC`` (breakpoint / unknown).
    4. **Construct the opcode map** — correlate opcode values with
       handler addresses from the boundaries.

    Args:
        trace: The execution trace (needs ``memory_accesses``).
        boundaries: Handler boundaries from segmentation.
        bytecode_width: If known, the fixed bytecode instruction width.
            0 = auto-detect from ``vip_delta`` values.
        parsed_binary: Optional ``ParsedBinary`` for reading real bytes
            from the target binary via VA → file-offset mapping.
        binary_data: Raw bytes of the target binary. Required when
            *parsed_binary* is supplied.

    Returns:
        A :class:`BytecodeStream` with the extracted bytecode.
    """
    if not boundaries:
        return BytecodeStream()

    # ---- 1. vIP direction -----------------------------------------------
    direction = _determine_direction(boundaries)

    # ---- 2. Determine base address and auto-detect width ----------------
    vip_values = [b.vip_value for b in boundaries]
    base = min(vip_values) if direction > 0 else max(vip_values)

    if bytecode_width == 0:
        bytecode_width = _auto_detect_width(boundaries)

    # ---- 3. Collect bytes from memory reads -----------------------------
    mem_map = _build_memory_map(trace.memory_accesses)
    collected: Dict[int, int] = {}  # vaddr → byte value

    for boundary in boundaries:
        vip = boundary.vip_value
        width = abs(boundary.vip_delta) if boundary.vip_delta != 0 else bytecode_width
        if width == 0:
            width = 1

        for offset in range(width):
            addr = vip + offset * direction
            if addr in mem_map:
                collected[addr] = mem_map[addr]

    # Supplement sparse trace memory with binary reads when available.
    if parsed_binary is not None and binary_data is not None:
        for boundary in boundaries:
            vip = boundary.vip_value
            width = abs(boundary.vip_delta) if boundary.vip_delta != 0 else bytecode_width
            if width == 0:
                width = 1
            # Only read for addresses not already in 'collected'
            for off in range(width):
                addr = vip + off * direction
                if addr not in collected:
                    try:
                        chunk = parsed_binary.read_va(binary_data, addr, 1)
                        if chunk is not None and len(chunk) == 1:
                            collected[addr] = chunk[0]
                    except (ValueError, TypeError, IndexError, OSError, RuntimeError):
                        pass

    # ---- 4. Build contiguous stream ------------------------------------
    if not collected:
        # Fall back: use vIP values and boundary info to build opcodes
        # even without memory access data.
        return _build_from_boundaries_only(
            boundaries, direction, base, bytecode_width,
            parsed_binary=parsed_binary,
            binary_data=binary_data,
        )

    sorted_addrs = sorted(collected.keys())
    stream_base = sorted_addrs[0]
    stream_end = sorted_addrs[-1]
    stream_len = stream_end - stream_base + 1

    raw = bytearray(b"\xCC" * stream_len)
    gaps: List[Tuple[int, int]] = []
    gap_start: Optional[int] = None

    for i in range(stream_len):
        addr = stream_base + i
        if addr in collected:
            raw[i] = collected[addr]
            if gap_start is not None:
                gaps.append((gap_start, i - gap_start))
                gap_start = None
        else:
            if gap_start is None:
                gap_start = i
    if gap_start is not None:
        gaps.append((gap_start, stream_len - gap_start))

    # ---- 5. Build opcodes and opcode map --------------------------------
    opcode_map = OpcodeMap()
    opcodes: List[VMOpcode] = []

    for boundary in boundaries:
        vip = boundary.vip_value
        offset = vip - stream_base
        if 0 <= offset < len(raw):
            opcode_val = raw[offset]
            width = abs(boundary.vip_delta) if boundary.vip_delta != 0 else bytecode_width
            if width == 0:
                width = 1
            operand_start = offset + 1
            operand_end = min(offset + width, len(raw))
            operand_bytes = bytes(raw[operand_start:operand_end])

            opcodes.append(VMOpcode(
                offset=offset,
                value=opcode_val,
                size=1,
                handler_address=boundary.handler_address,
                handler_category=boundary.category,
                operand_bytes=operand_bytes,
                vip_value=vip,
            ))
            opcode_map.add(opcode_val, boundary.handler_address, boundary.category)

    return BytecodeStream(
        base_address=stream_base,
        raw_bytes=bytes(raw),
        opcodes=opcodes,
        opcode_map=opcode_map,
        gaps=gaps,
        vip_direction=direction,
    )


def _build_from_boundaries_only(
    boundaries: List[HandlerBoundary],
    direction: int,
    base: int,
    bytecode_width: int,
    *,
    parsed_binary: Optional[Any] = None,
    binary_data: Optional[bytes] = None,
) -> BytecodeStream:
    """Build a BytecodeStream from boundaries when no memory reads are
    available (common when traces lack memory access detail).

    When *parsed_binary* and *binary_data* are supplied the function
    attempts to read real opcode + operand bytes from the binary via
    ``parsed_binary.read_va(binary_data, vip, width)``.  This avoids
    fabricating synthetic sequential opcodes and zero-filled operands.
    The synthetic fallback is still used when the binary cannot supply
    the requested bytes.
    """

    opcode_map = OpcodeMap()
    opcodes: List[VMOpcode] = []

    # --- attempt real byte reads from the binary -----------------------
    can_read_binary = (
        parsed_binary is not None
        and binary_data is not None
        and hasattr(parsed_binary, "read_va")
    )

    # Assign synthetic opcode values only when we cannot read real bytes.
    handler_to_opcode: Dict[int, int] = {}
    next_opcode = 0

    for boundary in boundaries:
        vip = boundary.vip_value
        width = abs(boundary.vip_delta) if boundary.vip_delta != 0 else bytecode_width
        if width == 0:
            width = 1

        real_bytes: Optional[bytes] = None
        if can_read_binary:
            try:
                real_bytes = parsed_binary.read_va(binary_data, vip, width)
            except (ValueError, TypeError, IndexError, OSError, RuntimeError):
                real_bytes = None

        if real_bytes is not None and len(real_bytes) == width:
            # Use real opcode + operand bytes from the binary.
            opval = real_bytes[0]
            operand = real_bytes[1:]
        else:
            # Fallback: synthetic sequential opcode, zero-fill operands.
            if boundary.handler_address not in handler_to_opcode:
                handler_to_opcode[boundary.handler_address] = next_opcode
                next_opcode += 1
            opval = handler_to_opcode[boundary.handler_address]
            operand = b"\x00" * max(width - 1, 0)

        offset = abs(vip - base)
        opcodes.append(VMOpcode(
            offset=offset,
            value=opval,
            size=1,
            handler_address=boundary.handler_address,
            handler_category=boundary.category,
            operand_bytes=operand,
            vip_value=vip,
        ))
        opcode_map.add(opval, boundary.handler_address, boundary.category)

    # Build a raw stream of the opcodes.
    if opcodes:
        max_offset = max(op.offset + 1 + len(op.operand_bytes) for op in opcodes)
        raw = bytearray(b"\xCC" * max_offset)
        for op in opcodes:
            if 0 <= op.offset < len(raw):
                raw[op.offset] = op.value & 0xFF
                # Also fill in operand bytes
                for i, b in enumerate(op.operand_bytes):
                    pos = op.offset + 1 + i
                    if 0 <= pos < len(raw):
                        raw[pos] = b
    else:
        raw = bytearray()

    return BytecodeStream(
        base_address=base,
        raw_bytes=bytes(raw),
        opcodes=opcodes,
        opcode_map=opcode_map,
        vip_direction=direction,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _determine_direction(boundaries: List[HandlerBoundary]) -> int:
    """Return +1 if vIP advances forward, -1 if backward."""
    ups = 0
    downs = 0
    for b in boundaries:
        if b.vip_delta > 0:
            ups += 1
        elif b.vip_delta < 0:
            downs += 1
    return -1 if downs > ups else 1


def _auto_detect_width(boundaries: List[HandlerBoundary]) -> int:
    """Guess the fixed bytecode width from vip_delta values."""
    deltas = [abs(b.vip_delta) for b in boundaries if b.vip_delta != 0]
    if not deltas:
        return 1
    counter = Counter(deltas)
    return counter.most_common(1)[0][0]


def _build_memory_map(
    accesses: List[TraceMemoryAccess],
) -> Dict[int, int]:
    """Build addr → byte value map from read accesses.

    Only reads are considered (the VM fetches bytecode via reads).
    Multi-byte values are split into individual bytes (little-endian).
    """
    mem: Dict[int, int] = {}
    for ma in accesses:
        if ma.type != "R":
            continue
        val = ma.value
        for i in range(ma.size):
            byte_val = (val >> (i * 8)) & 0xFF
            addr = ma.address + i
            if addr not in mem:
                mem[addr] = byte_val
    return mem
