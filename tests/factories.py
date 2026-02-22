"""Shared test factories for VMDragonSlayer.

Reduces boilerplate across 22+ test files by providing canonical builder
functions for common domain objects.  Import into any test module::

    from tests.factories import make_insn, make_pe, make_trace_record
"""

from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from dragonslayer.analysis.symbolic_execution.lifter import (
    InstructionCategory,
    LiftedInstruction,
)
from dragonslayer.analysis.pattern_analysis.database import (
    Pattern,
    PatternDatabase,
)

__all__ = [
    "make_insn",
    "make_taint_insn",
    "make_summary",
    "make_trace_record",
    "make_ns_record",
    "make_handler",
    "make_pattern",
    "make_pattern_db",
    "make_pe",
    "make_pipeline_ctx",
]


# ---------------------------------------------------------------------------
# LiftedInstruction builder  (replaces _make_insn in 13+ test files)
# ---------------------------------------------------------------------------

def make_insn(
    address: int = 0x401000,
    mnemonic: str = "nop",
    operands: str = "",
    size: int = 1,
    category: str = InstructionCategory.UNKNOWN,
    is_branch: bool = False,
    branch_target: Optional[int] = None,
    reads: Optional[List[str]] = None,
    writes: Optional[List[str]] = None,
    raw_bytes: Optional[bytes] = None,
    registers: Optional[Dict[str, int]] = None,
    is_tainted: bool = False,
) -> LiftedInstruction:
    """Build a :class:`LiftedInstruction` with sensible defaults.

    Every parameter matches the dataclass field of the same name, so
    callers only need to specify the parts they care about.
    """
    return LiftedInstruction(
        address=address,
        mnemonic=mnemonic,
        operands=operands,
        size=size,
        category=category,
        raw_bytes=raw_bytes or (b"\x90" * size),
        reads=reads or [],
        writes=writes or [],
        is_branch=is_branch,
        branch_target=branch_target,
        registers=registers or {},
        is_tainted=is_tainted,
    )


# ---------------------------------------------------------------------------
# SimpleNamespace instruction  (replaces _insn in 9 taint-tracker tests)
# ---------------------------------------------------------------------------

def make_taint_insn(
    mnemonic: str = "nop",
    operands: str = "",
    reads: Optional[List[str]] = None,
    writes: Optional[List[str]] = None,
    address: int = 0,
    category: str = "unknown",
    registers: Optional[Dict[str, int]] = None,
) -> SimpleNamespace:
    """Lightweight namespace instruction used by the taint tracker tests."""
    return SimpleNamespace(
        mnemonic=mnemonic,
        operands=operands,
        reads=reads or [],
        writes=writes or [],
        address=address,
        category=category,
        registers=registers or {},
    )


# ---------------------------------------------------------------------------
# Symbolic summary builder  (replaces _make_summary in 4 test files)
# ---------------------------------------------------------------------------

def make_summary(
    *,
    address: int = 0x401000,
    instruction_count: int = 10,
    final_registers: Optional[Dict] = None,
    simplified_registers: Optional[Dict] = None,
    input_symbols: Optional[Dict] = None,
    memory_writes: Optional[List] = None,
    constraints: Optional[List] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a symbolic-execution handler summary dict."""
    writes = memory_writes or []
    return {
        "address": address,
        "instruction_count": instruction_count,
        "final_registers": final_registers or {},
        "simplified_registers": simplified_registers or {},
        "memory_writes": writes,
        "memory_write_count": len(writes),
        "constraints": constraints or [],
        "constraint_count": len(constraints or []),
        "input_symbols": input_symbols or {},
        "error": error,
    }


# ---------------------------------------------------------------------------
# Trace record builder  (replaces _make_trace_record in 5 test files)
# ---------------------------------------------------------------------------

def make_trace_record(
    address: int = 0x401000,
    mnemonic: str = "nop",
    operands: str = "",
    disassembly: str = "",
    registers: Optional[Dict[str, int]] = None,
    raw_bytes: bytes = b"\x90",
) -> Dict[str, Any]:
    """Build a trace-record dict as expected by trace ingestion code."""
    return {
        "address": address,
        "mnemonic": mnemonic,
        "operands": operands,
        "disassembly": disassembly or f"{mnemonic} {operands}".strip(),
        "registers": registers or {},
        "raw_bytes": raw_bytes.hex(),
        "size": len(raw_bytes),
    }


# ---------------------------------------------------------------------------
# SimpleNamespace trace record  (replaces _make_ns_record in 3+ files)
# ---------------------------------------------------------------------------

def make_ns_record(
    address: int = 0x401000,
    mnemonic: str = "nop",
    operands: str = "",
    raw_bytes: bytes = b"",
) -> SimpleNamespace:
    """Build a lightweight namespace trace record."""
    return SimpleNamespace(
        address=address,
        mnemonic=mnemonic,
        operands=operands,
        raw_bytes=raw_bytes,
    )


# ---------------------------------------------------------------------------
# ML handler dict builder  (replaces _make_handler in 4 test files)
# ---------------------------------------------------------------------------

def make_handler(
    mnemonics: Optional[List[str]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build an ML handler dict with instruction mnemonics."""
    mnems = mnemonics or ["nop"]
    instructions = [{"mnemonic": m, "operands": ""} for m in mnems]
    h: Dict[str, Any] = {
        "instructions": instructions,
        "mnemonics": list(mnems),
        "reads": [],
        "writes": [],
    }
    h.update(kwargs)
    return h


# ---------------------------------------------------------------------------
# Pattern / PatternDatabase builders  (replaces _make_pattern in 3 files)
# ---------------------------------------------------------------------------

def make_pattern(
    pattern_id: str = "p1",
    name: str = "test_pattern",
    signature: str = "48 8B 45 00",
    architecture: str = "x64",
    handler_type: str = "arithmetic",
    operation: str = "vAdd64",
    confidence: float = 0.9,
    wildcards: bool = True,
    variants: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Pattern:
    """Build a :class:`Pattern` with sensible defaults."""
    return Pattern(
        pattern_id=pattern_id,
        name=name,
        signature=signature,
        architecture=architecture,
        handler_type=handler_type,
        operation=operation,
        confidence=confidence,
        wildcards=wildcards,
        variants=variants or [],
        metadata=metadata or {},
    )


def make_pattern_db(*patterns: Pattern) -> PatternDatabase:
    """Build a :class:`PatternDatabase` populated with *patterns*."""
    db = PatternDatabase()
    for p in patterns:
        db.add_pattern(p)
    return db


# ---------------------------------------------------------------------------
# Minimal PE builder  (replaces _make_pe in 6 test files)
# ---------------------------------------------------------------------------

def make_pe(
    *,
    text_payload: bytes = b"\xCC" * 0x200,
    extra_sections: Optional[List[tuple]] = None,
    image_base: int = 0x00400000,
    machine: int = 0x8664,
) -> bytes:
    """Build a minimal but valid PE with a ``.text`` section.

    Parameters
    ----------
    text_payload:
        Raw bytes for the ``.text`` section.
    extra_sections:
        List of ``(name_bytes_8, characteristics, payload)`` tuples.
    image_base:
        ``ImageBase`` field in the optional header.
    machine:
        ``Machine`` field (``0x14c`` = x86, ``0x8664`` = x64).

    Returns
    -------
    bytes
        A byte string parseable by LIEF / pefile as a PE.
    """
    is_64 = machine == 0x8664
    sections: list[tuple[bytes, int, bytes]] = [
        (b".text\x00\x00\x00", 0x60000020, text_payload),
    ]
    if extra_sections:
        sections.extend(extra_sections)

    num_sections = len(sections)

    # DOS header (64 bytes)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)  # e_lfanew → PE signature at offset 64

    # PE signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, machine)
    struct.pack_into("<H", coff, 2, num_sections)
    opt_size = 240 if is_64 else 224
    struct.pack_into("<H", coff, 16, opt_size)
    struct.pack_into("<H", coff, 18, 0x0022)  # executable, large-address, no relocs

    # Optional header
    opt = bytearray(opt_size)
    if is_64:
        struct.pack_into("<H", opt, 0, 0x020B)          # PE32+
        struct.pack_into("<I", opt, 16, 0x1000)          # AddressOfEntryPoint
        struct.pack_into("<Q", opt, 24, image_base)      # ImageBase
    else:
        struct.pack_into("<H", opt, 0, 0x010B)           # PE32
        struct.pack_into("<I", opt, 16, 0x1000)          # AddressOfEntryPoint
        struct.pack_into("<I", opt, 28, image_base)      # ImageBase

    alignment = 0x200
    section_alignment = 0x1000
    if is_64:
        struct.pack_into("<I", opt, 32, section_alignment)
        struct.pack_into("<I", opt, 36, alignment)
        struct.pack_into("<I", opt, 56, 0x1000)          # SizeOfHeaders
    else:
        struct.pack_into("<I", opt, 32, section_alignment)
        struct.pack_into("<I", opt, 36, alignment)
        struct.pack_into("<I", opt, 52, 0x1000)          # SizeOfHeaders

    # Section headers (40 bytes each)
    headers_end = 64 + 4 + 20 + opt_size + 40 * num_sections
    raw_offset = _align(headers_end, alignment)

    sec_headers = bytearray()
    rva = section_alignment
    cur_offset = raw_offset

    for name_bytes, chars, payload in sections:
        sh = bytearray(40)
        sh[0:8] = name_bytes[:8].ljust(8, b"\x00")
        raw_size = _align(len(payload), alignment)
        struct.pack_into("<I", sh, 8, len(payload))      # VirtualSize
        struct.pack_into("<I", sh, 12, rva)               # VirtualAddress
        struct.pack_into("<I", sh, 16, raw_size)          # SizeOfRawData
        struct.pack_into("<I", sh, 20, cur_offset)        # PointerToRawData
        struct.pack_into("<I", sh, 36, chars)             # Characteristics
        sec_headers += sh
        rva += _align(len(payload), section_alignment)
        cur_offset += raw_size

    # Assemble image
    header_block = dos + pe_sig + bytes(coff) + bytes(opt) + bytes(sec_headers)
    header_block += b"\x00" * (raw_offset - len(header_block))

    body = bytearray()
    for _name, _chars, payload in sections:
        padded = payload + b"\x00" * (_align(len(payload), alignment) - len(payload))
        body += padded

    # Patch SizeOfImage
    image_size = rva
    if is_64:
        struct.pack_into("<I", opt, 60 - 4, image_size)  # offset 56 in opt
    # (simplified — close enough for analysis tests)

    return bytes(header_block) + bytes(body)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


# ---------------------------------------------------------------------------
# Pipeline context mock  (replaces _make_ctx / _make_pipeline_ctx in 3+ files)
# ---------------------------------------------------------------------------

def make_pipeline_ctx(**shared_data: Any) -> SimpleNamespace:
    """Build a mock pipeline context with ``shared_data``."""
    return SimpleNamespace(shared_data=shared_data)
