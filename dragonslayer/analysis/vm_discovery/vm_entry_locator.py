"""
PE VM Entry Point Locator
=========================

Identifies VM entry points (vm_enter stubs) inside PE/ELF binaries by
analysing the raw bytes of executable sections.

VMProtect typically inserts a *vm_enter* stub at the start of each
virtualised function.  The stub:

1. Pushes all general-purpose registers + flags (``pushad``/series of
   ``push`` instructions) — the "save context".
2. Loads the bytecode address (``mov reg, imm`` or ``lea reg, [rip+X]``).
3. Jumps or falls through to the dispatcher.

This module implements a lightweight, dependency-free scanner that
identifies these stubs without needing a full disassembler.

When *capstone* is available the scanner refines candidates by
disassembling the prologue and checking instruction semantics.

Usage::

    from dragonslayer.analysis.vm_discovery.vm_entry_locator import (
        locate_vm_entries,
        VmEntryCandidate,
        VmEntryReport,
    )

    report = locate_vm_entries(
        pe_data,                # raw bytes of the PE file
        image_base=0x00400000,
        sections=sections,      # from PE analyzer
        bit_width=64,
    )

    for entry in report.entries:
        print(f"VM entry at {entry.rva:#x}, confidence={entry.confidence:.2f}")
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Try to import capstone for refined disassembly-based validation.
_HAS_CAPSTONE = False
try:
    import capstone  # type: ignore[import-untyped]
    _HAS_CAPSTONE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VmEntryCandidate:
    """A single suspected VM entry point."""

    rva: int
    """Relative virtual address (image-base-relative)."""

    va: int
    """Absolute virtual address (image_base + rva)."""

    file_offset: int
    """Raw file offset within the PE/ELF image."""

    section_name: str
    """Name of the section containing this entry."""

    confidence: float
    """Confidence score in [0, 1]."""

    push_count: int = 0
    """Number of register-save ``push`` instructions in prologue."""

    bytecode_address: Optional[int] = None
    """If detected, the immediate loaded as bytecode pointer."""

    dispatcher_target: Optional[int] = None
    """If detected, the address jumped to (dispatcher)."""

    reason: str = ""
    """Human-readable reason for flagging this address."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rva": self.rva,
            "va": self.va,
            "file_offset": self.file_offset,
            "section_name": self.section_name,
            "confidence": round(self.confidence, 3),
            "push_count": self.push_count,
            "bytecode_address": self.bytecode_address,
            "dispatcher_target": self.dispatcher_target,
            "reason": self.reason,
        }


@dataclass
class VmEntryReport:
    """Results of VM entry point scanning."""

    entries: List[VmEntryCandidate] = field(default_factory=list)
    sections_scanned: int = 0
    bytes_scanned: int = 0
    method: str = "raw"

    @property
    def count(self) -> int:
        return len(self.entries)

    def top(self, n: int = 10) -> List[VmEntryCandidate]:
        return sorted(self.entries, key=lambda e: -e.confidence)[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "sections_scanned": self.sections_scanned,
            "bytes_scanned": self.bytes_scanned,
            "method": self.method,
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Constants — x86/x64 opcode patterns
# ---------------------------------------------------------------------------

# Single-byte PUSH r32 opcodes (x86): 0x50..0x57
_PUSH_REG32 = set(range(0x50, 0x58))

# PUSHAD (x86 only): 0x60
_PUSHAD = 0x60

# PUSHFQ / PUSHFD: 0x9C
_PUSHF = 0x9C

# Two-byte PUSH r64 via REX.B prefix (x64): 0x41 0x50..0x57
_REX_B = 0x41

# MOV r64, imm64 — REX.W prefix (0x48) + MOV opcode (0xB8..0xBF)
_REX_W = 0x48
_MOV_R64_IMM = set(range(0xB8, 0xC0))

# MOV r32, imm32: 0xB8..0xBF (no prefix)
_MOV_R32_IMM = set(range(0xB8, 0xC0))

# LEA r64, [rip+disp32]: 0x48 0x8D + ModR/M (0x05 | 0x0D | 0x15 | ...)
_LEA_OPCODE = 0x8D

# JMP rel32: 0xE9
_JMP_REL32 = 0xE9

# JMP rel8: 0xEB
_JMP_REL8 = 0xEB

# CALL rel32: 0xE8
_CALL_REL32 = 0xE8

# Minimum push count to consider a "register-save" prologue.
_MIN_PUSH_COUNT_64 = 6   # At least 6 of 16 GPRs + flags
_MIN_PUSH_COUNT_32 = 4   # At least 4 of 8 GPRs (or pushad)


# ---------------------------------------------------------------------------
# Section descriptor (PE sections or ELF segments)
# ---------------------------------------------------------------------------

@dataclass
class SectionInfo:
    """Normalised section descriptor for scanning."""

    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    executable: bool = True

    @classmethod
    def from_pe_dict(cls, d: Dict[str, Any]) -> "SectionInfo":
        """Build from PE analyzer section dict (hex strings)."""
        def _h(v: Any) -> int:
            if isinstance(v, int):
                return v
            return int(str(v), 16)

        chars = _h(d.get("characteristics", 0))
        return cls(
            name=d.get("name", ""),
            rva=_h(d.get("virtual_address", 0)),
            virtual_size=_h(d.get("virtual_size", 0)),
            raw_offset=_h(d.get("raw_offset", d.get("pointer_to_raw_data", 0))),
            raw_size=_h(d.get("raw_size", 0)),
            executable=bool(chars & 0x20000000),  # IMAGE_SCN_MEM_EXECUTE
        )


# ---------------------------------------------------------------------------
# Raw byte-level scanner
# ---------------------------------------------------------------------------

def _count_push_prefix_64(data: bytes, offset: int) -> Tuple[int, int]:
    """Count consecutive push-register instructions starting at *offset*.

    Returns ``(push_count, bytes_consumed)``.
    """
    i = offset
    end = min(offset + 80, len(data))  # cap scan window
    pushes = 0

    while i < end:
        b = data[i]

        if b in _PUSH_REG32:
            # push r32 (also used in x64 for rax..rdi)
            pushes += 1
            i += 1
        elif b == _REX_B and i + 1 < end and data[i + 1] in _PUSH_REG32:
            # push r8..r15 (REX.B + 0x50..)
            pushes += 1
            i += 2
        elif b == _PUSHF:
            pushes += 1
            i += 1
        elif b == _PUSHAD:
            # pushad saves 8 registers
            pushes += 8
            i += 1
        else:
            break

    return pushes, i - offset


def _count_push_prefix_32(data: bytes, offset: int) -> Tuple[int, int]:
    """Count push-register instructions at *offset* for 32-bit mode."""
    i = offset
    end = min(offset + 40, len(data))
    pushes = 0

    while i < end:
        b = data[i]
        if b in _PUSH_REG32:
            pushes += 1
            i += 1
        elif b == _PUSHF:
            pushes += 1
            i += 1
        elif b == _PUSHAD:
            pushes += 8
            i += 1
        else:
            break

    return pushes, i - offset


def _detect_load_and_jump_64(
    data: bytes, offset: int, section_rva: int
) -> Tuple[Optional[int], Optional[int]]:
    """After push prefix, look for ``mov reg, imm64`` then ``jmp/call``.

    Returns ``(bytecode_address, jump_target_rva)`` or (None, None).
    """
    end = min(offset + 20, len(data))
    i = offset

    bytecode_addr: Optional[int] = None
    jmp_target: Optional[int] = None

    # Try MOV r64, imm64 (REX.W + 0xB8..0xBF + 8 bytes)
    if i + 10 <= end and data[i] == _REX_W and data[i + 1] in _MOV_R64_IMM:
        bytecode_addr = struct.unpack_from("<Q", data, i + 2)[0]
        i += 10
    # Try LEA r64, [rip + disp32] (REX.W + 0x8D + modr/m + 4 bytes)
    elif i + 7 <= end and data[i] == _REX_W and data[i + 1] == _LEA_OPCODE:
        modrm = data[i + 2]
        mod = (modrm >> 6) & 3
        rm = modrm & 7
        if mod == 0 and rm == 5:
            disp = struct.unpack_from("<i", data, i + 3)[0]
            # rip-relative: rip points at next instruction = section_rva + offset + 7
            rip_next = section_rva + (i - offset) + 7
            bytecode_addr = rip_next + disp
            i += 7
    # Try MOV r32, imm32 (0xB8..0xBF + 4 bytes)
    elif i + 5 <= end and data[i] in _MOV_R32_IMM:
        bytecode_addr = struct.unpack_from("<I", data, i + 1)[0]
        i += 5

    # Now look for jump / call
    if i < end:
        b = data[i]
        if b == _JMP_REL32 and i + 5 <= end:
            disp = struct.unpack_from("<i", data, i + 1)[0]
            jmp_target = section_rva + (i - offset) + 5 + disp
            i += 5
        elif b == _JMP_REL8 and i + 2 <= end:
            disp = struct.unpack_from("<b", data, i + 1)[0]
            jmp_target = section_rva + (i - offset) + 2 + disp
            i += 2
        elif b == _CALL_REL32 and i + 5 <= end:
            disp = struct.unpack_from("<i", data, i + 1)[0]
            jmp_target = section_rva + (i - offset) + 5 + disp
            i += 5

    return bytecode_addr, jmp_target


def _detect_load_and_jump_32(
    data: bytes, offset: int, section_rva: int
) -> Tuple[Optional[int], Optional[int]]:
    """32-bit variant: ``mov reg, imm32`` + ``jmp/call``."""
    end = min(offset + 20, len(data))
    i = offset

    bytecode_addr: Optional[int] = None
    jmp_target: Optional[int] = None

    if i + 5 <= end and data[i] in _MOV_R32_IMM:
        bytecode_addr = struct.unpack_from("<I", data, i + 1)[0]
        i += 5

    if i < end:
        b = data[i]
        if b == _JMP_REL32 and i + 5 <= end:
            disp = struct.unpack_from("<i", data, i + 1)[0]
            jmp_target = section_rva + (i - offset) + 5 + disp
            i += 5
        elif b == _JMP_REL8 and i + 2 <= end:
            disp = struct.unpack_from("<b", data, i + 1)[0]
            jmp_target = section_rva + (i - offset) + 2 + disp
            i += 2
        elif b == _CALL_REL32 and i + 5 <= end:
            disp = struct.unpack_from("<i", data, i + 1)[0]
            jmp_target = section_rva + (i - offset) + 5 + disp
            i += 5

    return bytecode_addr, jmp_target


# ---------------------------------------------------------------------------
# Capstone-based refinement
# ---------------------------------------------------------------------------

def _refine_with_capstone(
    data: bytes,
    file_offset: int,
    section_rva: int,
    bit_width: int,
    max_insns: int = 30,
) -> Tuple[int, Optional[int], Optional[int], str]:
    """Disassemble a short prologue and check for push-save + load + branch.

    Returns ``(push_count, bytecode_addr, branch_target, reason)``.
    """
    if not _HAS_CAPSTONE:
        return 0, None, None, "capstone unavailable"

    if bit_width == 64:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    push_count = 0
    load_imm: Optional[int] = None
    branch_target: Optional[int] = None
    reason_parts: List[str] = []

    insns = list(md.disasm(data[file_offset:file_offset + 120], section_rva))
    for insn in insns[:max_insns]:
        mn = insn.mnemonic
        if mn in ("push", "pushfq", "pushfd"):
            push_count += 1
        elif mn == "pusha" or mn == "pushad":
            push_count += 8
        elif mn in ("mov", "movabs") and "," in insn.op_str:
            parts = insn.op_str.replace(" ", "").split(",")
            if len(parts) == 2:
                try:
                    load_imm = int(parts[1], 16)
                except (ValueError, TypeError):
                    pass
        elif mn == "lea" and "," in insn.op_str:
            # Try to extract rip-relative target
            try:
                if "[rip" in insn.op_str:
                    # Capstone gives us the resolved address via detail
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_MEM:
                            load_imm = insn.address + insn.size + op.mem.disp
            except Exception:
                pass
        elif mn in ("jmp", "call"):
            try:
                branch_target = int(insn.op_str, 16)
            except (ValueError, TypeError):
                pass
            break  # stop after first branch

    if push_count >= (_MIN_PUSH_COUNT_64 if bit_width == 64 else _MIN_PUSH_COUNT_32):
        reason_parts.append(f"{push_count} register saves")
    if load_imm is not None:
        reason_parts.append(f"bytecode ptr {load_imm:#x}")
    if branch_target is not None:
        reason_parts.append(f"branch → {branch_target:#x}")

    return push_count, load_imm, branch_target, "; ".join(reason_parts)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_candidate(
    push_count: int,
    bytecode_addr: Optional[int],
    jmp_target: Optional[int],
    bit_width: int,
    section_entropy: float = 0.0,
) -> float:
    """Compute confidence score for a candidate vm_entry.

    Score weights:
    - Push count exceeding minimum → strong signal
    - Presence of bytecode address load → strong signal
    - Presence of jump/call target       → moderate signal
    - High section entropy (>7.0)       → slight boost (packed/VM sections)
    """
    score = 0.0
    min_push = _MIN_PUSH_COUNT_64 if bit_width == 64 else _MIN_PUSH_COUNT_32
    max_push = 17 if bit_width == 64 else 9  # 16 GPRs + flags | 8 + flags

    if push_count >= min_push:
        # Linear ramp from threshold to max
        push_score = min(1.0, (push_count - min_push + 1) / (max_push - min_push + 1))
        score += 0.45 * push_score
    else:
        return 0.0  # below minimum push count → not a candidate

    if bytecode_addr is not None:
        score += 0.30

    if jmp_target is not None:
        score += 0.15

    if section_entropy > 7.0:
        score += 0.05

    # Bonus for push count covering all GPRs + flags
    if push_count >= max_push:
        score += 0.05

    return min(1.0, score)


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------

def locate_vm_entries(
    pe_data: bytes,
    *,
    image_base: int = 0x00400000,
    sections: Optional[Sequence[Dict[str, Any]]] = None,
    bit_width: int = 64,
    min_confidence: float = 0.40,
    use_capstone: bool = True,
    max_entries: int = 200,
) -> VmEntryReport:
    """Scan PE/ELF executable sections for VM entry stubs.

    Parameters
    ----------
    pe_data:
        Raw bytes of the entire executable image.
    image_base:
        The image base address (used to compute VAs from RVAs).
    sections:
        Section descriptors — list of dicts from the PE analyzer
        (with keys ``name``, ``virtual_address``, ``virtual_size``,
        ``raw_size``, ``characteristics``, and optionally ``entropy``
        and ``raw_offset``/``pointer_to_raw_data``).
        If *None*, the scanner attempts to locate executable regions
        heuristically.
    bit_width:
        Target architecture width (32 or 64).
    min_confidence:
        Minimum confidence to include a candidate.
    use_capstone:
        If *True* and capstone is installed, refine candidates.
    max_entries:
        Safety cap on the number of candidates returned.

    Returns
    -------
    VmEntryReport
        Scanning results with scored candidates.
    """
    report = VmEntryReport()
    count_push = _count_push_prefix_64 if bit_width == 64 else _count_push_prefix_32
    detect_lj = _detect_load_and_jump_64 if bit_width == 64 else _detect_load_and_jump_32
    min_push = _MIN_PUSH_COUNT_64 if bit_width == 64 else _MIN_PUSH_COUNT_32

    # ── Build section list ───────────────────────────────────────────
    sec_infos: List[Tuple[SectionInfo, float]] = []
    if sections:
        for sd in sections:
            si = SectionInfo.from_pe_dict(sd)
            entropy = float(sd.get("entropy", 0.0))
            sec_infos.append((si, entropy))
    else:
        # Heuristic: treat entire file as one executable section
        si = SectionInfo(
            name=".flat",
            rva=0,
            virtual_size=len(pe_data),
            raw_offset=0,
            raw_size=len(pe_data),
            executable=True,
        )
        sec_infos.append((si, 0.0))

    # ── Scan each executable section ─────────────────────────────────
    for si, entropy in sec_infos:
        if not si.executable:
            continue

        start = si.raw_offset
        end = min(start + si.raw_size, len(pe_data))
        if end <= start:
            continue

        report.sections_scanned += 1
        report.bytes_scanned += end - start

        section_data = pe_data[start:end]

        # Slide byte-by-byte looking for push-save prologues
        i = 0
        while i < len(section_data) - 10 and len(report.entries) < max_entries:
            b = section_data[i]

            # Quick filter: must start with push-reg, pushad, or pushf
            if b not in _PUSH_REG32 and b != _PUSHAD and b != _PUSHF and b != _REX_B:
                i += 1
                continue

            pushes, consumed = count_push(section_data, i)
            if pushes < min_push:
                i += 1
                continue

            # After push prefix, look for load + jump
            after_push = i + consumed
            bytecode_addr, jmp_target = detect_lj(
                section_data, after_push, si.rva)

            score = _score_candidate(
                pushes, bytecode_addr, jmp_target, bit_width, entropy)

            if score < min_confidence:
                i += 1
                continue

            reason = f"{pushes} push insns"
            if bytecode_addr is not None:
                reason += f", bytecode @ {bytecode_addr:#x}"
            if jmp_target is not None:
                reason += f", branch → {jmp_target:#x}"

            # Capstone refinement
            if use_capstone and _HAS_CAPSTONE:
                cs_push, cs_bc, cs_br, cs_reason = _refine_with_capstone(
                    pe_data, start + i, si.rva + i, bit_width)
                if cs_push > 0:
                    pushes = max(pushes, cs_push)
                    bytecode_addr = cs_bc or bytecode_addr
                    jmp_target = cs_br or jmp_target
                    score = _score_candidate(
                        pushes, bytecode_addr, jmp_target, bit_width, entropy)
                    if cs_reason:
                        reason = f"capstone: {cs_reason}"
                    report.method = "capstone"

            rva = si.rva + i
            candidate = VmEntryCandidate(
                rva=rva,
                va=image_base + rva,
                file_offset=start + i,
                section_name=si.name,
                confidence=score,
                push_count=pushes,
                bytecode_address=bytecode_addr,
                dispatcher_target=jmp_target,
                reason=reason,
            )
            report.entries.append(candidate)
            logger.debug("VM entry candidate: RVA=%#x score=%.2f %s",
                         rva, score, reason)

            # Skip past the push sequence to avoid duplicates
            i += max(consumed, 1)
            continue

    # Sort by descending confidence
    report.entries.sort(key=lambda e: -e.confidence)
    return report


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------

def locate_entries_from_pe_result(
    pe_data: bytes,
    pe_result: Dict[str, Any],
    *,
    bit_width: int = 64,
    min_confidence: float = 0.40,
) -> VmEntryReport:
    """Convenience: extract image_base and sections from a PE analyzer result.

    This is the intended entry point when called from the pipeline, where
    ``pe_result`` comes from ``ctx.shared_data["pe_analyzer"]``.
    """
    image_base = 0x00400000
    oh = pe_result.get("optional_header", {})
    if oh:
        ib = oh.get("image_base", "0x400000")
        image_base = int(str(ib), 16) if isinstance(ib, str) else int(ib)

    # Determine bit width from PE magic
    magic = oh.get("magic", "")
    if magic:
        magic_int = int(str(magic), 16) if isinstance(magic, str) else int(magic)
        if magic_int == 0x20B:
            bit_width = 64
        elif magic_int == 0x10B:
            bit_width = 32

    sections = pe_result.get("sections", [])

    return locate_vm_entries(
        pe_data,
        image_base=image_base,
        sections=sections,
        bit_width=bit_width,
        min_confidence=min_confidence,
    )
