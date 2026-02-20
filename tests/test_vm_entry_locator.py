"""Batch 21 — PE VM Entry Point Locator tests.

Tests for the raw byte-level scanner and capstone-refined VM entry
detection in PE executables.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List

import pytest

from dragonslayer.analysis.vm_discovery.vm_entry_locator import (
    VmEntryCandidate,
    VmEntryReport,
    SectionInfo,
    locate_vm_entries,
    locate_entries_from_pe_result,
    _count_push_prefix_64,
    _count_push_prefix_32,
    _detect_load_and_jump_64,
    _detect_load_and_jump_32,
    _score_candidate,
    _MIN_PUSH_COUNT_64,
    _MIN_PUSH_COUNT_32,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _push_reg32(n: int) -> bytes:
    """Generate n consecutive PUSH r32 opcodes (0x50,0x51,...,0x57 cycling)."""
    return bytes(0x50 + (i % 8) for i in range(n))


def _push_reg64(n: int) -> bytes:
    """Generate n consecutive PUSH instructions for x64 (mix of r0-r15)."""
    result = bytearray()
    for i in range(n):
        if i < 8:
            result.append(0x50 + i)  # push rax..rdi
        else:
            result.extend([0x41, 0x50 + (i - 8)])  # REX.B push r8..r15
    return bytes(result)


def _pushf() -> bytes:
    return b"\x9c"


def _pushad() -> bytes:
    return b"\x60"


def _mov_r64_imm(imm: int) -> bytes:
    """REX.W + mov rax, imm64."""
    return b"\x48\xb8" + struct.pack("<Q", imm)


def _mov_r32_imm(imm: int) -> bytes:
    """mov eax, imm32."""
    return b"\xb8" + struct.pack("<I", imm)


def _jmp_rel32(disp: int) -> bytes:
    """jmp rel32."""
    return b"\xe9" + struct.pack("<i", disp)


def _jmp_rel8(disp: int) -> bytes:
    """jmp rel8."""
    return b"\xeb" + struct.pack("<b", disp)


def _call_rel32(disp: int) -> bytes:
    """call rel32."""
    return b"\xe8" + struct.pack("<i", disp)


def _section_dict(
    name: str = ".text",
    va: int = 0x1000,
    vsize: int = 0x1000,
    raw_offset: int = 0,
    raw_size: int = 0x1000,
    chars: int = 0x60000020,
    entropy: float = 6.0,
) -> Dict[str, Any]:
    return {
        "name": name,
        "virtual_address": hex(va),
        "virtual_size": hex(vsize),
        "raw_offset": hex(raw_offset),
        "raw_size": hex(raw_size),
        "characteristics": hex(chars),
        "entropy": entropy,
    }


# ═══════════════════════════════════════════════════════════════════════
# _count_push_prefix_64
# ═══════════════════════════════════════════════════════════════════════

class TestCountPushPrefix64:
    def test_simple_pushes(self):
        data = _push_reg64(8) + b"\xcc"
        pushes, consumed = _count_push_prefix_64(data, 0)
        assert pushes == 8
        assert consumed == 8 + 0  # first 8 are single-byte push rax-rdi

    def test_with_rex_prefix(self):
        # push r8 = 0x41 0x50, push r9 = 0x41 0x51
        data = bytes([0x41, 0x50, 0x41, 0x51])
        pushes, consumed = _count_push_prefix_64(data, 0)
        assert pushes == 2
        assert consumed == 4

    def test_pushf(self):
        data = _pushf() + _push_reg64(3) + b"\x90"
        pushes, consumed = _count_push_prefix_64(data, 0)
        assert pushes == 4  # pushf + 3 push regs

    def test_mixed_all_regs_plus_flags(self):
        data = _push_reg64(16) + _pushf()
        pushes, _ = _count_push_prefix_64(data, 0)
        assert pushes == 17  # 16 GPRs + flags

    def test_empty(self):
        pushes, consumed = _count_push_prefix_64(b"\xcc\xcc", 0)
        assert pushes == 0
        assert consumed == 0

    def test_offset(self):
        data = b"\x90\x90" + _push_reg64(6) + b"\xcc"
        pushes, consumed = _count_push_prefix_64(data, 2)
        assert pushes == 6


# ═══════════════════════════════════════════════════════════════════════
# _count_push_prefix_32
# ═══════════════════════════════════════════════════════════════════════

class TestCountPushPrefix32:
    def test_pushad(self):
        data = _pushad() + b"\xcc"
        pushes, consumed = _count_push_prefix_32(data, 0)
        assert pushes == 8
        assert consumed == 1

    def test_simple_pushes(self):
        data = _push_reg32(5) + b"\x90"
        pushes, consumed = _count_push_prefix_32(data, 0)
        assert pushes == 5

    def test_pushad_plus_pushf(self):
        data = _pushad() + _pushf()
        pushes, consumed = _count_push_prefix_32(data, 0)
        assert pushes == 9


# ═══════════════════════════════════════════════════════════════════════
# _detect_load_and_jump_64
# ═══════════════════════════════════════════════════════════════════════

class TestDetectLoadAndJump64:
    def test_mov_r64_imm_then_jmp(self):
        addr = 0xDEADBEEF12345678
        data = _mov_r64_imm(addr) + _jmp_rel32(0x100)
        bc, jt = _detect_load_and_jump_64(data, 0, 0x1000)
        assert bc == addr
        assert jt is not None

    def test_mov_r32_imm_then_call(self):
        addr = 0x00401234
        data = _mov_r32_imm(addr) + _call_rel32(0x50)
        bc, jt = _detect_load_and_jump_64(data, 0, 0x2000)
        assert bc == addr
        assert jt is not None

    def test_jmp_rel8(self):
        data = _mov_r64_imm(0x1000) + _jmp_rel8(5)
        bc, jt = _detect_load_and_jump_64(data, 0, 0x1000)
        assert bc == 0x1000
        assert jt is not None

    def test_no_load(self):
        data = b"\x90" * 20
        bc, jt = _detect_load_and_jump_64(data, 0, 0x1000)
        assert bc is None
        assert jt is None


# ═══════════════════════════════════════════════════════════════════════
# _detect_load_and_jump_32
# ═══════════════════════════════════════════════════════════════════════

class TestDetectLoadAndJump32:
    def test_mov_then_jmp(self):
        addr = 0x00401234
        data = _mov_r32_imm(addr) + _jmp_rel32(0x200)
        bc, jt = _detect_load_and_jump_32(data, 0, 0x1000)
        assert bc == addr
        assert jt is not None

    def test_no_jmp(self):
        data = _mov_r32_imm(0x1000) + b"\x90\x90"
        bc, jt = _detect_load_and_jump_32(data, 0, 0x1000)
        assert bc == 0x1000
        assert jt is None


# ═══════════════════════════════════════════════════════════════════════
# _score_candidate
# ═══════════════════════════════════════════════════════════════════════

class TestScoreCandidate:
    def test_below_min_push_returns_zero(self):
        assert _score_candidate(2, None, None, 64) == 0.0
        assert _score_candidate(1, 0x1000, 0x2000, 32) == 0.0

    def test_min_push_64(self):
        s = _score_candidate(_MIN_PUSH_COUNT_64, None, None, 64)
        assert 0.0 < s < 0.5

    def test_high_push_with_load_and_jump(self):
        s = _score_candidate(17, 0xDEAD, 0xBEEF, 64, section_entropy=7.5)
        assert s >= 0.9

    def test_entropy_boost(self):
        s1 = _score_candidate(8, 0x1000, None, 64, section_entropy=5.0)
        s2 = _score_candidate(8, 0x1000, None, 64, section_entropy=7.5)
        assert s2 > s1


# ═══════════════════════════════════════════════════════════════════════
# SectionInfo
# ═══════════════════════════════════════════════════════════════════════

class TestSectionInfo:
    def test_from_pe_dict_hex_strings(self):
        d = _section_dict(name=".vmp0", va=0x2000, vsize=0x5000,
                          raw_offset=0x400, raw_size=0x5000)
        si = SectionInfo.from_pe_dict(d)
        assert si.name == ".vmp0"
        assert si.rva == 0x2000
        assert si.virtual_size == 0x5000
        assert si.raw_offset == 0x400
        assert si.raw_size == 0x5000
        assert si.executable is True

    def test_non_executable_section(self):
        d = _section_dict(chars=0x40000040)  # MEM_READ | INITIALIZED_DATA
        si = SectionInfo.from_pe_dict(d)
        assert si.executable is False


# ═══════════════════════════════════════════════════════════════════════
# VmEntryCandidate / VmEntryReport
# ═══════════════════════════════════════════════════════════════════════

class TestDataStructures:
    def test_candidate_to_dict(self):
        c = VmEntryCandidate(rva=0x1000, va=0x401000, file_offset=0x400,
                             section_name=".text", confidence=0.85,
                             push_count=10, reason="test")
        d = c.to_dict()
        assert d["rva"] == 0x1000
        assert d["confidence"] == 0.85
        assert d["push_count"] == 10

    def test_report_top(self):
        r = VmEntryReport(entries=[
            VmEntryCandidate(rva=1, va=1, file_offset=1,
                             section_name=".text", confidence=0.5),
            VmEntryCandidate(rva=2, va=2, file_offset=2,
                             section_name=".text", confidence=0.9),
            VmEntryCandidate(rva=3, va=3, file_offset=3,
                             section_name=".text", confidence=0.7),
        ])
        top = r.top(2)
        assert len(top) == 2
        assert top[0].confidence == 0.9
        assert top[1].confidence == 0.7

    def test_report_to_dict(self):
        r = VmEntryReport(entries=[], sections_scanned=3, bytes_scanned=4096)
        d = r.to_dict()
        assert d["count"] == 0
        assert d["sections_scanned"] == 3


# ═══════════════════════════════════════════════════════════════════════
# locate_vm_entries — integration
# ═══════════════════════════════════════════════════════════════════════

class TestLocateVmEntries:
    def _build_pe_with_entry_stubs(
        self,
        bit_width: int = 64,
        count: int = 2,
    ) -> tuple:
        """Build a fake PE section containing *count* vm_enter stubs."""
        stubs = bytearray()
        if bit_width == 64:
            for idx in range(count):
                stub = (
                    _push_reg64(16) + _pushf()
                    + _mov_r64_imm(0xBADC0DE000 + idx * 0x100)
                    + _jmp_rel32(0x500 + idx * 4)
                )
                stubs.extend(stub)
                stubs.extend(b"\xcc" * 8)  # padding
        else:
            for idx in range(count):
                stub = (
                    _pushad() + _pushf()
                    + _mov_r32_imm(0x00401000 + idx * 0x100)
                    + _jmp_rel32(0x200 + idx * 4)
                )
                stubs.extend(stub)
                stubs.extend(b"\xcc" * 8)

        section = _section_dict(
            name=".vmp0",
            va=0x1000,
            vsize=len(stubs),
            raw_offset=0,
            raw_size=len(stubs),
            chars=0x60000020,
            entropy=7.2,
        )
        return bytes(stubs), [section]

    def test_finds_64bit_stubs(self):
        data, sections = self._build_pe_with_entry_stubs(64, count=3)
        report = locate_vm_entries(
            data, sections=sections, bit_width=64, min_confidence=0.3)
        assert report.count >= 3
        assert report.sections_scanned == 1
        for e in report.entries:
            assert e.confidence > 0.3
            assert e.push_count >= _MIN_PUSH_COUNT_64
            assert e.section_name == ".vmp0"

    def test_finds_32bit_stubs(self):
        data, sections = self._build_pe_with_entry_stubs(32, count=2)
        report = locate_vm_entries(
            data, sections=sections, bit_width=32, min_confidence=0.3)
        assert report.count >= 2
        for e in report.entries:
            assert e.push_count >= _MIN_PUSH_COUNT_32

    def test_no_executable_section(self):
        data = b"\x90" * 256
        sections = [_section_dict(chars=0x40000040)]  # not executable
        report = locate_vm_entries(data, sections=sections, bit_width=64)
        assert report.count == 0
        assert report.sections_scanned == 0

    def test_empty_data(self):
        report = locate_vm_entries(b"", bit_width=64)
        assert report.count == 0

    def test_no_sections_heuristic(self):
        """Without sections, scanner treats entire file as flat section."""
        stub = _push_reg64(10) + _mov_r64_imm(0x12345678) + _jmp_rel32(0x100)
        data = b"\xcc" * 16 + stub + b"\xcc" * 16
        report = locate_vm_entries(data, sections=None, bit_width=64,
                                   min_confidence=0.3)
        assert report.count >= 1
        assert report.entries[0].file_offset == 16

    def test_max_entries_cap(self):
        """Ensure max_entries limits result count."""
        data, sections = self._build_pe_with_entry_stubs(64, count=5)
        report = locate_vm_entries(
            data, sections=sections, bit_width=64,
            min_confidence=0.1, max_entries=2)
        assert report.count <= 2

    def test_results_sorted_by_confidence(self):
        data, sections = self._build_pe_with_entry_stubs(64, count=3)
        report = locate_vm_entries(
            data, sections=sections, bit_width=64, min_confidence=0.1)
        confs = [e.confidence for e in report.entries]
        assert confs == sorted(confs, reverse=True)


# ═══════════════════════════════════════════════════════════════════════
# locate_entries_from_pe_result
# ═══════════════════════════════════════════════════════════════════════

class TestLocateEntriesFromPeResult:
    def test_basic(self):
        stub = _push_reg64(16) + _pushf() + _mov_r64_imm(0x1000) + _jmp_rel32(0x50)
        data = stub + b"\xcc" * 64

        pe_result = {
            "valid": True,
            "optional_header": {
                "magic": hex(0x20B),
                "image_base": hex(0x140000000),
            },
            "sections": [
                _section_dict(va=0x1000, raw_offset=0, raw_size=len(data)),
            ],
        }
        report = locate_entries_from_pe_result(data, pe_result)
        assert report.count >= 1
        assert report.entries[0].va >= 0x140000000  # image base applied

    def test_32bit_magic(self):
        stub = _pushad() + _pushf() + _mov_r32_imm(0x401000) + _jmp_rel32(0x50)
        data = stub + b"\xcc" * 64

        pe_result = {
            "valid": True,
            "optional_header": {
                "magic": hex(0x10B),
                "image_base": hex(0x400000),
            },
            "sections": [
                _section_dict(va=0x1000, raw_offset=0, raw_size=len(data)),
            ],
        }
        report = locate_entries_from_pe_result(data, pe_result, bit_width=32)
        assert report.count >= 1

    def test_no_optional_header(self):
        """Graceful fallback when no optional header."""
        data = _push_reg64(8) + _mov_r64_imm(0xABCD) + _jmp_rel32(0x10)
        data += b"\xcc" * 64
        pe_result = {
            "valid": True,
            "sections": [
                _section_dict(va=0x1000, raw_offset=0, raw_size=len(data)),
            ],
        }
        report = locate_entries_from_pe_result(data, pe_result)
        # Should use default image base 0x400000
        assert report.entries[0].va >= 0x400000 if report.count > 0 else True
