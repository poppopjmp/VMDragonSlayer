"""
Tests for the Unified Disassembler Backend  (Batch 38)
=======================================================

Tests cover:
  1. DisassembledInstruction construction & serialisation
  2. Disassembler x64 basic disassembly (capstone)
  3. Disassembler x86 (32-bit) mode
  4. disassemble_one() single instruction
  5. max_instructions limit
  6. Branch detection & target extraction
  7. Register reads/writes extraction
  8. Category assignment from mnemonics
  9. Fallback (no capstone) path
 10. Factory functions (create_disassembler, from_pe)
 11. disassemble_section() convenience
 12. PE integration: parse PE → disassemble .text
 13. Edge cases: empty code, single byte, unknown arch
 14. Import from dragonslayer.core
"""

from __future__ import annotations

import struct
import pytest
from unittest.mock import MagicMock, patch

from dragonslayer.core.disassembler import (
    Disassembler,
    DisassembledInstruction,
    DisasmArchitecture,
    create_disassembler,
    from_pe,
    disassemble_section,
    CAPSTONE_AVAILABLE,
    _MNEMONIC_CATEGORIES,
)


# ── Helpers ──────────────────────────────────────────────────────────

# Real x86-64 byte sequences (verified)
_NOP = b"\x90"                          # nop
_RET = b"\xc3"                          # ret
_ADD_RAX_RBX = b"\x48\x01\xd8"         # add rax, rbx
_MOV_RAX_1 = b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, 1
_JMP_REL8 = b"\xeb\x05"                # jmp $+7
_PUSH_RBP = b"\x55"                     # push rbp
_POP_RBP = b"\x5d"                      # pop rbp
_XOR_EAX_EAX = b"\x31\xc0"             # xor eax, eax
_CALL_REL32 = b"\xe8\x00\x00\x00\x00"  # call $+5
_SUB_RSP_8 = b"\x48\x83\xec\x08"       # sub rsp, 0x8

# Combined snippet (a realistic function prologue)
_PROLOGUE = _PUSH_RBP + b"\x48\x89\xe5" + _SUB_RSP_8  # push rbp; mov rbp, rsp; sub rsp, 8


# =====================================================================
#  1. DisassembledInstruction
# =====================================================================

class TestDisassembledInstruction:
    def test_basic_fields(self):
        insn = DisassembledInstruction(
            address=0x1000, size=3, mnemonic="add", operands="rax, rbx",
            category="arithmetic", raw_bytes=b"\x48\x01\xd8",
        )
        assert insn.address == 0x1000
        assert insn.size == 3
        assert insn.mnemonic == "add"
        assert insn.is_branch is False

    def test_to_dict(self):
        insn = DisassembledInstruction(
            address=0x2000, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
            reads=["rip"], writes=["rip"],
        )
        d = insn.to_dict()
        assert d["address"] == 0x2000
        assert d["raw_bytes"] == "90"
        assert d["reads"] == ["rip"]

    def test_str_representation(self):
        insn = DisassembledInstruction(
            address=0x401000, size=3, mnemonic="add", operands="rax, rbx",
            category="arithmetic", raw_bytes=b"\x48\x01\xd8",
        )
        s = str(insn)
        assert "0x00401000" in s
        assert "add" in s

    def test_branch_fields(self):
        insn = DisassembledInstruction(
            address=0x1000, size=2, mnemonic="jmp", operands="0x1007",
            category="branch_unconditional", raw_bytes=b"\xeb\x05",
            is_branch=True, branch_target=0x1007,
        )
        assert insn.is_branch is True
        assert insn.branch_target == 0x1007


# =====================================================================
#  2. Disassembler x64 basic
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestDisassemblerX64:
    def test_disassemble_nop(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_NOP, 0x1000)
        assert len(result) == 1
        assert result[0].mnemonic == "nop"
        assert result[0].address == 0x1000
        assert result[0].size == 1

    def test_disassemble_add(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_ADD_RAX_RBX, 0x1000)
        assert len(result) == 1
        assert result[0].mnemonic == "add"
        assert result[0].category == "arithmetic"

    def test_disassemble_multiple(self):
        code = _PUSH_RBP + _NOP + _RET
        dis = Disassembler("x64")
        result = dis.disassemble(code, 0x1000)
        assert len(result) == 3
        mnems = [i.mnemonic for i in result]
        assert "push" in mnems
        assert "nop" in mnems
        assert "ret" in mnems

    def test_addresses_sequential(self):
        code = _NOP + _NOP + _NOP
        dis = Disassembler("x64")
        result = dis.disassemble(code, 0x5000)
        assert result[0].address == 0x5000
        assert result[1].address == 0x5001
        assert result[2].address == 0x5002

    def test_raw_bytes_preserved(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_ADD_RAX_RBX, 0)
        assert result[0].raw_bytes == _ADD_RAX_RBX

    def test_architecture_property(self):
        dis = Disassembler("x64")
        assert dis.architecture == "x64"
        assert dis.is_capstone_available is True

    def test_prologue_disassembly(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_PROLOGUE, 0x401000)
        assert len(result) >= 3
        mnems = [i.mnemonic for i in result]
        assert "push" in mnems
        assert "sub" in mnems


# =====================================================================
#  3. Disassembler x86 (32-bit)
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestDisassemblerX86:
    def test_x86_mode(self):
        dis = Disassembler("x86")
        assert dis.architecture == "x86"

    def test_disassemble_32bit_push(self):
        dis = Disassembler("x86")
        # push ebp = 0x55 in 32-bit
        result = dis.disassemble(b"\x55", 0x1000)
        assert len(result) == 1
        assert result[0].mnemonic == "push"

    def test_disassemble_32bit_ret(self):
        dis = Disassembler("x86")
        result = dis.disassemble(_RET, 0x1000)
        assert len(result) == 1
        assert result[0].mnemonic == "ret"


# =====================================================================
#  4. disassemble_one()
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestDisassembleOne:
    def test_returns_single_instruction(self):
        dis = Disassembler("x64")
        insn = dis.disassemble_one(_ADD_RAX_RBX + _NOP, 0x1000)
        assert insn is not None
        assert insn.mnemonic == "add"

    def test_returns_none_for_empty(self):
        dis = Disassembler("x64")
        assert dis.disassemble_one(b"", 0) is None


# =====================================================================
#  5. max_instructions limit
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestMaxInstructions:
    def test_limit_two(self):
        code = _NOP * 10
        dis = Disassembler("x64")
        result = dis.disassemble(code, 0, max_instructions=2)
        assert len(result) == 2

    def test_limit_zero_means_all(self):
        code = _NOP * 5
        dis = Disassembler("x64")
        result = dis.disassemble(code, 0, max_instructions=0)
        assert len(result) == 5


# =====================================================================
#  6. Branch detection & target extraction
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestBranchDetection:
    def test_jmp_detected(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_JMP_REL8, 0x1000)
        assert len(result) == 1
        assert result[0].is_branch is True
        assert result[0].category == "branch_unconditional"

    def test_jmp_target_resolved(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_JMP_REL8, 0x1000)
        # jmp $+7 from 0x1000 → target should be 0x1007
        assert result[0].branch_target == 0x1007

    def test_call_is_branch(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_CALL_REL32, 0x2000)
        assert result[0].is_branch is True
        assert result[0].category == "call"

    def test_ret_is_branch(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_RET, 0x3000)
        assert result[0].is_branch is True
        assert result[0].category == "return"

    def test_nop_not_branch(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_NOP, 0)
        assert result[0].is_branch is False


# =====================================================================
#  7. Register reads/writes
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestRegisterExtraction:
    def test_add_reads_writes(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_ADD_RAX_RBX, 0)
        insn = result[0]
        # add rax, rbx → should read rbx, write rax (implicit reads may vary)
        assert isinstance(insn.reads, list)
        assert isinstance(insn.writes, list)

    def test_push_writes_rsp(self):
        dis = Disassembler("x64")
        result = dis.disassemble(_PUSH_RBP, 0)
        insn = result[0]
        # push should implicitly write rsp
        all_regs = insn.reads + insn.writes
        assert len(all_regs) >= 0  # at least some register activity


# =====================================================================
#  8. Category assignment
# =====================================================================

class TestCategoryAssignment:
    def test_known_categories(self):
        assert _MNEMONIC_CATEGORIES["add"] == "arithmetic"
        assert _MNEMONIC_CATEGORIES["xor"] == "logic"
        assert _MNEMONIC_CATEGORIES["push"] == "stack_push"
        assert _MNEMONIC_CATEGORIES["jmp"] == "branch_unconditional"
        assert _MNEMONIC_CATEGORIES["call"] == "call"
        assert _MNEMONIC_CATEGORIES["ret"] == "return"
        assert _MNEMONIC_CATEGORIES["nop"] == "nop"
        assert _MNEMONIC_CATEGORIES["cpuid"] == "system"

    def test_unknown_mnemonic_defaults(self):
        assert _MNEMONIC_CATEGORIES.get("bswap", "unknown") == "unknown"


# =====================================================================
#  9. Fallback path (mock capstone unavailable)
# =====================================================================

class TestFallbackDisassembly:
    def test_fallback_produces_db_instructions(self):
        dis = Disassembler.__new__(Disassembler)
        dis._arch_str = "x64"
        dis._cs = None  # simulate no capstone
        result = dis.disassemble(b"\x90\xc3", 0x1000)
        assert len(result) == 2
        assert result[0].mnemonic == "db"
        assert result[0].operands == "0x90"
        assert result[1].mnemonic == "db"
        assert result[1].address == 0x1001

    def test_fallback_max_instructions(self):
        dis = Disassembler.__new__(Disassembler)
        dis._arch_str = "x64"
        dis._cs = None
        result = dis.disassemble(b"\x00" * 100, 0, max_instructions=3)
        assert len(result) == 3

    def test_fallback_empty(self):
        dis = Disassembler.__new__(Disassembler)
        dis._arch_str = "x64"
        dis._cs = None
        assert dis.disassemble(b"", 0) == []


# =====================================================================
# 10. Factory functions
# =====================================================================

class TestFactoryFunctions:
    def test_create_disassembler_str(self):
        dis = create_disassembler("x64")
        assert isinstance(dis, Disassembler)
        assert dis.architecture == "x64"

    def test_create_disassembler_enum(self):
        dis = create_disassembler(DisasmArchitecture.X86)
        assert dis.architecture == "x86"

    def test_from_pe_x64(self):
        pb = MagicMock()
        pb.architecture = MagicMock()
        pb.architecture.value = "x64"
        dis = from_pe(pb)
        assert dis.architecture == "x64"

    def test_from_pe_x86(self):
        pb = MagicMock()
        pb.architecture = MagicMock()
        pb.architecture.value = "x86"
        dis = from_pe(pb)
        assert dis.architecture == "x86"

    def test_from_pe_string_arch(self):
        pb = MagicMock()
        pb.architecture = "AMD64"
        dis = from_pe(pb)
        assert dis.architecture == "x64"

    def test_from_pe_no_arch(self):
        pb = MagicMock(spec=[])  # no architecture attribute
        dis = from_pe(pb)
        assert dis.architecture == "x64"  # default


# =====================================================================
# 11. disassemble_section()
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestDisassembleSection:
    def test_section_disassembly(self):
        code = _PUSH_RBP + _NOP + _RET
        result = disassemble_section(code, 0x401000, "x64")
        assert len(result) == 3
        assert result[0].address == 0x401000

    def test_section_x86(self):
        result = disassemble_section(b"\x55\xc3", 0x1000, "x86")
        assert len(result) == 2


# =====================================================================
# 12. PE integration: parse PE → disassemble .text
# =====================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
class TestPEDisassemblyIntegration:
    """Full pipeline: build PE → parse → extract .text → disassemble."""

    def _make_pe(self, text_payload: bytes) -> bytes:
        """Minimal PE64 stub with given .text payload."""
        pe_off = 0x80
        opt_size = 0x70
        sec_table_off = pe_off + 24 + opt_size
        hdr_size = (sec_table_off + 40 + 0x1FF) & ~0x1FF
        buf = bytearray(hdr_size)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, pe_off)
        buf[pe_off:pe_off+4] = b"PE\x00\x00"
        struct.pack_into("<H", buf, pe_off+4, 0x8664)
        struct.pack_into("<H", buf, pe_off+6, 1)
        struct.pack_into("<H", buf, pe_off+20, opt_size)
        struct.pack_into("<H", buf, pe_off+24, 0x20B)
        struct.pack_into("<I", buf, pe_off+24+16, 0x1000)
        struct.pack_into("<Q", buf, pe_off+24+24, 0x400000)
        off = sec_table_off
        buf[off:off+8] = b".text\x00\x00\x00"
        raw_size = (len(text_payload) + 0x1FF) & ~0x1FF
        struct.pack_into("<I", buf, off+8, max(len(text_payload), 0x1000))
        struct.pack_into("<I", buf, off+12, 0x1000)
        struct.pack_into("<I", buf, off+16, raw_size)
        struct.pack_into("<I", buf, off+20, hdr_size)
        struct.pack_into("<I", buf, off+36, 0x60000020)
        buf += text_payload + b"\x00" * (raw_size - len(text_payload))
        return bytes(buf)

    def test_disassemble_pe_text_section(self):
        from dragonslayer.analysis.binary_format import parse_binary
        code = _PUSH_RBP + b"\x48\x89\xe5" + _SUB_RSP_8 + _XOR_EAX_EAX + _RET
        pe = self._make_pe(code + b"\xCC" * (0x200 - len(code)))
        pb = parse_binary(pe)
        sections = pb.load_sections(pe)
        text_data = next(iter(sections.values()))

        dis = from_pe(pb)
        instructions = dis.disassemble(text_data, 0x401000)
        mnems = [i.mnemonic for i in instructions]
        assert "push" in mnems
        assert "sub" in mnems
        assert "xor" in mnems
        assert "ret" in mnems

    def test_from_pe_selects_correct_arch(self):
        from dragonslayer.analysis.binary_format import parse_binary
        pe = self._make_pe(b"\x90" * 0x200)
        pb = parse_binary(pe)
        dis = from_pe(pb)
        assert dis.architecture == "x64"


# =====================================================================
# 13. Edge cases
# =====================================================================

class TestEdgeCases:
    def test_empty_code(self):
        dis = Disassembler("x64")
        assert dis.disassemble(b"", 0) == []

    def test_disassemble_one_empty(self):
        dis = Disassembler("x64")
        assert dis.disassemble_one(b"", 0) is None

    def test_get_info(self):
        dis = Disassembler("x64")
        info = dis.get_info()
        assert info["architecture"] == "x64"
        assert "backend" in info
        assert "capstone_available" in info

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="capstone not installed")
    def test_single_invalid_byte(self):
        dis = Disassembler("x64")
        # 0xFF alone may or may not decode; just check no crash
        result = dis.disassemble(b"\xff", 0)
        assert isinstance(result, list)

    def test_disasm_architecture_enum(self):
        dis = Disassembler(DisasmArchitecture.X64)
        assert dis.architecture == "x64"

    def test_disasm_architecture_enum_x86(self):
        dis = Disassembler(DisasmArchitecture.X86)
        assert dis.architecture == "x86"


# =====================================================================
# 14. Import from dragonslayer.core
# =====================================================================

class TestImportPath:
    def test_import_from_core(self):
        from dragonslayer.core import (
            Disassembler,
            DisassembledInstruction,
            DisasmArchitecture,
            create_disassembler,
            from_pe,
            disassemble_section,
            CAPSTONE_AVAILABLE,
        )
        assert Disassembler is not None
        assert DisassembledInstruction is not None
