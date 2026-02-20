"""
Tests for Disassembler-to-Engine Integration (Batch 40)
=======================================================

Tests cover:
  1. ``disassemble_to_text()`` method on Disassembler
  2. ``to_lifted_instruction()`` adapter (DisassembledInstruction → LiftedInstruction)
  3. ``to_lifted_instructions()`` batch adapter
  4. InstructionLifter delegation to unified Disassembler
  5. TraceEngine wiring (uses unified _make_disassembler)
  6. vm_entry_locator shared disassembler
  7. Import path validation
"""

from __future__ import annotations

import pytest
from typing import Any

from dragonslayer.core.disassembler import (
    Disassembler,
    DisassembledInstruction,
    create_disassembler,
    disassemble_section,
    to_lifted_instruction,
    to_lifted_instructions,
    CAPSTONE_AVAILABLE,
)
from dragonslayer.analysis.symbolic_execution.lifter import (
    InstructionLifter,
    LiftedInstruction,
    InstructionCategory,
    _CAPSTONE_AVAILABLE as LIFTER_CS_AVAIL,
)

# Skip entire file if capstone is not installed (nothing useful to test)
_skip_no_capstone = pytest.mark.skipif(
    not CAPSTONE_AVAILABLE,
    reason="capstone not installed",
)


# ── Fixtures ──────────────────────────────────────────────────────────

# NOP sled followed by ret  (x86-64)
_NOP_RET = b"\x90\x90\x90\xc3"

# add rax, rbx ; ret     (x86-64)
_ADD_RAX_RBX_RET = b"\x48\x01\xd8\xc3"

# mov [rsp-8], rax ; ret  (x86-64)
_MOV_MEM_RET = b"\x48\x89\x44\x24\xf8\xc3"

# push rbp ; push rbx ; push rdi ; nop ; ret   (x86-64)
_PUSH_SEQ = b"\x55\x53\x57\x90\xc3"


# =====================================================================
#  1. disassemble_to_text()
# =====================================================================

class TestDisassembleToText:
    @_skip_no_capstone
    def test_nop_text(self):
        dis = create_disassembler("x64")
        text, size = dis.disassemble_to_text(b"\x90", 0x1000)
        assert "nop" in text.lower()
        assert size == 1

    @_skip_no_capstone
    def test_ret_text(self):
        dis = create_disassembler("x64")
        text, size = dis.disassemble_to_text(b"\xc3", 0x1000)
        assert "ret" in text.lower()
        assert size == 1

    @_skip_no_capstone
    def test_add_text(self):
        dis = create_disassembler("x64")
        text, size = dis.disassemble_to_text(_ADD_RAX_RBX_RET[:3], 0x1000)
        assert "add" in text.lower()
        assert size == 3

    def test_empty_bytes_fallback(self):
        dis = create_disassembler("x64")
        text, size = dis.disassemble_to_text(b"", 0x1000)
        assert text == "db 0x00"
        assert size >= 1


# =====================================================================
#  2. to_lifted_instruction() adapter
# =====================================================================

class TestToLiftedInstruction:
    def _make_disasm_insn(self, **overrides) -> DisassembledInstruction:
        defaults = {
            "address": 0x401000,
            "size": 3,
            "mnemonic": "add",
            "operands": "rax, rbx",
            "category": "arithmetic",
            "raw_bytes": b"\x48\x01\xd8",
            "reads": ["rax", "rbx"],
            "writes": ["rax"],
            "is_branch": False,
            "branch_target": None,
        }
        defaults.update(overrides)
        return DisassembledInstruction(**defaults)

    def test_basic_conversion(self):
        di = self._make_disasm_insn()
        li = to_lifted_instruction(di)
        assert isinstance(li, LiftedInstruction)
        assert li.address == di.address
        assert li.mnemonic == di.mnemonic
        assert li.category == di.category
        assert li.reads == di.reads
        assert li.writes == di.writes
        assert li.raw_bytes == di.raw_bytes

    def test_mov_memory_read(self):
        """mov eax, [rbx] → category should be memory_read."""
        di = self._make_disasm_insn(
            mnemonic="mov",
            operands="eax, [rbx]",
            category="memory",
        )
        li = to_lifted_instruction(di)
        assert li.category == "memory_read"

    def test_mov_memory_write(self):
        """mov [rbx], eax → category should be memory_write."""
        di = self._make_disasm_insn(
            mnemonic="mov",
            operands="[rbx], eax",
            category="memory",
        )
        li = to_lifted_instruction(di)
        assert li.category == "memory_write"

    def test_mov_ptr_write(self):
        """mov dword ptr [rsp+8], 0 → memory_write."""
        di = self._make_disasm_insn(
            mnemonic="mov",
            operands="dword ptr [rsp + 8], 0",
            category="memory",
        )
        li = to_lifted_instruction(di)
        assert li.category == "memory_write"

    def test_branch_target_preserved(self):
        di = self._make_disasm_insn(
            mnemonic="jmp",
            operands="0x402000",
            category="branch_unconditional",
            is_branch=True,
            branch_target=0x402000,
        )
        li = to_lifted_instruction(di)
        assert li.is_branch is True
        assert li.branch_target == 0x402000

    def test_lifted_has_extra_fields(self):
        """LiftedInstruction has registers + is_tainted; defaults applied."""
        di = self._make_disasm_insn()
        li = to_lifted_instruction(di)
        assert li.registers == {}
        assert li.is_tainted is False


# =====================================================================
#  3. to_lifted_instructions() batch
# =====================================================================

class TestToLiftedBatch:
    def test_empty_list(self):
        result = to_lifted_instructions([])
        assert result == []

    def test_batch_conversion(self):
        insns = [
            DisassembledInstruction(
                address=0x1000 + i, size=1, mnemonic="nop",
                operands="", category="nop", raw_bytes=b"\x90",
            )
            for i in range(5)
        ]
        result = to_lifted_instructions(insns)
        assert len(result) == 5
        assert all(isinstance(r, LiftedInstruction) for r in result)


# =====================================================================
#  4. InstructionLifter with unified Disassembler
# =====================================================================

class TestLifterDelegation:
    @_skip_no_capstone
    def test_lifter_accepts_disassembler(self):
        """InstructionLifter constructor accepts disassembler kwarg."""
        dis = create_disassembler("x64")
        lifter = InstructionLifter(arch="x86_64", disassembler=dis)
        assert lifter._unified_disasm is dis

    @_skip_no_capstone
    def test_lifter_delegates_lift(self):
        """When capstone is available + disassembler given, lift still works."""
        dis = create_disassembler("x64")
        lifter = InstructionLifter(arch="x86_64", disassembler=dis)
        # Even when _md is None, _lift_via_unified should work
        lifter._md = None
        result = lifter.lift(_ADD_RAX_RBX_RET, base_address=0x401000)
        assert len(result) >= 1
        assert isinstance(result[0], LiftedInstruction)
        assert result[0].mnemonic == "add"

    @_skip_no_capstone
    def test_lifter_default_still_works(self):
        """Default InstructionLifter (no disassembler kwarg) still works."""
        lifter = InstructionLifter(arch="x86_64")
        assert lifter._unified_disasm is None
        result = lifter.lift(_NOP_RET, base_address=0x401000)
        assert len(result) == 4  # nop nop nop ret
        assert result[0].mnemonic == "nop"

    @_skip_no_capstone
    def test_lifter_lift_function_works(self):
        """lift_function should still return (instructions, metadata)."""
        dis = create_disassembler("x64")
        lifter = InstructionLifter(arch="x86_64", disassembler=dis)
        lifter._md = None  # Force delegation
        insns, meta = lifter.lift_function(_PUSH_SEQ, base_address=0x401000)
        assert len(insns) >= 3
        assert "instruction_count" in meta
        assert "category_counts" in meta

    def test_lifter_fallback_when_no_disasm(self):
        """When neither capstone nor disassembler: fallback 1-byte."""
        lifter = InstructionLifter(arch="x86_64")
        lifter._md = None
        lifter._unified_disasm = None
        result = lifter.lift(b"\x90\xc3", base_address=0x1000)
        assert len(result) == 2
        assert result[0].mnemonic == "db"


# =====================================================================
#  5. TraceEngine wiring
# =====================================================================

class TestTraceEngineWiring:
    def test_make_disassembler_uses_unified(self):
        """_make_disassembler now returns a unified Disassembler."""
        from dragonslayer.analysis.trace_engine import _make_disassembler
        dis = _make_disassembler("x86_64")
        assert isinstance(dis, Disassembler)
        assert dis.architecture == "x64"

    def test_make_disassembler_32bit(self):
        from dragonslayer.analysis.trace_engine import _make_disassembler
        dis = _make_disassembler("x86")
        assert isinstance(dis, Disassembler)
        assert dis.architecture == "x86"

    @_skip_no_capstone
    def test_disassemble_one_via_unified(self):
        from dragonslayer.analysis.trace_engine import _disassemble_one, _make_disassembler
        dis = _make_disassembler("x86_64")
        text, size = _disassemble_one(dis, b"\x90", 0x1000)
        assert "nop" in text.lower()
        assert size == 1


# =====================================================================
#  6. vm_entry_locator shared disassembler
# =====================================================================

class TestVmEntryLocatorWiring:
    @_skip_no_capstone
    def test_refine_accepts_disassembler(self):
        """_refine_with_capstone accepts disassembler kwarg."""
        from dragonslayer.analysis.vm_discovery.vm_entry_locator import (
            _refine_with_capstone,
        )
        dis = create_disassembler("x64")
        # Empty data — should return 0 pushes
        result = _refine_with_capstone(
            b"\x00" * 200, 0, 0x401000, 64,
            disassembler=dis,
        )
        assert len(result) == 4  # (push_count, bc, br, reason)

    @_skip_no_capstone
    def test_refine_detects_pushes(self):
        """Push sequence should be counted."""
        from dragonslayer.analysis.vm_discovery.vm_entry_locator import (
            _refine_with_capstone,
        )
        dis = create_disassembler("x64")
        # push rbp ; push rbx ; push rdi ; nop ; ret
        data = _PUSH_SEQ + b"\x00" * 120
        push_count, _, _, reason = _refine_with_capstone(
            data, 0, 0x401000, 64,
            disassembler=dis,
        )
        assert push_count >= 3


# =====================================================================
#  7. Import paths
# =====================================================================

class TestImportPaths:
    def test_import_to_lifted_from_core(self):
        from dragonslayer.core import to_lifted_instruction, to_lifted_instructions
        assert callable(to_lifted_instruction)
        assert callable(to_lifted_instructions)

    def test_import_from_disassembler_module(self):
        from dragonslayer.core.disassembler import (
            to_lifted_instruction,
            to_lifted_instructions,
        )
        assert callable(to_lifted_instruction)


# =====================================================================
#  8. Round-trip: disassemble → lift → taint-compatible
# =====================================================================

class TestRoundTrip:
    @_skip_no_capstone
    def test_disassemble_convert_taint_compatible(self):
        """LiftedInstruction from adapter has attrs the taint tracker uses."""
        dis = create_disassembler("x64")
        insns = dis.disassemble(_ADD_RAX_RBX_RET, 0x401000)
        lifted = to_lifted_instructions(insns)
        for li in lifted:
            # TaintTracker uses getattr() for these
            assert hasattr(li, "reads")
            assert hasattr(li, "writes")
            assert hasattr(li, "mnemonic")
            assert hasattr(li, "operands")
            assert hasattr(li, "category")
            assert hasattr(li, "address")
            assert hasattr(li, "registers")
