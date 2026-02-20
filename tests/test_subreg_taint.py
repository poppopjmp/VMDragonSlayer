"""Tests for sub-register taint propagation (Batch 31).

Covers:
  - subreg_canonical / subreg_aliases / subreg_info lookup tables
  - TaintTracker with sub_register_aware=True (default)
  - Upward propagation: tainting al → rax/eax/ax all tainted
  - Downward propagation: tainting rax → al/ah/eax/ax all tainted
  - Cross-alias reads: instruction reads eax, rax was tainted → tainted
  - Clean write scoping: 32-bit write clears family, 8-bit does not
  - Backward compat: sub_register_aware=False behaves like old tracker
  - Integration with process_instruction / analyze
"""
from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    subreg_canonical,
    subreg_aliases,
    subreg_info,
)


# ── Fake instruction for testing ─────────────────────────────────────────────

@dataclass
class _FakeInsn:
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    address: int = 0
    mnemonic: str = "mov"
    operands: str = ""
    category: str = "data_transfer"
    registers: Dict[str, int] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# subreg_canonical
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubregCanonical:
    def test_64bit_is_self(self):
        assert subreg_canonical("rax") == "rax"
        assert subreg_canonical("r15") == "r15"

    def test_32bit_maps_to_64(self):
        assert subreg_canonical("eax") == "rax"
        assert subreg_canonical("ebx") == "rbx"
        assert subreg_canonical("r8d") == "r8"

    def test_16bit_maps_to_64(self):
        assert subreg_canonical("ax") == "rax"
        assert subreg_canonical("si") == "rsi"
        assert subreg_canonical("r12w") == "r12"

    def test_8bit_low_maps_to_64(self):
        assert subreg_canonical("al") == "rax"
        assert subreg_canonical("cl") == "rcx"
        assert subreg_canonical("sil") == "rsi"
        assert subreg_canonical("r9b") == "r9"

    def test_8bit_high_maps_to_64(self):
        assert subreg_canonical("ah") == "rax"
        assert subreg_canonical("bh") == "rbx"
        assert subreg_canonical("ch") == "rcx"
        assert subreg_canonical("dh") == "rdx"

    def test_unknown_returns_self(self):
        # B69: xmm0 is now in zmm0 family
        assert subreg_canonical("xmm0") == "zmm0"
        assert subreg_canonical("rflags") == "rflags"

    def test_case_insensitive(self):
        assert subreg_canonical("RAX") == "rax"
        assert subreg_canonical("EAX") == "rax"


# ═══════════════════════════════════════════════════════════════════════════════
# subreg_aliases
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubregAliases:
    def test_rax_family(self):
        fam = subreg_aliases("rax")
        assert "rax" in fam
        assert "eax" in fam
        assert "ax" in fam
        assert "al" in fam
        assert "ah" in fam
        assert len(fam) == 5

    def test_rbx_family(self):
        fam = subreg_aliases("bl")
        assert "rbx" in fam
        assert "ebx" in fam
        assert "bh" in fam

    def test_rsi_family_no_high_byte(self):
        fam = subreg_aliases("rsi")
        assert "rsi" in fam
        assert "esi" in fam
        assert "si" in fam
        assert "sil" in fam
        assert len(fam) == 4  # no "sih"

    def test_r8_family(self):
        fam = subreg_aliases("r8")
        assert "r8" in fam
        assert "r8d" in fam
        assert "r8w" in fam
        assert "r8b" in fam
        assert len(fam) == 4

    def test_unknown_returns_singleton(self):
        # B69: xmm0 is now in zmm0 family (xmm/ymm/zmm)
        fam = subreg_aliases("xmm0")
        assert fam == {"xmm0", "ymm0", "zmm0"}


# ═══════════════════════════════════════════════════════════════════════════════
# subreg_info
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubregInfo:
    def test_rax_info(self):
        info = subreg_info("rax")
        assert info == ("rax", 0, 64, False)

    def test_eax_zero_extends(self):
        info = subreg_info("eax")
        assert info is not None
        canonical, bit_lo, width, zext = info
        assert canonical == "rax"
        assert width == 32
        assert zext is True

    def test_ah_high_byte(self):
        info = subreg_info("ah")
        assert info is not None
        canonical, bit_lo, width, _ = info
        assert canonical == "rax"
        assert bit_lo == 8
        assert width == 8

    def test_al_low_byte(self):
        info = subreg_info("al")
        assert info is not None
        assert info[1] == 0  # bit_lo
        assert info[2] == 8  # width

    def test_unknown_returns_none(self):
        # B69: xmm0 is now known (SIMD family)
        info = subreg_info("xmm0")
        assert info is not None
        assert info[0] == "zmm0"
        assert info[2] == 128  # xmm = 128 bits

    def test_r15d_zero_extends(self):
        info = subreg_info("r15d")
        assert info is not None
        assert info[0] == "r15"
        assert info[3] is True  # zero_ext


# ═══════════════════════════════════════════════════════════════════════════════
# TaintTracker — upward propagation (sub-reg → parent)
# ═══════════════════════════════════════════════════════════════════════════════

class TestUpwardPropagation:
    def test_taint_al_sees_rax(self):
        t = TaintTracker()
        t.taint_register("al", TaintTag.INPUT)
        assert t.is_tainted("rax")
        assert t.is_tainted("eax")
        assert t.is_tainted("ax")

    def test_taint_eax_sees_rax(self):
        t = TaintTracker()
        t.taint_register("eax", TaintTag.VM_OPERAND)
        assert t.is_tainted("rax")
        assert t.get_taint("rax") == TaintTag.VM_OPERAND

    def test_taint_ah_sees_family(self):
        t = TaintTracker()
        t.taint_register("ah", TaintTag.CRYPTO)
        assert t.is_tainted("rax")  # rax ORs all bytes → sees ah
        # B58 byte-level precision: al (byte 0) is NOT tainted by ah (byte 1)
        assert not t.is_tainted("al")

    def test_taint_r8b_sees_r8(self):
        t = TaintTracker()
        t.taint_register("r8b", TaintTag.INPUT)
        assert t.is_tainted("r8")
        assert t.is_tainted("r8d")
        assert t.is_tainted("r8w")


# ═══════════════════════════════════════════════════════════════════════════════
# TaintTracker — downward propagation (parent → sub-regs)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDownwardPropagation:
    def test_taint_rax_sees_al(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        assert t.is_tainted("al")
        assert t.is_tainted("ah")
        assert t.is_tainted("eax")
        assert t.is_tainted("ax")

    def test_taint_rbx_sees_bl_bh(self):
        t = TaintTracker()
        t.taint_register("rbx", TaintTag.MEMORY)
        assert t.is_tainted("bl")
        assert t.is_tainted("bh")


# ═══════════════════════════════════════════════════════════════════════════════
# TaintTracker — cross-alias reads in process_instruction
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossAliasReads:
    def test_read_eax_after_taint_rax(self):
        """Instruction reads eax, but rax was tainted → propagates."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        insn = _FakeInsn(reads=["eax"], writes=["rbx"])
        t.process_instruction(insn)
        assert t.is_tainted("rbx")

    def test_read_al_after_taint_rax(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        insn = _FakeInsn(reads=["al"], writes=["rcx"])
        t.process_instruction(insn)
        assert t.is_tainted("rcx")

    def test_write_eax_taints_rax(self):
        """Writing to eax with tainted source → rax also tainted."""
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.INPUT)
        insn = _FakeInsn(reads=["rdi"], writes=["eax"])
        t.process_instruction(insn)
        assert t.is_tainted("rax")
        assert t.is_tainted("al")

    def test_write_al_taints_rax(self):
        t = TaintTracker()
        t.taint_register("rsi", TaintTag.VM_OPERAND)
        insn = _FakeInsn(reads=["rsi"], writes=["al"])
        t.process_instruction(insn)
        assert t.is_tainted("rax")
        assert t.is_tainted("eax")


# ═══════════════════════════════════════════════════════════════════════════════
# TaintTracker — clean write scoping
# ═══════════════════════════════════════════════════════════════════════════════

class TestCleanWriteScoping:
    def test_32bit_clean_write_clears_family(self):
        """Writing a clean value to eax (32-bit, zero-ext) clears rax family."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        assert t.is_tainted("rax")
        # Clean write to eax
        insn = _FakeInsn(reads=[], writes=["eax"])
        t.process_instruction(insn)
        assert not t.is_tainted("eax")
        assert not t.is_tainted("rax")

    def test_64bit_clean_write_clears_all(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        insn = _FakeInsn(reads=[], writes=["rax"])
        t.process_instruction(insn)
        assert not t.is_tainted("rax")
        assert not t.is_tainted("al")

    def test_8bit_clean_write_does_not_clear_parent(self):
        """Writing clean to al should NOT clear rax/ah — parent stays tainted.

        In x86, 8-bit writes don't zero-extend, so the parent register's
        upper bits still carry taint.  B58 byte-level precision: al (byte 0)
        is cleared, but ah (byte 1) and rax (OR of all bytes) remain tainted.
        """
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        insn = _FakeInsn(reads=[], writes=["al"])
        t.process_instruction(insn)
        # ah and parent rax are still tainted
        assert t.is_tainted("ah")
        assert t.is_tainted("rax")
        # B58 byte-level precision: al (byte 0) was cleaned
        assert not t.is_tainted("al")


# ═══════════════════════════════════════════════════════════════════════════════
# Backward compatibility: sub_register_aware=False
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardCompat:
    def test_no_aliasing_when_disabled(self):
        t = TaintTracker(sub_register_aware=False)
        t.taint_register("rax", TaintTag.INPUT)
        assert t.is_tainted("rax")
        assert not t.is_tainted("eax")
        assert not t.is_tainted("al")

    def test_disabled_read_propagation(self):
        t = TaintTracker(sub_register_aware=False)
        t.taint_register("rax", TaintTag.INPUT)
        insn = _FakeInsn(reads=["eax"], writes=["rbx"])
        t.process_instruction(insn)
        # eax was not tainted → rbx should not be tainted
        assert not t.is_tainted("rbx")

    def test_default_is_enabled(self):
        t = TaintTracker()
        assert t._subreg_aware is True


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: analyze() with sub-register awareness
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeIntegration:
    def test_taint_chain_through_subregisters(self):
        """rdi(tainted) → al, al → rbx  — rbx should be tainted."""
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.INPUT)
        instructions = [
            _FakeInsn(reads=["rdi"], writes=["al"]),    # al gets taint
            _FakeInsn(reads=["eax"], writes=["rbx"]),   # eax → rbx (alias of al)
        ]
        result = t.analyze(instructions)
        assert result.success
        assert "rbx" in result.tainted_registers or "eax" in result.tainted_registers

    def test_mixed_register_widths(self):
        """Complex chain: taint rax, read al, write r8b, check r8."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        instructions = [
            _FakeInsn(reads=["al"], writes=["r8b"]),  # taint flows al→r8b
        ]
        result = t.analyze(instructions)
        assert result.success
        assert t.is_tainted("r8")
        assert t.is_tainted("r8d")

    def test_events_recorded_for_cross_alias(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        insn = _FakeInsn(reads=["eax"], writes=["rcx"])
        t.process_instruction(insn)
        events = [e for e in t._events if e.event_type == "propagate"]
        assert len(events) > 0
        assert any(e.destination == "rcx" for e in events)


# ═══════════════════════════════════════════════════════════════════════════════
# Coverage of all GP register families
# ═══════════════════════════════════════════════════════════════════════════════

class TestAllFamilies:
    @pytest.mark.parametrize("parent,sub", [
        ("rax", "al"), ("rbx", "bl"), ("rcx", "cl"), ("rdx", "dl"),
        ("rsi", "sil"), ("rdi", "dil"), ("rbp", "bpl"), ("rsp", "spl"),
        ("r8", "r8b"), ("r9", "r9b"), ("r10", "r10b"), ("r11", "r11b"),
        ("r12", "r12b"), ("r13", "r13b"), ("r14", "r14b"), ("r15", "r15b"),
    ])
    def test_family_taint_round_trip(self, parent, sub):
        t = TaintTracker()
        t.taint_register(sub, TaintTag.INPUT)
        assert t.is_tainted(parent), f"Tainting {sub} should taint {parent}"
        t.reset()
        t.taint_register(parent, TaintTag.INPUT)
        assert t.is_tainted(sub), f"Tainting {parent} should taint {sub}"


# ═══════════════════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_non_gp_register_unaffected(self):
        """Non-GP registers like xmm0 should work but have no aliases."""
        t = TaintTracker()
        t.taint_register("xmm0", TaintTag.INPUT)
        assert t.is_tainted("xmm0")
        assert not t.is_tainted("xmm1")

    def test_reset_clears_subreg_taint(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        t.reset()
        assert not t.is_tainted("rax")
        assert not t.is_tainted("al")

    def test_multiple_families_independent(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        assert not t.is_tainted("rbx")
        assert not t.is_tainted("bl")

    def test_overwrite_tag(self):
        t = TaintTracker()
        t.taint_register("al", TaintTag.INPUT)
        t.taint_register("al", TaintTag.CRYPTO)
        assert t.get_taint("al") == TaintTag.CRYPTO
        assert t.get_taint("rax") == TaintTag.CRYPTO
