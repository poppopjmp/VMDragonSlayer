"""
Tests for Batch 28 -- Obfuscated Dispatcher Variants
====================================================

Validates that the dispatcher recogniser detects push+ret, call-based,
and computed-goto dispatch styles in addition to the classic jmp pattern.
"""

from __future__ import annotations

import pytest
from dataclasses import dataclass
from typing import Optional

from dragonslayer.analysis.vm_discovery.dispatcher import (
    find_vmprotect_dispatcher,
    VMProtectDispatcherMatch,
    _find_dispatch_candidates,
)


# ---------------------------------------------------------------------------
# Helper: build a lightweight instruction-like object for tests
# ---------------------------------------------------------------------------

@dataclass
class _FakeInsn:
    """Lightweight instruction stub.

    The dispatcher accessor ``_get_operands_raw`` returns ``insn.operands``
    which must be a **raw string** (e.g. ``"rax, [rbx+rcx*8]"``), not a list.
    """
    address: int = 0
    mnemonic: str = ""
    operands: str = ""          # raw operand string, comma-separated
    raw_bytes: bytes = b"\x90"
    size: int = 1
    branch_target: Optional[int] = None


GP_REGS_64 = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}


# ===================================================================
# 1. Classic jmp-based dispatch (regression)
# ===================================================================

class TestClassicJmpDispatch:
    """Ensure the classic jmp pattern still works after refactoring."""

    def test_jmp_reg_detected(self):
        insns = [
            _FakeInsn(address=0x1000, mnemonic="jmp", operands="rax"),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        assert len(candidates) >= 1
        assert candidates[0].dispatch_style == "jmp"
        assert candidates[0].target_reg == "rax"

    def test_jmp_mem_detected(self):
        insns = [
            _FakeInsn(address=0x1000, mnemonic="jmp",
                      operands="[rbx+rcx*8]"),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        assert len(candidates) >= 1
        assert candidates[0].dispatch_style == "jmp"
        assert candidates[0].uses_memory is True


# ===================================================================
# 2. Push+ret dispatch
# ===================================================================

class TestPushRetDispatch:
    """VMProtect v2-style dispatch: push handler_addr; ret."""

    def test_push_ret_detected(self):
        insns = [
            _FakeInsn(address=0x2000, mnemonic="push", operands="rax"),
            _FakeInsn(address=0x2001, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        push_ret = [c for c in candidates if c.dispatch_style == "push_ret"]
        assert len(push_ret) >= 1
        assert push_ret[0].target_reg == "rax"

    def test_push_ret_with_nop_padding(self):
        """push rcx; nop; ret  -- the nop should be skipped."""
        insns = [
            _FakeInsn(address=0x3000, mnemonic="push", operands="rcx"),
            _FakeInsn(address=0x3001, mnemonic="nop", operands=""),
            _FakeInsn(address=0x3002, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        push_ret = [c for c in candidates if c.dispatch_style == "push_ret"]
        assert len(push_ret) >= 1
        assert push_ret[0].target_reg == "rcx"

    def test_push_imm_not_detected(self):
        """push 0x401000; ret -- immediate, not a register -> skip."""
        insns = [
            _FakeInsn(address=0x4000, mnemonic="push", operands="0x401000"),
            _FakeInsn(address=0x4005, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        push_ret = [c for c in candidates if c.dispatch_style == "push_ret"]
        assert len(push_ret) == 0


# ===================================================================
# 3. Call-based dispatch
# ===================================================================

class TestCallDispatch:
    """Dispatch via indirect call: call reg or call [mem]."""

    def test_call_reg_detected(self):
        insns = [
            _FakeInsn(address=0x5000, mnemonic="call", operands="rdx"),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        call = [c for c in candidates if c.dispatch_style == "call"]
        assert len(call) >= 1
        assert call[0].target_reg == "rdx"

    def test_call_mem_detected(self):
        insns = [
            _FakeInsn(address=0x5000, mnemonic="call",
                      operands="[rbx+rsi*4]"),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        call = [c for c in candidates if c.dispatch_style == "call"]
        assert len(call) >= 1
        assert call[0].uses_memory is True

    def test_call_imm_not_detected(self):
        """call 0x401000 -- direct call, not a register -> skip."""
        insns = [
            _FakeInsn(address=0x5000, mnemonic="call", operands="0x401000"),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        call = [c for c in candidates if c.dispatch_style == "call"]
        assert len(call) == 0


# ===================================================================
# 4. Computed goto (xchg [rsp], reg; ret)
# ===================================================================

class TestComputedGotoDispatch:
    """Stack-based dispatch: xchg [rsp], reg; ret  or  mov [rsp], reg; ret."""

    def test_xchg_rsp_ret_detected(self):
        insns = [
            _FakeInsn(address=0x6000, mnemonic="xchg",
                      operands="[rsp], rax"),
            _FakeInsn(address=0x6004, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        cg = [c for c in candidates if c.dispatch_style == "computed_goto"]
        assert len(cg) >= 1
        assert cg[0].target_reg == "rax"

    def test_mov_rsp_ret_detected(self):
        insns = [
            _FakeInsn(address=0x7000, mnemonic="mov",
                      operands="[rsp], r11"),
            _FakeInsn(address=0x7004, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        cg = [c for c in candidates if c.dispatch_style == "computed_goto"]
        assert len(cg) >= 1
        assert cg[0].target_reg == "r11"

    def test_mov_not_rsp_no_match(self):
        """mov [rbx], rax; ret -- destination is not [rsp] -> no computed_goto."""
        insns = [
            _FakeInsn(address=0x8000, mnemonic="mov", operands="[rbx], rax"),
            _FakeInsn(address=0x8004, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        cg = [c for c in candidates if c.dispatch_style == "computed_goto"]
        assert len(cg) == 0


# ===================================================================
# 5. Full dispatcher identification with obfuscated styles
# ===================================================================

class TestFullDispatcherWithStyles:
    """End-to-end: find_vmprotect_dispatcher with push+ret dispatch."""

    def _build_push_ret_dispatcher(self):
        """Build a minimal VMProtect-like dispatcher using push+ret."""
        return [
            # Fetch: movzx ecx, byte ptr [rsi]
            _FakeInsn(address=0x1000, mnemonic="movzx",
                      operands="ecx, byte ptr [rsi]"),
            # Advance: inc rsi
            _FakeInsn(address=0x1003, mnemonic="inc", operands="rsi"),
            # Decode: xor ecx, 0x3F
            _FakeInsn(address=0x1006, mnemonic="xor", operands="ecx, 0x3F"),
            # Table lookup: mov rax, [rbx+rcx*8]
            _FakeInsn(address=0x1009, mnemonic="mov",
                      operands="rax, [rbx+rcx*8]"),
            # Dispatch: push rax; ret
            _FakeInsn(address=0x100D, mnemonic="push", operands="rax"),
            _FakeInsn(address=0x100E, mnemonic="ret", operands=""),
        ]

    def test_push_ret_dispatcher_found(self):
        insns = self._build_push_ret_dispatcher()
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.confidence > 0.3
        assert result.dispatch_style == "push_ret"

    def test_push_ret_dispatcher_vip(self):
        insns = self._build_push_ret_dispatcher()
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.vip_register == "rsi"

    def _build_call_dispatcher(self):
        """Dispatcher using 'call rax' instead of jmp."""
        return [
            _FakeInsn(address=0x2000, mnemonic="movzx",
                      operands="ecx, byte ptr [rdi]"),
            _FakeInsn(address=0x2003, mnemonic="add", operands="rdi, 1"),
            _FakeInsn(address=0x2007, mnemonic="mov",
                      operands="rax, [rbx+rcx*8]"),
            _FakeInsn(address=0x200B, mnemonic="call", operands="rax"),
        ]

    def test_call_dispatcher_found(self):
        insns = self._build_call_dispatcher()
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.confidence > 0.3
        assert result.dispatch_style == "call"


# ===================================================================
# 6. dispatch_style in VMProtectDispatcherMatch
# ===================================================================

class TestDispatchStyleField:
    def test_default_style_is_jmp(self):
        m = VMProtectDispatcherMatch()
        assert m.dispatch_style == "jmp"

    def test_to_dict_includes_style(self):
        m = VMProtectDispatcherMatch(dispatch_style="push_ret")
        d = m.to_dict()
        assert d["dispatch_style"] == "push_ret"

    def test_all_styles_valid(self):
        for style in ("jmp", "push_ret", "call", "computed_goto"):
            m = VMProtectDispatcherMatch(dispatch_style=style)
            assert m.dispatch_style == style


# ===================================================================
# 7. Mixed styles in same instruction stream
# ===================================================================

class TestMixedStyleCandidates:
    def test_multiple_styles_detected(self):
        """A stream with both jmp and push+ret should yield both candidates."""
        insns = [
            _FakeInsn(address=0xA000, mnemonic="jmp", operands="rax"),
            _FakeInsn(address=0xA004, mnemonic="push", operands="rcx"),
            _FakeInsn(address=0xA005, mnemonic="ret", operands=""),
        ]
        candidates = _find_dispatch_candidates(insns, GP_REGS_64)
        styles = {c.dispatch_style for c in candidates}
        assert "jmp" in styles
        assert "push_ret" in styles


# ===================================================================
# 8. Confidence bonus for obfuscated styles
# ===================================================================

class TestConfidenceBonus:
    def test_push_ret_higher_confidence_than_jmp_equivalent(self):
        """Two identical dispatchers, one uses push+ret -- should score
        higher due to the obfuscation bonus.
        """
        base_insns = [
            _FakeInsn(address=0xB000, mnemonic="movzx",
                      operands="ecx, byte ptr [rsi]"),
            _FakeInsn(address=0xB003, mnemonic="inc", operands="rsi"),
        ]
        jmp_insns = base_insns + [
            _FakeInsn(address=0xB006, mnemonic="jmp", operands="rcx"),
        ]
        push_ret_insns = base_insns + [
            _FakeInsn(address=0xB006, mnemonic="push", operands="rcx"),
            _FakeInsn(address=0xB007, mnemonic="ret", operands=""),
        ]
        r_jmp = find_vmprotect_dispatcher(jmp_insns, bit_width=64)
        r_pr = find_vmprotect_dispatcher(push_ret_insns, bit_width=64)
        # Both should be found
        assert r_jmp is not None
        assert r_pr is not None
        # push+ret should have >= confidence due to obfuscation bonus
        assert r_pr.confidence >= r_jmp.confidence
