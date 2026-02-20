"""
B58 — Byte-Level Taint + Implicit Flow Propagation tests.

Tests cover:
1. ByteTaintMap per-byte granularity
2. TaintTracker sub-register precision with byte-level map
3. Implicit flow scope: tainted conditional branches propagate CONTROL
4. Implicit flow scope termination on unconditional branch
5. Implicit flow disabled when depth=0
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace

from dragonslayer.analysis.taint_tracking.tracker import (
    ByteTaintMap,
    TaintTag,
    TaintTracker,
    subreg_info,
)


def _make_insn(
    mnemonic: str = "mov",
    operands: str = "",
    reads: list | None = None,
    writes: list | None = None,
    address: int = 0,
    category: str = "unknown",
):
    return SimpleNamespace(
        mnemonic=mnemonic,
        operands=operands,
        reads=reads or [],
        writes=writes or [],
        address=address,
        category=category,
        registers={},
    )


# ──────────────────────────────────────────────────────────────────────
# 1. ByteTaintMap standalone
# ──────────────────────────────────────────────────────────────────────

class TestByteTaintMap:
    def test_set_full_register(self):
        m = ByteTaintMap()
        m.set_bytes("rax", TaintTag.INPUT)
        assert m.get_bytes("rax") == TaintTag.INPUT
        assert m.get_bytes("eax") == TaintTag.INPUT
        assert m.get_bytes("al") == TaintTag.INPUT
        assert m.get_bytes("ah") == TaintTag.INPUT

    def test_set_al_only(self):
        m = ByteTaintMap()
        m.set_bytes("al", TaintTag.INPUT)
        # al covers byte 0 only
        assert m.get_bytes("al") == TaintTag.INPUT
        # ah is byte 1 — should be clean
        assert m.get_bytes("ah") == TaintTag.CLEAN
        # rax = OR of all 8 bytes → includes byte 0
        assert m.get_bytes("rax") == TaintTag.INPUT

    def test_set_ah_does_not_taint_al(self):
        m = ByteTaintMap()
        m.set_bytes("ah", TaintTag.VM_OPERAND)
        assert m.get_bytes("ah") == TaintTag.VM_OPERAND
        assert m.get_bytes("al") == TaintTag.CLEAN
        # ax includes both al and ah byte ranges
        assert m.get_bytes("ax") == TaintTag.VM_OPERAND

    def test_eax_zero_extends(self):
        m = ByteTaintMap()
        m.set_bytes("rax", TaintTag.INPUT)  # taint all 8 bytes
        m.set_bytes("eax", TaintTag.VM_CONTEXT)  # 32-bit write → zero-extend upper 32
        # Bytes 0-3 = VM_CONTEXT, bytes 4-7 = CLEAN (zero-extended)
        assert m.get_bytes("eax") == TaintTag.VM_CONTEXT
        # Upper half should be clean
        # rax = OR of all bytes; only bytes 0-3 should have VM_CONTEXT
        full = m.get_full("rax")
        assert TaintTag.INPUT not in full  # zeroed by 32-bit write
        assert full == TaintTag.VM_CONTEXT

    def test_clear_bytes_al(self):
        m = ByteTaintMap()
        m.set_bytes("rax", TaintTag.INPUT)
        m.clear_bytes("al")  # clear byte 0 only
        assert m.get_bytes("al") == TaintTag.CLEAN
        assert m.get_bytes("ah") == TaintTag.INPUT  # byte 1 still tainted

    def test_clear_full_register(self):
        m = ByteTaintMap()
        m.set_bytes("rax", TaintTag.INPUT)
        m.clear_bytes("rax")
        assert m.get_full("rax") == TaintTag.CLEAN

    def test_r8_family(self):
        m = ByteTaintMap()
        m.set_bytes("r8b", TaintTag.CRYPTO)
        assert m.get_bytes("r8b") == TaintTag.CRYPTO
        assert m.get_bytes("r8") == TaintTag.CRYPTO  # full reg includes byte 0

    def test_multiple_tags_per_register(self):
        m = ByteTaintMap()
        m.set_bytes("al", TaintTag.INPUT)
        m.set_bytes("ah", TaintTag.VM_OPERAND)
        # rax should OR both
        full = m.get_full("rax")
        assert TaintTag.INPUT in full
        assert TaintTag.VM_OPERAND in full

    def test_to_dict_empty(self):
        m = ByteTaintMap()
        assert m.to_dict() == {}

    def test_to_dict_with_taint(self):
        m = ByteTaintMap()
        m.set_bytes("al", TaintTag.INPUT)
        d = m.to_dict()
        assert "rax" in d
        assert len(d["rax"]) == 8

    def test_clear_all(self):
        m = ByteTaintMap()
        m.set_bytes("rax", TaintTag.INPUT)
        m.set_bytes("rbx", TaintTag.VM_OPERAND)
        m.clear()
        assert m.get_bytes("rax") == TaintTag.CLEAN
        assert m.get_bytes("rbx") == TaintTag.CLEAN


# ──────────────────────────────────────────────────────────────────────
# 2. TaintTracker byte-level precision
# ──────────────────────────────────────────────────────────────────────

class TestTrackerByteLevelPrecision:
    def test_taint_al_leaves_ah_clean(self):
        """Tainting al should not taint ah (byte-level precision)."""
        tracker = TaintTracker()
        tracker.taint_register("al", TaintTag.INPUT)
        # al should be tainted
        assert tracker.get_taint("al") == TaintTag.INPUT
        # ah should be clean (byte-level)
        assert tracker._byte_taint.get_bytes("ah") == TaintTag.CLEAN

    def test_taint_ah_then_check_al(self):
        tracker = TaintTracker()
        tracker.taint_register("ah", TaintTag.VM_OPERAND)
        assert tracker._byte_taint.get_bytes("ah") == TaintTag.VM_OPERAND
        assert tracker._byte_taint.get_bytes("al") == TaintTag.CLEAN

    def test_eax_write_clears_upper(self):
        """Writing eax with taint should zero-extend and clear upper bytes."""
        tracker = TaintTracker()
        tracker.taint_register("rax", TaintTag.INPUT)
        # Now write eax → zero-extends upper 32 bits
        tracker._propagate_subreg_taint("eax", TaintTag.VM_CONTEXT)
        # Bytes 0-3 = VM_CONTEXT, bytes 4-7 = CLEAN
        assert tracker._byte_taint.get_bytes("eax") == TaintTag.VM_CONTEXT
        # Full register should only have VM_CONTEXT (upper cleared)
        assert tracker._byte_taint.get_full("rax") == TaintTag.VM_CONTEXT

    def test_process_instruction_byte_level(self):
        """Processing an instruction with al read should taint al writes precisely."""
        tracker = TaintTracker()
        tracker.taint_register("al", TaintTag.INPUT)

        insn = _make_insn(
            mnemonic="mov",
            operands="bl, al",
            reads=["al"],
            writes=["bl"],
        )
        tracker.process_instruction(insn)

        # bl should be tainted
        assert tracker._byte_taint.get_bytes("bl") != TaintTag.CLEAN
        # bh should still be clean at byte level
        assert tracker._byte_taint.get_bytes("bh") == TaintTag.CLEAN


# ──────────────────────────────────────────────────────────────────────
# 3. Implicit flow scope
# ──────────────────────────────────────────────────────────────────────

class TestImplicitFlowScope:
    def test_tainted_branch_starts_scope(self):
        """A tainted conditional branch should start an implicit-flow scope."""
        tracker = TaintTracker(implicit_flow_depth=8)
        tracker.taint_register("eflags", TaintTag.INPUT)  # taint the condition

        branch = _make_insn(
            mnemonic="jne",
            operands="0x401000",
            reads=["eflags"],
            writes=[],
            category="branch_conditional",
            address=0x400000,
        )
        tracker.process_instruction(branch)

        assert tracker._implicit_scope_remaining == 8
        assert TaintTag.CONTROL in tracker._implicit_scope_tag

    def test_implicit_scope_taints_subsequent_writes(self):
        """Writes inside an implicit-flow scope should inherit CONTROL taint."""
        tracker = TaintTracker(implicit_flow_depth=4)
        tracker.taint_register("eflags", TaintTag.INPUT)

        branch = _make_insn(
            mnemonic="je", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)

        # Next instruction: clean write that should get CONTROL taint
        clean_mov = _make_insn(
            mnemonic="mov", operands="rax, 42",
            reads=[], writes=["rax"],
        )
        tracker.process_instruction(clean_mov)

        # rax should have CONTROL taint from implicit scope
        tag = tracker.get_taint("rax")
        assert TaintTag.CONTROL in tag

    def test_implicit_scope_decrements(self):
        """Scope counter should decrement each instruction."""
        tracker = TaintTracker(implicit_flow_depth=3)
        tracker.taint_register("eflags", TaintTag.INPUT)

        branch = _make_insn(
            mnemonic="jne", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)
        assert tracker._implicit_scope_remaining == 3

        for i in range(3):
            insn = _make_insn(mnemonic="nop", reads=[], writes=[])
            tracker.process_instruction(insn)
        assert tracker._implicit_scope_remaining == 0

    def test_unconditional_branch_ends_scope(self):
        """An unconditional branch should end the implicit scope early."""
        tracker = TaintTracker(implicit_flow_depth=10)
        tracker.taint_register("eflags", TaintTag.INPUT)

        branch = _make_insn(
            mnemonic="je", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)
        assert tracker._implicit_scope_remaining == 10

        jmp = _make_insn(
            mnemonic="jmp", operands="0x402000",
            reads=[], writes=[], category="branch_unconditional",
        )
        tracker.process_instruction(jmp)
        assert tracker._implicit_scope_remaining == 0

    def test_no_scope_after_clean_branch(self):
        """A clean conditional branch should NOT start an implicit scope."""
        tracker = TaintTracker(implicit_flow_depth=8)
        # eflags are clean

        branch = _make_insn(
            mnemonic="jne", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)
        assert tracker._implicit_scope_remaining == 0

    def test_implicit_depth_zero_disables(self):
        """With implicit_flow_depth=0, no implicit scope is created."""
        tracker = TaintTracker(implicit_flow_depth=0)
        tracker.taint_register("eflags", TaintTag.INPUT)

        branch = _make_insn(
            mnemonic="je", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)
        assert tracker._implicit_scope_remaining == 0

    def test_implicit_events_recorded(self):
        """Implicit flow events should be recorded for writes in scope."""
        tracker = TaintTracker(implicit_flow_depth=4)
        tracker.taint_register("eflags", TaintTag.INPUT)

        branch = _make_insn(
            mnemonic="je", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)

        mov = _make_insn(
            mnemonic="mov", operands="rcx, 0",
            reads=[], writes=["rcx"],
        )
        tracker.process_instruction(mov)

        # Check that an implicit event was recorded
        implicit_events = [
            e for e in tracker._events
            if e.event_type == "implicit" and e.destination != "control_flow"
        ]
        assert len(implicit_events) >= 1
        assert implicit_events[0].destination == "rcx"

    def test_full_analyze_with_implicit_flow(self):
        """analyze() should correctly return results with implicit flow."""
        tracker = TaintTracker(implicit_flow_depth=4)
        tracker.taint_register("rdi", TaintTag.VM_CONTEXT)

        instructions = [
            _make_insn(mnemonic="cmp", operands="rdi, 0",
                       reads=["rdi"], writes=[], category="comparison"),
            _make_insn(mnemonic="je", operands="0x401000",
                       reads=["eflags"], writes=[], category="branch_conditional"),
            _make_insn(mnemonic="mov", operands="rax, 1",
                       reads=[], writes=["rax"]),
            _make_insn(mnemonic="mov", operands="rbx, 2",
                       reads=[], writes=["rbx"]),
        ]

        result = tracker.analyze(instructions)
        assert result.success
        # rax and rbx should be tainted via implicit flow
        assert "rax" in result.tainted_registers
        assert "rbx" in result.tainted_registers

    def test_reset_clears_implicit_scope(self):
        """reset() should clear the implicit scope state."""
        tracker = TaintTracker(implicit_flow_depth=8)
        tracker._implicit_scope_remaining = 5
        tracker._implicit_scope_tag = TaintTag.CONTROL
        tracker.reset()
        assert tracker._implicit_scope_remaining == 0
        assert tracker._implicit_scope_tag == TaintTag.CLEAN


# ──────────────────────────────────────────────────────────────────────
# 4. Integration: byte-level + implicit flow
# ──────────────────────────────────────────────────────────────────────

class TestByteLevelImplicitIntegration:
    def test_byte_level_through_implicit_scope(self):
        """Implicit scope should apply byte-level taint correctly."""
        tracker = TaintTracker(implicit_flow_depth=4)
        tracker.taint_register("eflags", TaintTag.INPUT)

        branch = _make_insn(
            mnemonic="jne", operands="0x401000",
            reads=["eflags"], writes=[], category="branch_conditional",
        )
        tracker.process_instruction(branch)

        # Write to al in implicit scope
        mov_al = _make_insn(
            mnemonic="mov", operands="al, 0",
            reads=[], writes=["al"],
        )
        tracker.process_instruction(mov_al)

        # al should have CONTROL taint
        assert TaintTag.CONTROL in tracker._byte_taint.get_bytes("al")

    def test_subreg_info_available(self):
        """Verify subreg_info is consistent for key registers."""
        info = subreg_info("al")
        assert info is not None
        assert info[0] == "rax"  # canonical
        assert info[1] == 0     # bit_lo
        assert info[2] == 8     # width

        info_ah = subreg_info("ah")
        assert info_ah is not None
        assert info_ah[0] == "rax"
        assert info_ah[1] == 8   # bit_lo
        assert info_ah[2] == 8   # width
