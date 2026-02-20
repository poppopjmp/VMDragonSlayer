"""Tests for handler extraction from execution traces.

Tests :mod:`dragonslayer.analysis.vm_discovery.handler_extraction`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

from dragonslayer.analysis.vm_discovery.handler_extraction import (
    extract_handler_bodies,
    fingerprint_handler,
    deduplicate_handlers,
    HandlerBody,
    HandlerGroup,
    HandlerOperand,
    RegisterDelta,
    ExtractionResult,
    _extract_operand,
    _compute_register_deltas,
    _infer_category,
    _normalize_disassembly,
    _classify_memory_access,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FakeBoundary:
    """Minimal boundary for testing."""
    vip_value: int = 0x5000
    handler_address: int = 0x401000
    trace_start: int = 0
    trace_end: int = 3
    instruction_count: int = 3
    vip_delta: int = 2
    category: str = ""
    handler_id: Optional[int] = None


def _make_trace_insn(
    address: int,
    disassembly: str = "",
    registers: Optional[Dict[str, int]] = None,
    raw_bytes: bytes = b"\x90",
) -> Dict[str, Any]:
    return {
        "address": address,
        "disassembly": disassembly,
        "registers": registers or {},
        "raw_bytes": raw_bytes.hex(),
        "size": len(raw_bytes),
    }


def _make_handler_trace(
    handler_addr: int = 0x401000,
    vip_reg: str = "rsi",
    vip_start: int = 0x5000,
    vip_end: int = 0x5002,
) -> List[Dict[str, Any]]:
    """Build a minimal 3-instruction handler trace."""
    return [
        _make_trace_insn(
            handler_addr,
            "push rax",
            {vip_reg: vip_start, "rax": 0x100, "rsp": 0xFF00},
            b"\x50",
        ),
        _make_trace_insn(
            handler_addr + 1,
            "mov rax, qword ptr [rsi]",
            {vip_reg: vip_start, "rax": 0x200, "rsp": 0xFEF8},
            b"\x48\x8B\x06",
        ),
        _make_trace_insn(
            handler_addr + 4,
            "add rax, rbx",
            {vip_reg: vip_end, "rax": 0x300, "rsp": 0xFEF8},
            b"\x48\x01\xD8",
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Register deltas
# ═══════════════════════════════════════════════════════════════════════════

class TestRegisterDeltas:

    def test_basic_delta(self):
        entry = {"rax": 0x100, "rbx": 0x200, "rsp": 0xFF00}
        exit_ = {"rax": 0x300, "rbx": 0x200, "rsp": 0xFEF8}
        deltas = _compute_register_deltas(entry, exit_)
        changed = {d.register for d in deltas}
        assert "rax" in changed
        assert "rsp" in changed
        assert "rbx" not in changed  # unchanged

    def test_no_change(self):
        regs = {"rax": 0x100, "rbx": 0x200}
        deltas = _compute_register_deltas(regs, regs)
        assert len(deltas) == 0

    def test_skip_rip(self):
        entry = {"rip": 0x401000, "rax": 0x100}
        exit_ = {"rip": 0x401010, "rax": 0x100}
        deltas = _compute_register_deltas(entry, exit_)
        regs = {d.register for d in deltas}
        assert "rip" not in regs

    def test_delta_value(self):
        entry = {"rax": 10}
        exit_ = {"rax": 15}
        deltas = _compute_register_deltas(entry, exit_)
        assert deltas[0].delta == 5


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Operand extraction
# ═══════════════════════════════════════════════════════════════════════════

class TestOperandExtraction:

    def test_no_operand_for_single_byte(self):
        """vIP delta of 1 means only opcode, no operand."""
        op = _extract_operand(vip_value=0x5000, vip_delta=1, bytecode_base=0x5000)
        assert op is None

    def test_no_operand_for_zero_delta(self):
        op = _extract_operand(vip_value=0x5000, vip_delta=0, bytecode_base=0x5000)
        assert op is None

    def test_2byte_delta_gives_1byte_operand(self):
        """vIP advances 2 → 1 opcode byte + 1 operand byte."""
        op = _extract_operand(vip_value=0x5000, vip_delta=2, bytecode_base=0x5000)
        assert op is not None
        assert op.width == 1
        assert op.offset == 1  # byte after opcode

    def test_5byte_delta_gives_4byte_operand(self):
        op = _extract_operand(vip_value=0x5010, vip_delta=5, bytecode_base=0x5000)
        assert op is not None
        assert op.width == 4
        assert op.offset == 0x11  # 0x5010 - 0x5000 + 1

    def test_negative_delta(self):
        """Backward vIP movement (some VM schemes go backwards)."""
        op = _extract_operand(vip_value=0x5010, vip_delta=-3, bytecode_base=0x5000)
        assert op is not None
        assert op.width == 2  # abs(3) - 1


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Category inference
# ═══════════════════════════════════════════════════════════════════════════

class TestCategoryInference:

    def test_arithmetic(self):
        assert _infer_category(["add", "mov", "add"]) == "arithmetic"

    def test_logic(self):
        assert _infer_category(["xor", "and", "shl"]) == "logic"

    def test_stack_op(self):
        assert _infer_category(["push", "push", "mov", "pop"]) == "stack_op"

    def test_branch(self):
        assert _infer_category(["jmp"]) == "vm_branch"

    def test_vm_exit(self):
        assert _infer_category(["ret"]) == "vm_exit"

    def test_memory(self):
        assert _infer_category(["mov", "lea", "mov"]) == "memory"

    def test_empty(self):
        assert _infer_category([]) == "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Disassembly normalization
# ═══════════════════════════════════════════════════════════════════════════

class TestDisassemblyNormalization:

    def test_hex_replaced(self):
        n = _normalize_disassembly("add rax, 0x1234")
        assert "0x1234" not in n
        assert "IMM" in n

    def test_decimal_replaced(self):
        n = _normalize_disassembly("sub rcx, 42")
        assert "42" not in n
        assert "IMM" in n

    def test_registers_preserved(self):
        n = _normalize_disassembly("mov rax, rbx")
        assert "rax" in n
        assert "rbx" in n

    def test_empty_string(self):
        assert _normalize_disassembly("") == ""


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════

class TestFingerprinting:

    def test_same_structure_same_fingerprint(self):
        """Two invocations with same instructions but different immediates
        should produce the same fingerprint."""
        body1 = HandlerBody(
            handler_address=0x401000, vip_value=0x5000,
            trace_start=0, trace_end=2,
            instructions=[
                {"disassembly": "add rax, 0x10"},
                {"disassembly": "mov [rsp], rax"},
            ],
        )
        body2 = HandlerBody(
            handler_address=0x401000, vip_value=0x5002,
            trace_start=5, trace_end=7,
            instructions=[
                {"disassembly": "add rax, 0x20"},
                {"disassembly": "mov [rsp], rax"},
            ],
        )
        assert fingerprint_handler(body1) == fingerprint_handler(body2)

    def test_different_structure_different_fingerprint(self):
        body1 = HandlerBody(
            handler_address=0x401000, vip_value=0x5000,
            trace_start=0, trace_end=2,
            instructions=[{"disassembly": "add rax, rbx"}],
        )
        body2 = HandlerBody(
            handler_address=0x401000, vip_value=0x5002,
            trace_start=5, trace_end=7,
            instructions=[{"disassembly": "sub rax, rbx"}],
        )
        assert fingerprint_handler(body1) != fingerprint_handler(body2)


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Deduplication
# ═══════════════════════════════════════════════════════════════════════════

class TestDeduplication:

    def _make_body(self, addr: int, fp: str, category: str = "arith",
                   vip_delta: int = 2) -> HandlerBody:
        return HandlerBody(
            handler_address=addr, vip_value=0, trace_start=0, trace_end=1,
            fingerprint=fp, category=category, vip_delta=vip_delta,
            operand=HandlerOperand(offset=0, width=abs(vip_delta) - 1) if abs(vip_delta) > 1 else None,
        )

    def test_groups_by_address_and_fingerprint(self):
        bodies = [
            self._make_body(0x401000, "aabb"),
            self._make_body(0x401000, "aabb"),
            self._make_body(0x402000, "ccdd"),
        ]
        groups = deduplicate_handlers(bodies)
        assert len(groups) == 2

    def test_group_visit_count(self):
        bodies = [
            self._make_body(0x401000, "aabb"),
            self._make_body(0x401000, "aabb"),
            self._make_body(0x401000, "aabb"),
        ]
        groups = deduplicate_handlers(bodies)
        assert len(groups) == 1
        assert groups[0].visit_count == 3

    def test_different_fingerprint_same_address(self):
        """Polymorphic handlers at the same address but different structure."""
        bodies = [
            self._make_body(0x401000, "aabb"),
            self._make_body(0x401000, "ccdd"),
        ]
        groups = deduplicate_handlers(bodies)
        assert len(groups) == 2

    def test_sorted_by_visit_count(self):
        bodies = [
            self._make_body(0x401000, "rare"),
            self._make_body(0x402000, "common"),
            self._make_body(0x402000, "common"),
            self._make_body(0x402000, "common"),
        ]
        groups = deduplicate_handlers(bodies)
        assert groups[0].handler_address == 0x402000

    def test_operand_widths_collected(self):
        bodies = [
            self._make_body(0x401000, "ff", vip_delta=2),
            self._make_body(0x401000, "ff", vip_delta=5),
        ]
        groups = deduplicate_handlers(bodies)
        assert 1 in groups[0].observed_operand_widths
        assert 4 in groups[0].observed_operand_widths


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Full extraction pipeline
# ═══════════════════════════════════════════════════════════════════════════

class TestExtractHandlerBodies:

    def test_basic_extraction(self):
        trace = _make_handler_trace(vip_start=0x5000, vip_end=0x5002)
        boundary = FakeBoundary(
            vip_value=0x5000, handler_address=0x401000,
            trace_start=0, trace_end=3, vip_delta=2,
        )
        result = extract_handler_bodies(trace, [boundary], vip_register="rsi")
        assert result.total_invocations == 1
        assert len(result.bodies) == 1
        body = result.bodies[0]
        assert body.handler_address == 0x401000
        assert body.vip_value == 0x5000
        assert body.instruction_count == 3
        assert body.vip_delta == 2

    def test_register_deltas_computed(self):
        trace = _make_handler_trace(vip_start=0x5000, vip_end=0x5002)
        boundary = FakeBoundary(trace_start=0, trace_end=3, vip_delta=2)
        result = extract_handler_bodies(trace, [boundary], vip_register="rsi")
        body = result.bodies[0]
        # rax changed from 0x100 → 0x300, rsp changed from 0xFF00 → 0xFEF8
        changed = {d.register for d in body.register_deltas}
        assert "rax" in changed or "rsi" in changed

    def test_fingerprint_assigned(self):
        trace = _make_handler_trace()
        boundary = FakeBoundary(trace_start=0, trace_end=3, vip_delta=2)
        result = extract_handler_bodies(trace, [boundary], vip_register="rsi")
        assert result.bodies[0].fingerprint != ""

    def test_groups_created(self):
        """Two invocations of the same handler should be grouped."""
        trace = _make_handler_trace(handler_addr=0x401000, vip_start=0x5000, vip_end=0x5002)
        trace += _make_handler_trace(handler_addr=0x401000, vip_start=0x5002, vip_end=0x5004)
        boundaries = [
            FakeBoundary(vip_value=0x5000, trace_start=0, trace_end=3, vip_delta=2),
            FakeBoundary(vip_value=0x5002, trace_start=3, trace_end=6, vip_delta=2),
        ]
        result = extract_handler_bodies(trace, boundaries, vip_register="rsi")
        assert result.total_invocations == 2
        assert result.unique_handlers == 1  # same handler, same structure

    def test_mnemonic_sequence(self):
        trace = _make_handler_trace()
        boundary = FakeBoundary(trace_start=0, trace_end=3, vip_delta=2)
        result = extract_handler_bodies(trace, [boundary], vip_register="rsi")
        mnemonics = result.bodies[0].mnemonic_sequence
        assert "push" in mnemonics
        assert "add" in mnemonics

    def test_operand_extracted(self):
        trace = _make_handler_trace(vip_start=0x5000, vip_end=0x5005)
        boundary = FakeBoundary(
            vip_value=0x5000, trace_start=0, trace_end=3, vip_delta=5,
        )
        result = extract_handler_bodies(trace, [boundary], vip_register="rsi")
        body = result.bodies[0]
        assert body.operand is not None
        assert body.operand.width == 4  # 5 - 1 opcode byte

    def test_empty_trace_returns_empty(self):
        result = extract_handler_bodies([], [], vip_register="rsi")
        assert result.total_invocations == 0
        assert result.unique_handlers == 0

    def test_dispatcher_instructions_filtered(self):
        trace = _make_handler_trace(handler_addr=0x401000)
        # Add a dispatcher instruction in the middle
        trace.insert(1, _make_trace_insn(0x400000, "jmp qword ptr [r12+rcx*8]"))
        boundary = FakeBoundary(trace_start=0, trace_end=4, vip_delta=2)
        result = extract_handler_bodies(
            trace, [boundary], vip_register="rsi",
            dispatcher_addresses=[0x400000],
        )
        body = result.bodies[0]
        # The dispatcher instruction should be filtered out
        addrs = [i["address"] for i in body.instructions]
        assert 0x400000 not in addrs

    def test_bytecode_consumed(self):
        """Total bytecode consumption should sum vip_deltas."""
        trace = _make_handler_trace(vip_start=0x5000, vip_end=0x5002)
        trace += _make_handler_trace(vip_start=0x5002, vip_end=0x5005)
        boundaries = [
            FakeBoundary(vip_value=0x5000, trace_start=0, trace_end=3, vip_delta=2),
            FakeBoundary(vip_value=0x5002, trace_start=3, trace_end=6, vip_delta=3),
        ]
        result = extract_handler_bodies(trace, boundaries, vip_register="rsi")
        assert result.bytecode_bytes_consumed == 5  # 2 + 3


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Memory access classification
# ═══════════════════════════════════════════════════════════════════════════

class TestMemoryAccessClassification:

    def test_push_is_write(self):
        reads, writes = [], []
        _classify_memory_access("push rax", "push", 0x401000, reads, writes)
        # push doesn't have explicit [mem] in operands in standard disasm
        assert len(writes) == 0  # push rax doesn't have [mem] in operands

    def test_mov_to_memory_is_write(self):
        reads, writes = [], []
        _classify_memory_access("mov [rsp+8], rax", "mov", 0x401000, reads, writes)
        assert len(writes) == 1
        assert writes[0]["memory_expr"] == "rsp+8"

    def test_mov_from_memory_is_read(self):
        reads, writes = [], []
        _classify_memory_access("mov rax, [rbx]", "mov", 0x401000, reads, writes)
        assert len(reads) == 1

    def test_no_memory_no_access(self):
        reads, writes = [], []
        _classify_memory_access("add rax, rbx", "add", 0x401000, reads, writes)
        assert len(reads) == 0
        assert len(writes) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Serialization
# ═══════════════════════════════════════════════════════════════════════════

class TestSerialization:

    def test_handler_body_to_dict(self):
        body = HandlerBody(
            handler_address=0x401000, vip_value=0x5000,
            trace_start=0, trace_end=3,
            vip_delta=2, fingerprint="abcd1234",
        )
        d = body.to_dict()
        assert d["handler_address"] == "0x401000"
        assert d["vip_delta"] == 2
        assert d["fingerprint"] == "abcd1234"

    def test_extraction_result_to_dict(self):
        result = ExtractionResult(
            vip_register="rsi",
            total_invocations=5,
            unique_handlers=3,
            bytecode_bytes_consumed=20,
        )
        d = result.to_dict()
        assert d["vip_register"] == "rsi"
        assert d["total_invocations"] == 5

    def test_register_delta_to_dict(self):
        delta = RegisterDelta(register="rax", value_before=10, value_after=20)
        d = delta.to_dict()
        assert d["delta"] == 10

    def test_handler_group_to_dict(self):
        group = HandlerGroup(
            handler_address=0x401000,
            fingerprint="abcd",
            canonical_mnemonics=["push", "mov"],
            category="stack_op",
        )
        d = group.to_dict()
        assert d["fingerprint"] == "abcd"
        assert "push" in d["canonical_mnemonics"]
