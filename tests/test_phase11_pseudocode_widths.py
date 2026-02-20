"""Phase 11 Batch 6 – Pseudocode operand-width-aware emission."""

import pytest

from dragonslayer.analysis.handler_semantics import (
    SemanticOpcodeTable,
    OpcodeTableEntry,
    HandlerSemantic,
    VMOperation,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
from dragonslayer.analysis.pseudocode import (
    _DefUseNamer,
    _WIDTH_CAST,
    _WIDTH_TYPE,
    _format_instruction_ssa,
    emit_linear,
    emit_c_like,
    emit_pseudocode,
    PseudocodeResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(addr, op, delta=4, width=0, opcode=0):
    return OpcodeTableEntry(
        opcode=opcode,
        handler_address=addr,
        semantic=HandlerSemantic(
            handler_address=addr, operation=op,
            confidence=0.9, operand_width=width,
        ),
        vip_delta=delta,
    )


def _bnd(vip, handler_addr, delta=4):
    return HandlerBoundary(
        vip_value=vip, handler_address=handler_addr,
        trace_start=0, trace_end=5,
        instruction_count=5, vip_delta=delta,
    )


# ---------------------------------------------------------------------------
# _WIDTH_CAST / _WIDTH_TYPE dictionaries
# ---------------------------------------------------------------------------

class TestWidthDicts:
    def test_width_cast_values(self):
        assert _WIDTH_CAST[1] == "BYTE"
        assert _WIDTH_CAST[2] == "WORD"
        assert _WIDTH_CAST[4] == "DWORD"
        assert _WIDTH_CAST[8] == "QWORD"

    def test_width_type_values(self):
        assert _WIDTH_TYPE[1] == "uint8_t"
        assert _WIDTH_TYPE[2] == "uint16_t"
        assert _WIDTH_TYPE[4] == "uint32_t"
        assert _WIDTH_TYPE[8] == "uint64_t"


# ---------------------------------------------------------------------------
# _DefUseNamer width tracking
# ---------------------------------------------------------------------------

class TestDefUseNamerWidths:
    def test_define_records_width(self):
        n = _DefUseNamer()
        name = n.define(VMOperation.ADD, width=4)
        assert n.var_width(name) == 4

    def test_define_zero_width_not_recorded(self):
        n = _DefUseNamer()
        name = n.define(VMOperation.ADD, width=0)
        assert n.var_width(name) == 0

    def test_all_var_widths(self):
        n = _DefUseNamer()
        n._stack = ["a", "b"]  # supply operands
        dst1, _, _ = n.consume_binary(VMOperation.ADD, width=4)
        n._stack.append("c")
        dst2, _ = n.consume_unary(VMOperation.NOT, width=2)
        widths = n.all_var_widths()
        assert widths[dst1] == 4
        assert widths[dst2] == 2

    def test_consume_binary_width(self):
        n = _DefUseNamer()
        n._stack = ["x", "y"]
        dst, _, _ = n.consume_binary(VMOperation.SUB, width=8)
        assert n.var_width(dst) == 8

    def test_consume_unary_width(self):
        n = _DefUseNamer()
        n._stack = ["x"]
        dst, _ = n.consume_unary(VMOperation.NEG, width=1)
        assert n.var_width(dst) == 1


# ---------------------------------------------------------------------------
# Width-qualified LOAD / STORE formatting
# ---------------------------------------------------------------------------

class TestWidthQualifiedLoadStore:
    def test_load_dword(self):
        """LOAD with width=4 → *(DWORD*)(addr)."""
        entry = _entry(0x1000, VMOperation.LOAD, width=4)
        namer = _DefUseNamer()
        namer.push("addr_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x1000), 0, namer)
        assert "*(DWORD*)" in line
        assert "addr_0" in line

    def test_load_qword(self):
        entry = _entry(0x1000, VMOperation.LOAD, width=8)
        namer = _DefUseNamer()
        namer.push("ptr_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x1000), 0, namer)
        assert "*(QWORD*)" in line
        assert "ptr_0" in line

    def test_load_byte(self):
        entry = _entry(0x1000, VMOperation.LOAD, width=1)
        namer = _DefUseNamer()
        namer.push("src_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x1000), 0, namer)
        assert "*(BYTE*)" in line

    def test_load_word(self):
        entry = _entry(0x1000, VMOperation.LOAD, width=2)
        namer = _DefUseNamer()
        namer.push("src_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x1000), 0, namer)
        assert "*(WORD*)" in line

    def test_load_no_width_uses_template(self):
        """LOAD with width=0 falls back to template (no cast)."""
        entry = _entry(0x1000, VMOperation.LOAD, width=0)
        namer = _DefUseNamer()
        namer.push("addr_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x1000), 0, namer)
        # Should NOT contain a width cast
        assert "DWORD" not in line
        assert "QWORD" not in line
        # Should contain the standard template tokens
        assert "=" in line

    def test_store_dword(self):
        """STORE with width=4 → *(DWORD*)(addr) = val."""
        entry = _entry(0x2000, VMOperation.STORE, width=4)
        namer = _DefUseNamer()
        namer.push("addr_0")
        namer.push("val_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x2000), 0, namer)
        assert "*(DWORD*)" in line
        assert "val_0" in line
        assert "addr_0" in line

    def test_store_qword(self):
        entry = _entry(0x2000, VMOperation.STORE, width=8)
        namer = _DefUseNamer()
        namer.push("addr_0")
        namer.push("val_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x2000), 0, namer)
        assert "*(QWORD*)" in line

    def test_store_no_width_uses_template(self):
        entry = _entry(0x2000, VMOperation.STORE, width=0)
        namer = _DefUseNamer()
        namer.push("addr_0")
        namer.push("val_0")
        line = _format_instruction_ssa(entry, _bnd(0x100, 0x2000), 0, namer)
        assert "DWORD" not in line
        assert "=" in line

    def test_load_defines_var_with_width(self):
        """LOAD records operand width on the produced variable."""
        entry = _entry(0x1000, VMOperation.LOAD, width=4)
        namer = _DefUseNamer()
        namer.push("addr_0")
        _format_instruction_ssa(entry, _bnd(0x100, 0x1000), 0, namer)
        # The namer should have recorded the ld_0 variable with width 4
        widths = namer.all_var_widths()
        ld_vars = [k for k in widths if k.startswith("ld_")]
        assert len(ld_vars) == 1
        assert widths[ld_vars[0]] == 4


# ---------------------------------------------------------------------------
# Binary/unary ops pass width through
# ---------------------------------------------------------------------------

class TestArithWidthPropagation:
    def test_add_records_width(self):
        entry = _entry(0x3000, VMOperation.ADD, width=4)
        namer = _DefUseNamer()
        namer.push("a_0")
        namer.push("b_0")
        _format_instruction_ssa(entry, _bnd(0x100, 0x3000), 0, namer)
        widths = namer.all_var_widths()
        sum_vars = [k for k in widths if k.startswith("sum_")]
        assert len(sum_vars) == 1
        assert widths[sum_vars[0]] == 4

    def test_not_records_width(self):
        entry = _entry(0x3000, VMOperation.NOT, width=2)
        namer = _DefUseNamer()
        namer.push("x_0")
        _format_instruction_ssa(entry, _bnd(0x100, 0x3000), 0, namer)
        widths = namer.all_var_widths()
        bnot_vars = [k for k in widths if k.startswith("bnot_")]
        assert len(bnot_vars) == 1
        assert widths[bnot_vars[0]] == 2

    def test_push_records_width(self):
        entry = _entry(0x4000, VMOperation.PUSH, width=8)
        namer = _DefUseNamer()
        _format_instruction_ssa(entry, _bnd(0x100, 0x4000), 0, namer)
        widths = namer.all_var_widths()
        assert any(w == 8 for w in widths.values())


# ---------------------------------------------------------------------------
# PseudocodeResult carries var_widths
# ---------------------------------------------------------------------------

class TestPseudocodeResultVarWidths:
    def test_result_has_var_widths_field(self):
        r = PseudocodeResult()
        assert hasattr(r, "var_widths")
        assert r.var_widths == {}

    def test_emit_linear_populates_var_widths(self):
        entries = [
            _entry(0x6000, VMOperation.POP, delta=1, opcode=0x10, width=4),
            _entry(0x7000, VMOperation.ADD, delta=2, opcode=0x20, width=4),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=2, unique_operations=2,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x7000, delta=2),
        ]
        result = emit_linear(table, boundaries)
        # POP with width=0 won't record (POP doesn't go through define with width),
        # but ADD with width=4 should.
        assert isinstance(result.var_widths, dict)
        sum_vars = [k for k in result.var_widths if k.startswith("sum_")]
        assert len(sum_vars) >= 1
        assert all(result.var_widths[k] == 4 for k in sum_vars)


# ---------------------------------------------------------------------------
# emit_c_like per-variable type declarations
# ---------------------------------------------------------------------------

class TestEmitCLikePerVarTypes:
    def _make_mixed_width_program(self):
        """Create a program with 4-byte and 8-byte operations."""
        entries = [
            _entry(0x6000, VMOperation.POP, delta=1, opcode=0x10, width=4),
            _entry(0x6001, VMOperation.POP, delta=1, opcode=0x11, width=4),
            _entry(0x7000, VMOperation.ADD, delta=2, opcode=0x20, width=4),
            _entry(0x7001, VMOperation.LOAD, delta=2, opcode=0x21, width=8),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=4, unique_operations=4,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x6001, delta=1),
            _bnd(0x102, 0x7000, delta=2),
            _bnd(0x104, 0x7001, delta=2),
        ]
        return table, boundaries

    def test_mixed_widths_emit_separate_declarations(self):
        table, boundaries = self._make_mixed_width_program()
        result = emit_c_like(table, boundaries)
        text = result.text
        # Should have uint32_t and uint64_t declarations (not all one type)
        assert "uint32_t" in text
        assert "uint64_t" in text

    def test_uniform_width_single_type(self):
        """All operations at width=4 → all vars declared uint32_t."""
        entries = [
            _entry(0x6000, VMOperation.POP, delta=1, opcode=0x10, width=4),
            _entry(0x7000, VMOperation.ADD, delta=2, opcode=0x20, width=4),
            _entry(0x8000, VMOperation.PUSH, delta=1, opcode=0x30, width=4),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=3, unique_operations=3,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x7000, delta=2),
            _bnd(0x103, 0x8000, delta=1),
        ]
        result = emit_c_like(table, boundaries)
        # All vars should be uint32_t
        assert "uint32_t" in result.text

    def test_width_cast_in_load(self):
        """C-like output includes *(DWORD*) or *(QWORD*) for LOAD."""
        entries = [
            _entry(0x6000, VMOperation.PUSH, delta=1, opcode=0x10, width=4),
            _entry(0x7000, VMOperation.LOAD, delta=2, opcode=0x20, width=4),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=2, unique_operations=2,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x7000, delta=2),
        ]
        result = emit_c_like(table, boundaries)
        assert "*(DWORD*)" in result.text

    def test_width_cast_in_store(self):
        """C-like output includes *(DWORD*) for STORE."""
        entries = [
            _entry(0x6000, VMOperation.PUSH, delta=1, opcode=0x10, width=4),
            _entry(0x6001, VMOperation.PUSH, delta=1, opcode=0x11, width=4),
            _entry(0x7000, VMOperation.STORE, delta=2, opcode=0x20, width=4),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=3, unique_operations=3,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x6001, delta=1),
            _bnd(0x102, 0x7000, delta=2),
        ]
        result = emit_c_like(table, boundaries)
        assert "*(DWORD*)" in result.text

    def test_byte_width_type_declaration(self):
        """Width=1 operations → uint8_t type declarations."""
        entries = [
            _entry(0x6000, VMOperation.PUSH, delta=1, opcode=0x10, width=1),
            _entry(0x7000, VMOperation.LOAD, delta=1, opcode=0x20, width=1),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=2, unique_operations=2,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x7000, delta=1),
        ]
        result = emit_c_like(table, boundaries)
        assert "uint8_t" in result.text
        assert "*(BYTE*)" in result.text

    def test_word_width_type_declaration(self):
        """Width=2 operations → uint16_t type declarations."""
        entries = [
            _entry(0x6000, VMOperation.POP, delta=1, opcode=0x10, width=2),
            _entry(0x7000, VMOperation.ADD, delta=2, opcode=0x20, width=2),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=2, unique_operations=2,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x7000, delta=2),
        ]
        result = emit_c_like(table, boundaries)
        assert "uint16_t" in result.text


# ---------------------------------------------------------------------------
# emit_pseudocode dispatcher still works
# ---------------------------------------------------------------------------

class TestDispatcherWidths:
    def test_c_like_via_dispatcher(self):
        entries = [
            _entry(0x6000, VMOperation.PUSH, delta=1, opcode=0x10, width=4),
            _entry(0x7000, VMOperation.LOAD, delta=2, opcode=0x20, width=4),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=2, unique_operations=2,
        )
        boundaries = [
            _bnd(0x100, 0x6000, delta=1),
            _bnd(0x101, 0x7000, delta=2),
        ]
        result = emit_pseudocode(table, boundaries, style="c_like")
        assert "*(DWORD*)" in result.text
        assert "void vm_func()" in result.text
