"""Tests for pseudocode emission."""

import pytest

from dragonslayer.analysis.handler_semantics import (
    SemanticOpcodeTable,
    OpcodeTableEntry,
    HandlerSemantic,
    VMOperation,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
from dragonslayer.analysis.pseudocode import (
    emit_linear,
    emit_structured,
    emit_c_like,
    emit_pseudocode,
    PseudocodeResult,
)

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _entry(addr, op, delta=4, width=8, opcode=0):
    return OpcodeTableEntry(
        opcode=opcode,
        handler_address=addr,
        semantic=HandlerSemantic(
            handler_address=addr, operation=op,
            confidence=0.9, operand_width=width,
        ),
        vip_delta=delta,
    )


def _boundary(vip, handler_addr, delta=4, start=0, end=5):
    return HandlerBoundary(
        vip_value=vip, handler_address=handler_addr,
        trace_start=start, trace_end=end,
        instruction_count=end - start, vip_delta=delta,
    )


def _simple_table_and_boundaries():
    """Return a small opcode table + boundaries for a 3-instruction VM program:
    v0 = pop()
    v1 = v0 + v0
    push(v1)
    """
    entries = [
        _entry(0x6000, VMOperation.POP, delta=1, opcode=0x10),
        _entry(0x7000, VMOperation.ADD, delta=2, opcode=0x20),
        _entry(0x8000, VMOperation.PUSH, delta=1, opcode=0x30),
    ]
    table = SemanticOpcodeTable(
        entries=entries, handler_count=3, unique_operations=3,
    )
    boundaries = [
        _boundary(0x100, 0x6000, delta=1, start=0, end=5),
        _boundary(0x101, 0x7000, delta=2, start=5, end=10),
        _boundary(0x103, 0x8000, delta=1, start=10, end=15),
    ]
    return table, boundaries


# ---------------------------------------------------------------------------
# emit_linear
# ---------------------------------------------------------------------------

class TestEmitLinear:
    def test_basic_output(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_linear(table, boundaries)
        assert isinstance(result, PseudocodeResult)
        assert result.line_count == 3
        assert result.style == "linear"
        assert "pop()" in result.text
        assert "+" in result.text
        assert "push(" in result.text

    def test_unknown_handler_warning(self):
        table = SemanticOpcodeTable()  # empty
        boundaries = [_boundary(0x100, 0x6000)]
        result = emit_linear(table, boundaries)
        assert len(result.warnings) == 1
        assert "unknown" in result.text.lower() or "unknown" in result.warnings[0].lower()

    def test_vip_addresses_present(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_linear(table, boundaries)
        assert "0x00000100" in result.text

    def test_empty(self):
        result = emit_linear(SemanticOpcodeTable(), [])
        assert result.line_count == 0
        assert result.text == ""

    def test_all_operations(self):
        """Smoke test: every known operation emits without error."""
        for op_name in dir(VMOperation):
            if op_name.startswith("_"):
                continue
            op_val = getattr(VMOperation, op_name)
            if not isinstance(op_val, str):
                continue
            entry = _entry(0x6000, op_val)
            table = SemanticOpcodeTable(entries=[entry], handler_count=1, unique_operations=1)
            boundary = _boundary(0x100, 0x6000)
            result = emit_linear(table, [boundary])
            assert result.line_count == 1


# ---------------------------------------------------------------------------
# emit_structured
# ---------------------------------------------------------------------------

class TestEmitStructured:
    def test_fallback_to_linear(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_structured(table, boundaries, handler_cfg=None)
        # Without a CFG, falls back to linear.
        assert result.style == "linear"

    @pytest.mark.skipif(not NX_AVAILABLE, reason="networkx required")
    def test_with_cfg(self):
        table, boundaries = _simple_table_and_boundaries()
        G = nx.DiGraph()
        for i in range(len(boundaries)):
            G.add_node(i)
        for i in range(len(boundaries) - 1):
            G.add_edge(i, i + 1, type="sequential")
        result = emit_structured(table, boundaries, handler_cfg=G)
        assert result.style == "structured"
        assert result.line_count >= 3

    @pytest.mark.skipif(not NX_AVAILABLE, reason="networkx required")
    def test_jcc_emits_if(self):
        entry = _entry(0x9000, VMOperation.JCC, delta=8)
        table = SemanticOpcodeTable(entries=[entry], handler_count=1, unique_operations=1)
        boundary = _boundary(0x200, 0x9000, delta=8)
        G = nx.DiGraph()
        G.add_node(0)
        result = emit_structured(table, [boundary], handler_cfg=G)
        assert "if" in result.text

    @pytest.mark.skipif(not NX_AVAILABLE, reason="networkx required")
    def test_loop_detection(self):
        table, boundaries = _simple_table_and_boundaries()
        G = nx.DiGraph()
        for i in range(3):
            G.add_node(i)
        G.add_edge(0, 1, type="sequential")
        G.add_edge(1, 2, type="sequential")
        G.add_edge(2, 0, type="back_edge")  # loop back
        result = emit_structured(table, boundaries, handler_cfg=G)
        assert "while" in result.text

    @pytest.mark.skipif(not NX_AVAILABLE, reason="networkx required")
    def test_multiple_loops_close_correctly(self):
        """Two back-edges => two 'while(true){' ... two closing '}'."""
        table, boundaries = _simple_table_and_boundaries()
        # Extend to 4 boundaries so we have room for 2 loop targets
        extra_entries = [
            _entry(0x7004, VMOperation.ADD, delta=2),
        ]
        for e in extra_entries:
            table = SemanticOpcodeTable(
                entries=table.entries + extra_entries,
                handler_count=len(table.entries) + len(extra_entries),
                unique_operations=table.unique_operations + 1,
            )
        boundaries = boundaries + [_boundary(0x106, 0x7004, delta=2)]
        G = nx.DiGraph()
        for i in range(len(boundaries)):
            G.add_node(i)
        for i in range(len(boundaries) - 1):
            G.add_edge(i, i + 1, type="sequential")
        G.add_edge(2, 0, type="back_edge")  # first loop
        G.add_edge(3, 1, type="back_edge")  # second loop
        result = emit_structured(table, boundaries, handler_cfg=G)
        while_count = result.text.count("while (true) {")
        close_count = result.text.strip().split("\n")
        closing_braces = sum(1 for l in close_count if l.strip() == "}")
        assert while_count == 2
        assert closing_braces >= 2


# ---------------------------------------------------------------------------
# emit_c_like
# ---------------------------------------------------------------------------

class TestEmitCLike:
    def test_function_wrapper(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_c_like(table, boundaries, function_name="test_func")
        assert result.style == "c_like"
        assert "void test_func()" in result.text
        assert "uint64_t" in result.text  # 8-byte width

    def test_variable_declarations(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_c_like(table, boundaries)
        # SSA naming: pop → arg_N, add → sum_N, push uses operand names.
        assert "arg_0" in result.text
        assert "sum_0" in result.text

    def test_comments(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_c_like(table, boundaries)
        assert "Devirtualised" in result.text
        assert "vm_pop" in result.text or "vm_add" in result.text


# ---------------------------------------------------------------------------
# emit_pseudocode (dispatcher)
# ---------------------------------------------------------------------------

class TestEmitPseudocode:
    def test_linear_style(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_pseudocode(table, boundaries, style="linear")
        assert result.style == "linear"

    def test_c_like_default(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_pseudocode(table, boundaries, style="c_like")
        assert result.style == "c_like"

    def test_unknown_style_fallback(self):
        table, boundaries = _simple_table_and_boundaries()
        result = emit_pseudocode(table, boundaries, style="invalid")
        assert result.style == "linear"


# ---------------------------------------------------------------------------
# PseudocodeResult
# ---------------------------------------------------------------------------

class TestPseudocodeResult:
    def test_to_dict(self):
        r = PseudocodeResult(text="hello\nworld", line_count=2, style="linear")
        d = r.to_dict()
        assert d["line_count"] == 2
        assert d["style"] == "linear"
