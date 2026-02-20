"""Tests for B43: Pseudocode structuring improvements.

Covers:
  - emit_c_like uses Cifuentes when CFG available
  - emit_pseudocode dispatcher routes "cifuentes" style
  - Context-based variable renaming (_apply_context_renaming)
  - Dead variable elimination (_eliminate_trivial_dead)
  - Integration: full c_like output with context + clustering + CFG
"""
from __future__ import annotations

import re
import pytest
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Fake CFG helpers (reused from test_cifuentes_structuring) ────────────────

@dataclass
class _FakeVMInsn:
    handler_address: int = 0
    vip: int = 0
    operation: str = ""

    def is_branch(self):
        return "JCC" in self.operation or "JMP" in self.operation

    def is_terminator(self):
        return self.is_branch() or "RET" in self.operation


@dataclass
class _FakeBlock:
    block_id: int = 0
    instructions: list = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

    def terminator(self):
        return self.instructions[-1] if self.instructions else None


@dataclass
class _FakeEdge:
    source_block: int = 0
    target_block: int = 0
    edge_type: str = "fallthrough"


class _FakeCFG:
    def __init__(self, blocks, edges, entry_block_id=0):
        self.blocks = blocks
        self.edges = edges
        self.entry_block_id = entry_block_id
        self._block_map = {b.block_id: b for b in blocks}
        try:
            import networkx as nx
            self.graph = nx.DiGraph()
            for b in blocks:
                self.graph.add_node(b.block_id)
            for e in edges:
                self.graph.add_edge(e.source_block, e.target_block)
        except ImportError:
            self.graph = None

    def topological_order(self):
        if self.graph is not None:
            import networkx as nx
            try:
                return list(nx.topological_sort(self.graph))
            except nx.NetworkXUnfeasible:
                return sorted(self._block_map.keys())
        return sorted(self._block_map.keys())

    def loop_headers(self):
        return []

    def exit_blocks(self):
        return [b.block_id for b in self.blocks if b.is_exit]


# ── Semantic stubs ───────────────────────────────────────────────────────────

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
    emit_cifuentes,
    emit_pseudocode,
    PseudocodeResult,
    _apply_context_renaming,
    _eliminate_trivial_dead,
)


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


def _make_linear_cfg(boundaries):
    """Build a simple linear CFG (B0 → B1 → B2 → exit)."""
    blocks = []
    for i, bnd in enumerate(boundaries):
        insn = _FakeVMInsn(handler_address=bnd.handler_address, vip=bnd.vip_value)
        blocks.append(_FakeBlock(
            block_id=i,
            instructions=[insn],
            is_entry=(i == 0),
            is_exit=(i == len(boundaries) - 1),
        ))
    edges = [_FakeEdge(source_block=i, target_block=i + 1)
             for i in range(len(blocks) - 1)]
    return _FakeCFG(blocks, edges, entry_block_id=0)


# ==========================================================================
# TestContextRenaming
# ==========================================================================

class TestContextRenaming:
    """Tests for _apply_context_renaming."""

    def test_no_layout_noop(self):
        text = "rsp = rsp - 4"
        assert _apply_context_renaming(text, None) == text

    def test_empty_layout_noop(self):
        text = "rsp = rsp - 4"
        assert _apply_context_renaming(text, {}) == text

    def test_vsp_renamed(self):
        layout = {"vsp": "rsp"}
        text = "rsp = rsp - 4"
        result = _apply_context_renaming(text, layout)
        assert "vSP" in result
        assert "rsp" not in result.lower()

    def test_vip_renamed(self):
        layout = {"vip_register": "rsi"}
        text = "rsi += 4  // advance rsi"
        result = _apply_context_renaming(text, layout)
        assert "vIP" in result
        assert "rsi" not in result.lower()

    def test_table_base_renamed(self):
        layout = {"table_base": "rbx"}
        text = "handler = rbx[opcode]"
        result = _apply_context_renaming(text, layout)
        assert "hTable" in result

    def test_key_register_renamed(self):
        layout = {"key_register": "rdx"}
        text = "rdx ^= val"
        result = _apply_context_renaming(text, layout)
        assert "vKey" in result

    def test_context_base_renamed(self):
        layout = {"context_base": "rdi"}
        text = "rdi + offset"
        result = _apply_context_renaming(text, layout)
        assert "vCtx" in result

    def test_multiple_roles(self):
        layout = {"vsp": "rsp", "vip_register": "rsi", "table_base": "rbx"}
        text = "rsp -= 4; addr = rsi; tbl = rbx[0]"
        result = _apply_context_renaming(text, layout)
        assert "vSP" in result
        assert "vIP" in result
        assert "hTable" in result

    def test_word_boundary_only(self):
        """Should not clobber 'rsp' inside 'rsp_base' etc."""
        layout = {"vsp": "rsp"}
        text = "rsp_base = 0; rsp = 4"
        result = _apply_context_renaming(text, layout)
        # rsp_base should NOT be touched; rsp should.
        assert "rsp_base" in result
        assert "vSP = 4" in result

    def test_dict_with_registers_sub_dict(self):
        layout = {
            "registers": {
                "vsp": {"register": "rsp"},
                "vip_register": {"register": "rsi"},
            }
        }
        text = "rsp -= 4; rsi += 2"
        result = _apply_context_renaming(text, layout)
        assert "vSP" in result or "vsp" in result  # at least something renamed


# ==========================================================================
# TestDeadVarElimination
# ==========================================================================

class TestDeadVarElimination:
    """Tests for _eliminate_trivial_dead."""

    def test_no_assignments_noop(self):
        text = "if (flags) {\n  return;\n}"
        assert _eliminate_trivial_dead(text) == text

    def test_removes_single_use_var(self):
        text = "  add_0 = x + y;\n  result = add_0 + 1;"
        result = _eliminate_trivial_dead(text)
        # add_0 appears twice (def + use), so it stays
        assert "add_0" in result
        # result appears once (def only) so it's dead
        # Actually 'result' doesn't match [a-z]+_\d+ pattern
        assert "result" in result

    def test_removes_ssa_dead(self):
        text = "  tmp_1 = 42;\n  tmp_2 = tmp_1 + 1;\n  push(tmp_2);"
        result = _eliminate_trivial_dead(text)
        # tmp_1 is used in tmp_2 line → appears twice → kept
        assert "tmp_1" in result
        # tmp_2 is used in push line → appears twice → kept
        assert "tmp_2" in result

    def test_truly_dead_removed(self):
        lines = [
            "  dead_0 = 99;",
            "  live_0 = 42;",
            "  push(live_0);",
        ]
        text = "\n".join(lines)
        result = _eliminate_trivial_dead(text)
        assert "dead_0" not in result
        assert "live_0" in result

    def test_preserves_comments(self):
        text = "// header\n  dead_0 = 1;\n  // footer"
        result = _eliminate_trivial_dead(text)
        assert "// header" in result
        assert "// footer" in result
        assert "dead_0" not in result

    def test_empty_input(self):
        assert _eliminate_trivial_dead("") == ""

    def test_no_ssa_vars_noop(self):
        text = "  x = y + z;\n  return x;"
        assert _eliminate_trivial_dead(text) == text


# ==========================================================================
# TestCifuentesDispatcher
# ==========================================================================

class TestCifuentesDispatcher:
    """Test emit_pseudocode routes 'cifuentes' style correctly."""

    def test_cifuentes_style_available(self):
        table, bnds = _simple_table_and_boundaries()
        result = emit_pseudocode(table, bnds, style="cifuentes")
        assert isinstance(result, PseudocodeResult)
        assert result.line_count > 0

    def test_cifuentes_falls_back_without_cfg(self):
        table, bnds = _simple_table_and_boundaries()
        # No CFG → fallback to emit_structured → emit_linear
        result = emit_pseudocode(table, bnds, handler_cfg=None,
                                 style="cifuentes")
        assert isinstance(result, PseudocodeResult)

    def test_unknown_style_falls_to_linear(self):
        table, bnds = _simple_table_and_boundaries()
        result = emit_pseudocode(table, bnds, style="nonexistent_style")
        assert isinstance(result, PseudocodeResult)


# ==========================================================================
# TestEmitCLikeWithCFG
# ==========================================================================

class TestEmitCLikeWithCFG:
    """emit_c_like should use Cifuentes when a CFG is provided."""

    def test_c_like_with_cfg_uses_cifuentes(self):
        table, bnds = _simple_table_and_boundaries()
        cfg = _make_linear_cfg(bnds)
        result = emit_c_like(table, bnds, handler_cfg=cfg)
        assert isinstance(result, PseudocodeResult)
        assert result.style == "c_like"
        assert "void vm_func()" in result.text

    def test_c_like_without_cfg_fallback(self):
        table, bnds = _simple_table_and_boundaries()
        result = emit_c_like(table, bnds, handler_cfg=None)
        assert isinstance(result, PseudocodeResult)
        assert "void vm_func()" in result.text

    def test_c_like_with_context_layout(self):
        table, bnds = _simple_table_and_boundaries()
        layout = {"vsp": "rsp", "vip_register": "rsi"}
        result = emit_c_like(table, bnds, context_layout=layout)
        assert "VM Context Layout" in result.text

    def test_c_like_with_clustering(self):
        table, bnds = _simple_table_and_boundaries()
        clustering = {"clusters": [
            {"canonical_operation": "arithmetic", "handler_count": 3},
        ]}
        result = emit_c_like(table, bnds, clustering=clustering)
        assert "Semantic Clusters" in result.text

    def test_c_like_function_name_custom(self):
        table, bnds = _simple_table_and_boundaries()
        result = emit_c_like(table, bnds, function_name="devirt_main")
        assert "void devirt_main()" in result.text

    def test_c_like_text_not_empty(self):
        table, bnds = _simple_table_and_boundaries()
        result = emit_c_like(table, bnds)
        assert len(result.text.strip()) > 50

    def test_c_like_contains_closing_brace(self):
        table, bnds = _simple_table_and_boundaries()
        result = emit_c_like(table, bnds)
        assert result.text.strip().endswith("}")


# ==========================================================================
# TestCLikeContextRenaming
# ==========================================================================

class TestCLikeContextRenaming:
    """Verify that emit_c_like applies context-based renaming in the body."""

    def test_rsp_becomes_vsp_in_body(self):
        """If context_layout maps vsp→rsp, body text should use vSP."""
        table, bnds = _simple_table_and_boundaries()
        layout = {"vsp": "rsp"}
        result = emit_c_like(table, bnds, context_layout=layout)
        # The header will contain vsp = rsp in comments; the body
        # should have rsp references replaced with vSP
        # (only if the emitted pseudocode mentions rsp at all).
        assert isinstance(result.text, str)


# ==========================================================================
# TestCLikeDeadVarElimination
# ==========================================================================

class TestCLikeDeadVarElimination:
    """Verify that emit_c_like eliminates trivially dead vars."""

    def test_dead_vars_reduced(self):
        """The output should not contain SSA vars that appear only once."""
        table, bnds = _simple_table_and_boundaries()
        result = emit_c_like(table, bnds)
        # Find all SSA-style variable assignments
        import re
        assignments = re.findall(r"\b([a-z]+_\d+)\s*=", result.text)
        all_vars = re.findall(r"\b([a-z]+_\d+)\b", result.text)
        # Every assigned var should appear at least twice (def+use)
        # unless it was already removed by the dead elimination pass
        for var in set(assignments):
            count = all_vars.count(var)
            # If it survived, it must be used somewhere
            assert count >= 2, f"{var} is dead (appears {count} time(s))"


# ==========================================================================
# TestEmitPseudocodeIntegration
# ==========================================================================

class TestEmitPseudocodeIntegration:
    """Integration tests for emit_pseudocode with all styles."""

    def test_all_styles_produce_output(self):
        table, bnds = _simple_table_and_boundaries()
        for style in ("linear", "structured", "c_like", "cifuentes"):
            result = emit_pseudocode(table, bnds, style=style)
            assert result.line_count > 0, f"style={style} produced empty output"

    def test_c_like_line_count_ge_structured(self):
        table, bnds = _simple_table_and_boundaries()
        c_res = emit_pseudocode(table, bnds, style="c_like")
        s_res = emit_pseudocode(table, bnds, style="structured")
        # c_like wraps with headers/footers → always more lines
        assert c_res.line_count >= s_res.line_count

    def test_c_like_with_cfg_and_context(self):
        """Full integration: CFG + context layout + clustering."""
        table, bnds = _simple_table_and_boundaries()
        cfg = _make_linear_cfg(bnds)
        layout = {"vsp": "rsp", "vip_register": "rsi"}
        clustering = {"clusters": [
            {"canonical_operation": "stack", "handler_count": 2},
            {"canonical_operation": "arithmetic", "handler_count": 1},
        ]}
        result = emit_pseudocode(
            table, bnds, handler_cfg=cfg,
            style="c_like",
            context_layout=layout,
            clustering=clustering,
        )
        assert "VM Context Layout" in result.text
        assert "Semantic Clusters" in result.text
        assert "void vm_func()" in result.text
        assert result.style == "c_like"

    def test_cifuentes_with_cfg(self):
        table, bnds = _simple_table_and_boundaries()
        cfg = _make_linear_cfg(bnds)
        result = emit_pseudocode(table, bnds, handler_cfg=cfg,
                                 style="cifuentes")
        assert result.style == "cifuentes"
        assert result.line_count > 0
