"""Batch 20 — Pseudocode emitter upgrade tests.

Validates that emit_c_like/emit_pseudocode now leverage
context_layout and clustering annotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

from dragonslayer.analysis.handler_semantics import (
    HandlerSemantic,
    OpcodeTableEntry,
    SemanticOpcodeTable,
    VMOperation,
)
from dragonslayer.analysis.pseudocode import (
    emit_pseudocode,
    emit_c_like,
    emit_linear,
    PseudocodeResult,
    _extract_context_registers,
    _extract_cluster_summary,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sem(op: str, width: int = 4) -> HandlerSemantic:
    return HandlerSemantic(handler_address=0, operation=op, confidence=0.9,
                           operand_width=width)


def _entry(opcode: int, addr: int, op: str, delta: int = 1) -> OpcodeTableEntry:
    return OpcodeTableEntry(
        opcode=opcode, handler_address=addr,
        semantic=_sem(op), vip_delta=delta)


def _table(entries: List[OpcodeTableEntry]) -> SemanticOpcodeTable:
    return SemanticOpcodeTable(
        entries=entries,
        handler_count=len(entries),
        unique_operations=len({e.semantic.operation for e in entries}),
    )


def _boundary(vip: int, addr: int, delta: int = 1) -> HandlerBoundary:
    return HandlerBoundary(
        vip_value=vip, handler_address=addr,
        vip_delta=delta, instruction_count=3,
        trace_start=0, trace_end=3,
    )


def _simple_scenario():
    """Return (opcode_table, boundaries) for PUSH, ADD, RET."""
    entries = [
        _entry(0, 0x1000, VMOperation.PUSH, delta=5),
        _entry(1, 0x2000, VMOperation.ADD),
        _entry(2, 0x3000, VMOperation.RET),
    ]
    table = _table(entries)
    boundaries = [
        _boundary(0, 0x1000, delta=5),
        _boundary(5, 0x2000),
        _boundary(6, 0x3000),
    ]
    return table, boundaries


# ---------------------------------------------------------------------------
# _extract_context_registers tests
# ---------------------------------------------------------------------------

class TestExtractContextRegisters:
    def test_none_returns_empty(self):
        assert _extract_context_registers(None) == {}

    def test_dict_with_known_keys(self):
        layout = {"vsp": "rsp", "table_base": "rbx", "key_register": "rcx"}
        result = _extract_context_registers(layout)
        assert result["vsp"] == "rsp"
        assert result["table_base"] == "rbx"
        assert result["key_register"] == "rcx"

    def test_dict_with_registers_sub_dict(self):
        layout = {
            "registers": {
                "vSP": {"register": "rsp"},
                "vIP": {"register": "rsi"},
            }
        }
        result = _extract_context_registers(layout)
        assert result["vSP"] == "rsp"
        assert result["vIP"] == "rsi"

    def test_dict_ignores_none_values(self):
        layout = {"vsp": "rsp", "key_register": None}
        result = _extract_context_registers(layout)
        assert "vsp" in result
        assert "key_register" not in result

    def test_object_with_attributes(self):
        class FakeLayout:
            vsp = type("reg", (), {"register": "rsp"})()
            table_base = type("reg", (), {"register": "rbx"})()
            key_register = None
            context_base = None

        result = _extract_context_registers(FakeLayout())
        assert result["vsp"] == "rsp"
        assert result["table_base"] == "rbx"
        assert "key_register" not in result


# ---------------------------------------------------------------------------
# _extract_cluster_summary tests
# ---------------------------------------------------------------------------

class TestExtractClusterSummary:
    def test_none_returns_empty(self):
        assert _extract_cluster_summary(None) == {}

    def test_dict_with_clusters(self):
        clustering = {
            "clusters": [
                {"canonical_operation": "vm_add", "handler_count": 3},
                {"canonical_operation": "vm_push", "handler_count": 2},
            ]
        }
        result = _extract_cluster_summary(clustering)
        assert result["vm_add"] == 3
        assert result["vm_push"] == 2

    def test_dict_with_members_fallback(self):
        clustering = {
            "clusters": [
                {"canonical_operation": "vm_xor", "members": [1, 2, 3]},
            ]
        }
        result = _extract_cluster_summary(clustering)
        assert result["vm_xor"] == 3

    def test_object_with_clusters(self):
        class FakeCluster:
            canonical_operation = "vm_sub"
            members = [1, 2]

        class FakeResult:
            clusters = [FakeCluster()]

        result = _extract_cluster_summary(FakeResult())
        assert result["vm_sub"] == 2


# ---------------------------------------------------------------------------
# emit_c_like with context_layout and clustering
# ---------------------------------------------------------------------------

class TestEmitCLikeWithAnnotations:
    def test_baseline_without_annotations(self):
        table, boundaries = _simple_scenario()
        result = emit_c_like(table, boundaries)
        assert "void vm_func()" in result.text
        assert "Devirtualised from" in result.text

    def test_with_context_layout(self):
        table, boundaries = _simple_scenario()
        layout = {"vsp": "rsp", "table_base": "rbx"}
        result = emit_c_like(table, boundaries, context_layout=layout)
        assert "VM Context Layout" in result.text
        assert "vsp" in result.text
        assert "rsp" in result.text
        assert "table_base" in result.text
        assert "rbx" in result.text

    def test_with_clustering(self):
        table, boundaries = _simple_scenario()
        clustering = {
            "clusters": [
                {"canonical_operation": "vm_add", "handler_count": 2},
            ]
        }
        result = emit_c_like(table, boundaries, clustering=clustering)
        assert "Semantic Clusters" in result.text
        assert "vm_add" in result.text
        assert "2 handler variant(s)" in result.text

    def test_with_both(self):
        table, boundaries = _simple_scenario()
        layout = {"vsp": "rsp"}
        clustering = {
            "clusters": [
                {"canonical_operation": "vm_push", "handler_count": 1},
            ]
        }
        result = emit_c_like(table, boundaries,
                             context_layout=layout, clustering=clustering)
        assert "VM Context Layout" in result.text
        assert "Semantic Clusters" in result.text

    def test_no_layout_no_cluster_section(self):
        table, boundaries = _simple_scenario()
        result = emit_c_like(table, boundaries)
        assert "VM Context Layout" not in result.text
        assert "Semantic Clusters" not in result.text


# ---------------------------------------------------------------------------
# emit_pseudocode passes through context_layout and clustering
# ---------------------------------------------------------------------------

class TestEmitPseudocodePassthrough:
    def test_c_like_with_layout(self):
        table, boundaries = _simple_scenario()
        layout = {"vsp": "rdi"}
        result = emit_pseudocode(table, boundaries, style="c_like",
                                 context_layout=layout)
        assert "VM Context Layout" in result.text
        assert "rdi" in result.text

    def test_linear_ignores_extras(self):
        """Linear style doesn't use context_layout/clustering but shouldn't crash."""
        table, boundaries = _simple_scenario()
        result = emit_pseudocode(table, boundaries, style="linear",
                                 context_layout={"vsp": "rsp"},
                                 clustering={"clusters": []})
        assert result.style == "linear"

    def test_structured_ignores_extras(self):
        """Structured may fall back to linear when no CFG is available."""
        table, boundaries = _simple_scenario()
        result = emit_pseudocode(table, boundaries, style="structured",
                                 context_layout={"vsp": "rsp"})
        assert result.style in ("structured", "linear")

    def test_unknown_style_fallback(self):
        table, boundaries = _simple_scenario()
        result = emit_pseudocode(table, boundaries, style="markdown")
        assert result.style == "linear"  # falls back to linear
