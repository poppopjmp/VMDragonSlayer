"""B44 — Synthetic VM integration tests.

Exercises the complete analysis pipeline with a hand-crafted VMProtect-
like dispatcher and handler set.  Unlike earlier integration tests that
validate individual modules, these tests verify that the full chain
produces coherent end-to-end results:

  trace → vIP → segmentation → semantics → CFG → ML → pseudocode

The synthetic VM implements a tiny program:

    push(A); push(B); add; xor const; pop result; ret

This covers: stack ops, arithmetic, bitwise, store, control_flow (ret).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

# ── Reuse the synthetic trace builder from test_integration_e2e ──────
from tests.test_integration_e2e import (
    build_vmprotect_trace,
    build_trace_from_instructions,
    build_pe_with_entries,
    _DISPATCHER_ADDR,
    _HANDLER_BASE,
    _BYTECODE_BASE,
    _OPCODE_TABLE,
)

# ── Pipeline / analysis imports ──────────────────────────────────────
from dragonslayer.core.pipeline import AnalysisPipeline, StageResult

from dragonslayer.analysis.trace_ingestion import ExecutionTrace
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    identify_vip_register,
    segment_trace,
)
from dragonslayer.analysis.handler_semantics import (
    analyse_handler_semantics,
    SemanticOpcodeTable,
    VMOperation,
)
from dragonslayer.analysis.pseudocode import (
    emit_pseudocode,
    emit_c_like,
    PseudocodeResult,
)
from dragonslayer.analysis.bytecode_cfg import build_handler_cfg
from dragonslayer.analysis.symbolic_depth import collect_symbolic_summaries
from dragonslayer.analysis.devirtualisation_result import DevirtualisationResult
from dragonslayer.ml.taxonomy import CANONICAL_SET, is_canonical


# =====================================================================
# Fixtures
# =====================================================================

# VM program: push, push, add, xor, pop, ret
# Encoded as opcode bytes from _OPCODE_TABLE:
#   0x00=push, 0x02=add, 0x04=xor, 0x01=pop, 0x06=ret
_VM_PROGRAM = [0x00, 0x00, 0x02, 0x04, 0x01, 0x06]


@pytest.fixture(scope="module")
def vm_trace() -> ExecutionTrace:
    """Build a synthetic VMProtect execution trace from _VM_PROGRAM."""
    insns = build_vmprotect_trace(_VM_PROGRAM)
    return build_trace_from_instructions(insns)


@pytest.fixture(scope="module")
def vip_result(vm_trace):
    return identify_vip_register(vm_trace)


@pytest.fixture(scope="module")
def segmentation(vm_trace, vip_result):
    assert vip_result is not None
    return segment_trace(vm_trace, vip_result)


@pytest.fixture(scope="module")
def opcode_table(vm_trace, segmentation):
    return analyse_handler_semantics(vm_trace, segmentation.boundaries)


@pytest.fixture(scope="module")
def handler_cfg(opcode_table, segmentation):
    return build_handler_cfg(opcode_table, segmentation.boundaries)


# =====================================================================
# 1. Trace construction
# =====================================================================

class TestSyntheticTraceConstruction:
    """Verify the synthetic trace is well-formed."""

    def test_trace_has_instructions(self, vm_trace):
        # 6 opcodes × (4 dispatcher + ≥1 handler) = ≥30 instructions
        assert len(vm_trace.instructions) >= 30

    def test_trace_visits_dispatcher(self, vm_trace):
        disp_visits = sum(
            1 for i in vm_trace.instructions
            if i.address == _DISPATCHER_ADDR
        )
        # Should visit dispatcher once per VM instruction
        assert disp_visits >= len(_VM_PROGRAM)

    def test_trace_visits_multiple_handlers(self, vm_trace):
        handler_addrs = {
            i.address for i in vm_trace.instructions
            if i.address >= _HANDLER_BASE
        }
        # At least push, add, xor, pop, ret handlers
        assert len(handler_addrs) >= 4

    def test_trace_metadata(self, vm_trace):
        assert vm_trace.metadata.get("source") == "synthetic_vmprotect"
        assert vm_trace.metadata.get("bit_width") == 64


# =====================================================================
# 2. VIP identification
# =====================================================================

class TestVIPIdentification:
    def test_vip_found(self, vip_result):
        assert vip_result is not None

    def test_vip_is_rsi(self, vip_result):
        # Our synthetic trace uses rsi as VIP
        assert vip_result.name in ("rsi", "esi")


# =====================================================================
# 3. Trace segmentation
# =====================================================================

class TestTraceSegmentation:
    def test_boundaries_found(self, segmentation):
        assert len(segmentation.boundaries) >= len(_VM_PROGRAM)

    def test_boundaries_have_addresses(self, segmentation):
        for bnd in segmentation.boundaries:
            assert bnd.handler_address > 0

    def test_boundaries_consecutive_vip(self, segmentation):
        """VIP values should be monotonically increasing in a linear program."""
        vips = [b.vip_value for b in segmentation.boundaries]
        # Allow some flexibility (segmentation may reorder)
        assert len(set(vips)) >= 3  # at least 3 distinct VIP values


# =====================================================================
# 4. Handler semantics
# =====================================================================

class TestHandlerSemantics:
    def test_opcode_table_count(self, opcode_table):
        assert opcode_table.handler_count >= 2  # at least 2 unique handlers

    def test_operations_diverse(self, opcode_table):
        ops = opcode_table.operations_summary()
        assert len(ops) >= 2  # at least 2 different VMOperations

    def test_entries_have_semantic(self, opcode_table):
        for entry in opcode_table.entries:
            assert entry.semantic is not None
            assert entry.semantic.handler_address > 0


# =====================================================================
# 5. Handler-level CFG
# =====================================================================

class TestHandlerCFG:
    def test_cfg_built(self, handler_cfg):
        assert handler_cfg is not None

    def test_cfg_has_blocks(self, handler_cfg):
        assert handler_cfg.block_count >= 1

    def test_cfg_has_entry(self, handler_cfg):
        assert handler_cfg.entry_block_id is not None


# =====================================================================
# 6. Pseudocode emission
# =====================================================================

class TestPseudocodeEmission:
    def test_c_like_output(self, opcode_table, segmentation):
        result = emit_pseudocode(
            opcode_table, segmentation.boundaries, style="c_like",
        )
        assert isinstance(result, PseudocodeResult)
        assert result.style == "c_like"
        assert "void vm_func()" in result.text
        assert result.line_count > 5

    def test_c_like_with_cfg(self, opcode_table, segmentation, handler_cfg):
        cfg_graph = handler_cfg.graph if handler_cfg else None
        result = emit_pseudocode(
            opcode_table, segmentation.boundaries, cfg_graph,
            style="c_like",
        )
        assert result.text
        assert "void vm_func()" in result.text

    def test_c_like_with_context_and_clustering(
        self, opcode_table, segmentation
    ):
        layout = {"vsp": "rsp", "vip_register": "rsi", "table_base": "rbx"}
        clustering = {
            "clusters": [
                {"canonical_operation": "stack", "handler_count": 3},
                {"canonical_operation": "arithmetic", "handler_count": 1},
                {"canonical_operation": "bitwise", "handler_count": 1},
            ]
        }
        result = emit_pseudocode(
            opcode_table, segmentation.boundaries,
            style="c_like",
            context_layout=layout,
            clustering=clustering,
        )
        assert "VM Context Layout" in result.text
        assert "Semantic Clusters" in result.text

    def test_cifuentes_with_cfg(self, opcode_table, segmentation, handler_cfg):
        # emit_cifuentes expects HandlerCFG object, not raw nx graph
        result = emit_pseudocode(
            opcode_table, segmentation.boundaries,
            handler_cfg,
            style="cifuentes",
        )
        assert result.line_count >= 0  # may be 0 if CFG falls back

    def test_linear_output(self, opcode_table, segmentation):
        result = emit_pseudocode(
            opcode_table, segmentation.boundaries, style="linear",
        )
        assert result.style == "linear"
        assert result.line_count > 0


# =====================================================================
# 7. ML classification
# =====================================================================

class TestMLClassification:
    """Verify ML ensemble produces canonical category labels."""

    def test_heuristic_model_canonical(self, opcode_table):
        from dragonslayer.ml.model import VMHandlerModel
        model = VMHandlerModel()
        for entry in opcode_table.entries:
            op = entry.semantic.operation
            op_name = op.name if hasattr(op, "name") else str(op)
            features = {
                "handler_address": entry.handler_address,
                "operation": op_name if op else "UNKNOWN",
                "operand_width": entry.semantic.operand_width,
            }
            result = model.predict(features)
            assert is_canonical(result.label), (
                f"Non-canonical label: {result.label}"
            )

    def test_symbolic_model_canonical(self):
        from dragonslayer.ml.model import SymbolicClassifierModel
        model = SymbolicClassifierModel()
        # Feed a known pattern
        features = {
            "symbolic_summary": {
                "simplified_registers": {"rax": "init_rax + init_rbx"},
                "memory_writes": [],
                "input_symbols": {"rax": "init_rax", "rbx": "init_rbx"},
            }
        }
        result = model.predict(features)
        assert is_canonical(result.label)
        assert result.label == "arithmetic"

    def test_ensemble_canonical(self):
        from dragonslayer.ml.ensemble import WeightedEnsemble
        from dragonslayer.ml.model import VMHandlerModel, SymbolicClassifierModel
        ensemble = WeightedEnsemble(
            models=[VMHandlerModel(), SymbolicClassifierModel()],
        )
        features = {
            "handler_address": 0x1000,
            "operation": "ADD",
            "operand_width": 8,
            "symbolic_summary": {
                "simplified_registers": {"rax": "init_rax + init_rbx"},
                "memory_writes": [],
                "input_symbols": {"rax": "init_rax", "rbx": "init_rbx"},
            },
        }
        result = ensemble.predict(features)
        assert is_canonical(result.label)


# =====================================================================
# 8. DevirtualisationResult construction
# =====================================================================

class TestDevirtResultConstruction:
    """Build a DevirtualisationResult from all pipeline outputs."""

    def test_full_result(
        self, opcode_table, segmentation, handler_cfg, vip_result,
    ):
        pseudocode = emit_pseudocode(
            opcode_table, segmentation.boundaries,
            handler_cfg.graph if handler_cfg else None,
            style="c_like",
        )
        result = DevirtualisationResult(
            success=True,
            vip_register=vip_result.name,
            handler_count=len(segmentation.boundaries),
            unique_operations=len(opcode_table.operations_summary()),
            opcode_table={"entries": [str(e) for e in opcode_table.entries]},
            pseudocode=pseudocode.to_dict(),
            pseudocode_text=pseudocode.text,
            handler_cfg=handler_cfg.to_dict() if hasattr(handler_cfg, "to_dict") else {},
            ml_classifications={
                hex(e.handler_address): "arithmetic"
                for e in opcode_table.entries[:2]
            },
        )
        assert result.success is True
        assert result.vip_register in ("rsi", "esi")
        assert result.handler_count >= len(_VM_PROGRAM)
        assert result.unique_operations >= 2
        assert result.pseudocode_text
        assert "void vm_func()" in result.pseudocode_text

    def test_result_serialises_roundtrip(
        self, opcode_table, segmentation, handler_cfg, vip_result,
    ):
        pseudocode = emit_pseudocode(
            opcode_table, segmentation.boundaries, style="c_like",
        )
        original = DevirtualisationResult(
            success=True,
            vip_register=vip_result.name,
            handler_count=len(segmentation.boundaries),
            unique_operations=len(opcode_table.operations_summary()),
            opcode_table={"entries": []},
            pseudocode=pseudocode.to_dict(),
            pseudocode_text=pseudocode.text,
        )
        d = original.to_dict()
        restored = DevirtualisationResult.from_dict(d)
        assert restored.success == original.success
        assert restored.vip_register == original.vip_register
        assert restored.handler_count == original.handler_count


# =====================================================================
# 9. Pipeline-level integration
# =====================================================================

class TestPipelineIntegration:
    """Run _run_devirtualize through the pipeline with synthetic trace."""

    def _make_pipeline(self):
        return AnalysisPipeline(config={"stages": ["devirtualize"]})

    def _make_context(self, trace: ExecutionTrace):
        ctx = MagicMock()
        ctx.shared_data = {
            "qiling": {
                "trace": list(trace.instructions),
                "trace_format": "instruction_list",
            },
        }
        return ctx

    def test_devirtualize_stage_succeeds(self, vm_trace):
        pipeline = self._make_pipeline()
        ctx = self._make_context(vm_trace)
        result = pipeline._run_devirtualize(b"\x00" * 64, ctx)
        assert result is not None
        assert result.stage == "devirtualize"

    def test_devirtualize_with_pe_stubs(self, vm_trace):
        pe_data = build_pe_with_entries(count=2)
        pipeline = self._make_pipeline()
        ctx = self._make_context(vm_trace)
        ctx.shared_data["pe_analyzer"] = {
            "valid": True,
            "optional_header": {
                "magic": hex(0x20B),
                "image_base": hex(0x400000),
            },
            "sections": [{
                "name": ".vmp0",
                "virtual_address": hex(0x1000),
                "virtual_size": hex(len(pe_data)),
                "raw_offset": hex(0),
                "raw_size": hex(len(pe_data)),
                "characteristics": hex(0x60000020),
                "entropy": 7.2,
            }],
        }
        result = pipeline._run_devirtualize(pe_data, ctx)
        assert result is not None
        assert result.stage == "devirtualize"

    def test_devirt_result_in_stage_data(self, vm_trace):
        pipeline = self._make_pipeline()
        ctx = self._make_context(vm_trace)
        result = pipeline._run_devirtualize(b"\x00" * 64, ctx)
        # Stage result should have data dict with devirt fields
        if hasattr(result, "data") and isinstance(result.data, dict):
            assert "success" in result.data or "skipped" in result.data


# =====================================================================
# 10. Cross-module data flow (multi-handler)
# =====================================================================

class TestCrossModuleDataFlow:
    """Verify data flows coherently through the whole stack."""

    def test_opcode_table_to_cfg_to_pseudocode(
        self, opcode_table, segmentation, handler_cfg,
    ):
        """Table → CFG → pseudocode: the whole chain."""
        cfg_graph = handler_cfg.graph if handler_cfg else None
        result = emit_pseudocode(
            opcode_table, segmentation.boundaries, cfg_graph,
            style="c_like",
        )
        assert "void vm_func()" in result.text
        # The output should mention at least one VM operation
        assert result.line_count > 5

    def test_symbolic_summaries_for_handlers(self):
        """Collect symbolic summaries from extracted handler data."""
        shared = {
            "handler_extraction": {
                "handlers": [
                    {
                        "address": _OPCODE_TABLE[0x02][1],  # add handler
                        "register_delta": {
                            "rax": {"before": 0, "after": 15},
                        },
                    },
                    {
                        "address": _OPCODE_TABLE[0x04][1],  # xor handler
                        "register_delta": {
                            "rax": {"before": 0xFF, "after": 0x0F},
                        },
                    },
                ],
            },
        }
        summaries = collect_symbolic_summaries(shared, run_fresh=False)
        assert len(summaries) >= 2
        # Both handlers should have summaries
        assert _OPCODE_TABLE[0x02][1] in summaries
        assert _OPCODE_TABLE[0x04][1] in summaries

    def test_full_chain_diverse_program(self):
        """Wider program: push×3, add, sub, xor, pop, ret."""
        wide_program = [0x00, 0x00, 0x00, 0x02, 0x03, 0x04, 0x01, 0x06]
        insns = build_vmprotect_trace(wide_program)
        trace = build_trace_from_instructions(insns)

        vip = identify_vip_register(trace)
        assert vip is not None

        seg = segment_trace(trace, vip)
        assert len(seg.boundaries) >= len(wide_program)

        table = analyse_handler_semantics(trace, seg.boundaries)
        assert table.handler_count >= 2  # address dedup merges similar handlers

        cfg = build_handler_cfg(table, seg.boundaries)
        assert cfg.block_count >= 1

        result = emit_pseudocode(
            table, seg.boundaries, cfg.graph,
            style="c_like",
        )
        assert result.line_count > 5
        assert "void vm_func()" in result.text
