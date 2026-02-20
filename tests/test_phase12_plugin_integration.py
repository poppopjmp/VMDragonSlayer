"""
Phase 12 — Plugin ↔ Analysis Integration Tests
================================================

Tests that dynamic plugin output (Qiling, angr, Triton) flows through
``trace_ingestion`` into the taint-tracking and symbolic-execution
pipeline stages, preserving register snapshots, taint flags, and path
constraints.
"""

from __future__ import annotations

import copy
import time
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest


# ======================================================================
# Helpers
# ======================================================================

def _make_qiling_shared(
    *,
    n_insns: int = 4,
    base: int = 0x400000,
) -> Dict[str, Any]:
    """Synthesise a ``shared_data["qiling"]`` dict with register snapshots."""
    x86_bytes = [
        bytes([0x48, 0x89, 0xC3]),       # mov rbx, rax
        bytes([0x48, 0x01, 0xD8]),       # add rax, rbx
        bytes([0x48, 0x31, 0xC9]),       # xor rcx, rcx
        bytes([0x48, 0xFF, 0xC0]),       # inc rax
    ]
    insns = []
    addr = base
    for i in range(min(n_insns, len(x86_bytes))):
        raw = x86_bytes[i]
        insns.append({
            "address": addr,
            "size": len(raw),
            "raw_bytes": raw.hex(),
            "disassembly": f"insn_{i}",
            "registers": {"rax": 0x100 + i, "rbx": 0x200 + i, "rcx": 0x300 + i},
            "memory_accesses": [],
        })
        addr += len(raw)
    return {
        "qiling": {
            "instruction_trace": insns,
            "memory_accesses": [],
            "confidence": 0.9,
        },
    }


def _make_triton_shared(
    *,
    n_insns: int = 3,
    base: int = 0x500000,
    with_taint: bool = True,
    with_constraints: bool = True,
) -> Dict[str, Any]:
    """Synthesise ``shared_data["triton"]`` with taint flow + path constraints."""
    x86_bytes = [
        bytes([0x48, 0x89, 0xC3]),       # mov rbx, rax
        bytes([0x48, 0x01, 0xD8]),       # add rax, rbx
        bytes([0x48, 0x31, 0xC9]),       # xor rcx, rcx
    ]
    insns = []
    taint_flow = []
    addr = base
    for i in range(min(n_insns, len(x86_bytes))):
        raw = x86_bytes[i]
        insns.append({
            "address": addr,
            "size": len(raw),
            "raw_bytes": raw.hex(),
            "disassembly": f"triton_insn_{i}",
            "registers": {"rax": 0xA00 + i, "rsp": 0x7FFF00},
        })
        if with_taint:
            taint_flow.append({
                "address": addr,
                "is_tainted": i < 2,  # first two are tainted
                "disasm": f"triton_insn_{i}",
                "tainted_regs": ["rax"] if i == 0 else [],
            })
        addr += len(raw)

    constraints = []
    if with_constraints:
        constraints = [
            {"type": "branch", "address": base, "expression": "rax == 42"},
            {"type": "branch", "address": base + 3, "expression": "rbx != 0"},
        ]

    return {
        "triton": {
            "instruction_trace": insns,
            "taint_flow": taint_flow,
            "path_constraints": constraints,
            "memory_accesses": [],
            "confidence": 0.95,
        },
    }


def _make_angr_shared(
    *,
    n_handlers: int = 2,
    base: int = 0x600000,
) -> Dict[str, Any]:
    """Synthesise ``shared_data["angr"]`` with handler traces."""
    x86_bytes = [
        bytes([0x48, 0x89, 0xC3]),       # mov rbx, rax
        bytes([0x48, 0x01, 0xD8]),       # add rax, rbx
    ]
    handlers = []
    addr = base
    for h in range(n_handlers):
        handler_insns = []
        for i, raw in enumerate(x86_bytes):
            handler_insns.append({
                "address": addr,
                "size": len(raw),
                "raw_bytes": raw.hex(),
                "disassembly": f"angr_h{h}_insn_{i}",
                "registers": {"rax": 0xB00 + h * 10 + i},
            })
            addr += len(raw)
        handlers.append({"instructions": handler_insns})

    return {
        "angr": {
            "handler_traces": handlers,
            "arch": "x86_64",
            "entry_point": base,
            "functions": [],
            "confidence": 0.85,
        },
    }


def _make_combined_shared(**kwargs: Any) -> Dict[str, Any]:
    """Merge Qiling + Triton + angr shared_data (non-overlapping addrs)."""
    sd: Dict[str, Any] = {}
    sd.update(_make_qiling_shared(**kwargs))
    sd.update(_make_triton_shared(**kwargs))
    sd.update(_make_angr_shared(**kwargs))
    return sd


def _make_pipeline_ctx(shared_data: Dict[str, Any]) -> SimpleNamespace:
    """Build a minimal pipeline context object."""
    return SimpleNamespace(shared_data=dict(shared_data))


# ======================================================================
# 1. LiftedInstruction now carries registers + is_tainted
# ======================================================================

class TestLiftedInstructionFields:
    """LiftedInstruction has ``registers`` and ``is_tainted`` fields."""

    def test_defaults(self):
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        li = LiftedInstruction(
            address=0, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
        )
        assert li.registers == {}
        assert li.is_tainted is False

    def test_explicit(self):
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        li = LiftedInstruction(
            address=0, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
            registers={"rax": 42}, is_tainted=True,
        )
        assert li.registers == {"rax": 42}
        assert li.is_tainted is True

    def test_to_dict_includes_registers(self):
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        li = LiftedInstruction(
            address=0, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
            registers={"rax": 1}, is_tainted=True,
        )
        d = li.to_dict()
        assert d["registers"] == {"rax": 1}
        assert d["is_tainted"] is True

    def test_to_dict_omits_empty(self):
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        li = LiftedInstruction(
            address=0, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
        )
        d = li.to_dict()
        assert "registers" not in d
        assert "is_tainted" not in d


# ======================================================================
# 2. trace_ingestion preserves registers and taint through lifting
# ======================================================================

class TestTraceIngestionPreserves:
    """to_lifted_instructions() preserves register snapshots & taint."""

    def test_qiling_registers_preserved(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_qiling_shared()
        trace = from_shared_data(sd)
        lifted = trace.to_lifted_instructions()
        assert len(lifted) >= 1
        # First instruction should carry the register snapshot from Qiling
        first = lifted[0]
        assert hasattr(first, "registers")
        assert first.registers.get("rax") == 0x100

    def test_triton_taint_flags_preserved(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_triton_shared(with_taint=True)
        trace = from_shared_data(sd)
        lifted = trace.to_lifted_instructions()
        assert len(lifted) >= 2
        # First two instructions are tainted per our test data
        assert lifted[0].is_tainted is True
        assert lifted[1].is_tainted is True
        # Third is NOT tainted
        if len(lifted) >= 3:
            assert lifted[2].is_tainted is False

    def test_triton_path_constraints_in_metadata(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_triton_shared(with_constraints=True)
        trace = from_shared_data(sd)
        assert len(trace.metadata.get("path_constraints", [])) == 2

    def test_angr_registers_preserved(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_angr_shared()
        trace = from_shared_data(sd)
        lifted = trace.to_lifted_instructions()
        assert len(lifted) >= 1
        first = lifted[0]
        assert first.registers.get("rax") == 0xB00

    def test_combined_sources_merged(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_combined_shared()
        trace = from_shared_data(sd)
        # Should have instructions from all three sources
        assert len(trace.instructions) >= 3

    def test_simple_instruction_carries_registers(self):
        """When capstone is unavailable, _SimpleInstruction must still
        carry registers and is_tainted."""
        from dragonslayer.analysis.trace_ingestion import (
            ExecutionTrace,
            TraceInstruction,
        )
        trace = ExecutionTrace(source="test")
        trace.instructions.append(TraceInstruction(
            address=0x1000, size=3, raw_bytes=b"",  # empty → forces simple path
            disassembly="mov rax, rbx",
            registers={"rax": 99},
        ))
        trace.metadata["taint_flow_raw"] = [
            {"address": 0x1000, "is_tainted": True},
        ]
        lifted = trace.to_lifted_instructions()
        assert len(lifted) == 1
        assert lifted[0].registers == {"rax": 99}
        assert lifted[0].is_tainted is True


# ======================================================================
# 3. Pipeline taint stage uses plugin traces
# ======================================================================

class TestTaintStagePluginIntegration:
    """_run_taint_analysis prefers dynamic plugin traces over raw binary."""

    def _build_pipeline(self):
        from dragonslayer.core.pipeline import AnalysisPipeline
        return AnalysisPipeline.__new__(AnalysisPipeline)

    def test_taint_stage_uses_qiling_trace(self):
        pipe = self._build_pipeline()
        sd = _make_qiling_shared()
        sd["vm_discovery"] = {"vm_detected": False, "dispatcher_addresses": []}
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_taint_analysis(b"\x90", ctx)
        assert result.success is True
        # The taint result should exist
        assert "taint_results" in ctx.shared_data

    def test_taint_stage_uses_triton_trace(self):
        pipe = self._build_pipeline()
        sd = _make_triton_shared()
        sd["vm_discovery"] = {"vm_detected": False, "dispatcher_addresses": []}
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_taint_analysis(b"\x90", ctx)
        assert result.success is True
        assert "taint_results" in ctx.shared_data

    def test_taint_stage_falls_back_to_binary(self):
        """When no dynamic plugins are present, lifts from binary_data."""
        pipe = self._build_pipeline()
        # NOP sled - valid x86
        binary = b"\x90" * 8
        sd = {"vm_discovery": {"vm_detected": False, "dispatcher_addresses": []}}
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_taint_analysis(binary, ctx)
        assert result.success is True

    def test_taint_stage_with_vm_detected(self):
        pipe = self._build_pipeline()
        sd = _make_qiling_shared()
        sd["vm_discovery"] = {
            "vm_detected": True,
            "vm_type": "VMProtect",
            "dispatcher_addresses": [0x400000],
        }
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_taint_analysis(b"\x90", ctx)
        assert result.success is True


# ======================================================================
# 4. Pipeline symbolic stage uses plugin traces
# ======================================================================

class TestSymbolicStagePluginIntegration:
    """_run_symbolic_execution uses plugin code regions and forwards
    Triton path constraints."""

    def _build_pipeline(self):
        from dragonslayer.core.pipeline import AnalysisPipeline
        return AnalysisPipeline.__new__(AnalysisPipeline)

    def test_symbolic_stage_uses_triton_regions(self):
        pipe = self._build_pipeline()
        sd = _make_triton_shared(with_constraints=True)
        sd["vm_discovery"] = {"dispatcher_addresses": []}
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_symbolic_execution(b"\x90", ctx)
        assert result.success is True
        assert "symbolic_execution" in ctx.shared_data

    def test_symbolic_stage_forwards_path_constraints(self):
        pipe = self._build_pipeline()
        sd = _make_triton_shared(with_constraints=True)
        sd["vm_discovery"] = {"dispatcher_addresses": []}
        ctx = _make_pipeline_ctx(sd)

        pipe._run_symbolic_execution(b"\x90", ctx)
        # Path constraints should be in shared_data
        assert "_triton_path_constraints" in ctx.shared_data
        assert len(ctx.shared_data["_triton_path_constraints"]) == 2

    def test_symbolic_stage_uses_angr_regions(self):
        pipe = self._build_pipeline()
        sd = _make_angr_shared()
        sd["vm_discovery"] = {"dispatcher_addresses": []}
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_symbolic_execution(b"\x90", ctx)
        assert result.success is True

    def test_symbolic_stage_falls_back_to_binary(self):
        pipe = self._build_pipeline()
        binary = b"\x90" * 16
        sd = {"vm_discovery": {"dispatcher_addresses": []}}
        ctx = _make_pipeline_ctx(sd)

        result = pipe._run_symbolic_execution(binary, ctx)
        assert result.success is True


# ======================================================================
# 5. DTTExecutor accepts Triton taint seeds
# ======================================================================

class TestDTTExecutorTritonSeeding:
    """DTTExecutor can be seeded from Triton taint_flow data."""

    def _make_insns(self):
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        return [
            LiftedInstruction(
                address=0x1000, size=3, mnemonic="mov", operands="rbx, rax",
                category="memory_read", raw_bytes=b"\x48\x89\xc3",
                reads=["rax"], writes=["rbx"],
                registers={"rax": 0x100},
            ),
            LiftedInstruction(
                address=0x1003, size=3, mnemonic="add", operands="rcx, rbx",
                category="arithmetic", raw_bytes=b"\x48\x01\xd9",
                reads=["rcx", "rbx"], writes=["rcx"],
            ),
        ]

    def test_triton_taint_flow_seeds_registers(self):
        from dragonslayer.analysis.taint_tracking.dtt_executor import DTTExecutor
        dtt = DTTExecutor()
        taint_flow = [
            {"address": 0x1000, "is_tainted": True, "tainted_regs": ["rax"]},
        ]
        result = dtt.execute(
            self._make_insns(),
            triton_taint_flow=taint_flow,
        )
        assert result["success"]
        assert "rax" in result["triton_seeded_registers"]
        # rax was tainted → mov rbx,rax → rbx tainted → add rcx,rbx → rcx tainted
        assert "rcx" in result["final_tainted_registers"]

    def test_is_tainted_flag_auto_seeds(self):
        from dragonslayer.analysis.taint_tracking.dtt_executor import DTTExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction

        insns = [
            LiftedInstruction(
                address=0x2000, size=3, mnemonic="mov", operands="rbx, rax",
                category="memory_read", raw_bytes=b"\x48\x89\xc3",
                reads=["rax"], writes=["rbx"],
                is_tainted=True,
            ),
            LiftedInstruction(
                address=0x2003, size=3, mnemonic="add", operands="rcx, rbx",
                category="arithmetic", raw_bytes=b"\x48\x01\xd9",
                reads=["rcx", "rbx"], writes=["rcx"],
            ),
        ]
        dtt = DTTExecutor()
        result = dtt.execute(insns)
        assert result["success"]
        # rbx is written by the first tainted instruction → seeded
        assert "rbx" in result["triton_seeded_registers"]

    def test_no_triton_data_still_works(self):
        from dragonslayer.analysis.taint_tracking.dtt_executor import DTTExecutor
        dtt = DTTExecutor()
        result = dtt.execute(
            self._make_insns(),
            taint_sources={"rax": "input"},
        )
        assert result["success"]
        assert result["triton_seeded_registers"] == []


# ======================================================================
# 6. Register snapshot flows to taint tracker memory resolution
# ======================================================================

class TestRegisterSnapshotTaintResolution:
    """Register snapshots from traces enable concrete memory-address
    resolution in the taint tracker."""

    def test_memory_read_resolved_via_registers(self):
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction

        tracker = TaintTracker()
        # Taint memory at address 0xDEAD
        tracker.taint_memory(0xDEAD, TaintTag.INPUT)

        insn = LiftedInstruction(
            address=0x1000, size=3, mnemonic="mov", operands="rax, [rbx]",
            category="memory_read", raw_bytes=b"\x48\x8b\x03",
            reads=["rbx"], writes=["rax"],
            registers={"rbx": 0xDEAD},  # from plugin trace
        )
        tracker.process_instruction(insn)
        # rax should be tainted because [rbx] = [0xDEAD] is tainted
        assert tracker.is_tainted("rax")

    def test_memory_write_resolved_via_registers(self):
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction

        tracker = TaintTracker()
        tracker.taint_register("rax", TaintTag.INPUT)

        insn = LiftedInstruction(
            address=0x1000, size=3, mnemonic="mov", operands="[rbx], rax",
            category="memory_write", raw_bytes=b"\x48\x89\x03",
            reads=["rax", "rbx"], writes=[],
            registers={"rbx": 0xBEEF},
        )
        tracker.process_instruction(insn)
        # Memory at 0xBEEF should now be tainted
        assert tracker.mem_taint.get(0xBEEF, TaintTag.CLEAN) != TaintTag.CLEAN


# ======================================================================
# 7. ExecutionTrace.extract_code_regions
# ======================================================================

class TestExtractCodeRegions:
    """extract_code_regions produces contiguous blobs from trace."""

    def test_single_region(self):
        from dragonslayer.analysis.trace_ingestion import ExecutionTrace, TraceInstruction
        trace = ExecutionTrace()
        trace.instructions = [
            TraceInstruction(address=0x1000, size=3, raw_bytes=b"\x48\x89\xc3", disassembly="mov rbx, rax"),
            TraceInstruction(address=0x1003, size=3, raw_bytes=b"\x48\x01\xd8", disassembly="add rax, rbx"),
        ]
        regions = trace.extract_code_regions()
        assert len(regions) == 1
        assert 0x1000 in regions
        assert regions[0x1000] == b"\x48\x89\xc3\x48\x01\xd8"

    def test_gap_produces_two_regions(self):
        from dragonslayer.analysis.trace_ingestion import ExecutionTrace, TraceInstruction
        trace = ExecutionTrace()
        trace.instructions = [
            TraceInstruction(address=0x1000, size=3, raw_bytes=b"\x90\x90\x90", disassembly="nop*3"),
            TraceInstruction(address=0x2000, size=2, raw_bytes=b"\xcc\xcc", disassembly="int3*2"),
        ]
        regions = trace.extract_code_regions()
        assert len(regions) == 2
        assert 0x1000 in regions
        assert 0x2000 in regions


# ======================================================================
# 8. End-to-end: Qiling trace → taint tracker with memory resolution
# ======================================================================

class TestEndToEndQilingTaint:
    """Full path: Qiling shared_data → trace_ingestion → taint tracker."""

    def test_qiling_trace_feeds_taint_tracker(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag

        sd = _make_qiling_shared()
        trace = from_shared_data(sd)
        lifted = trace.to_lifted_instructions()
        assert len(lifted) >= 1

        tracker = TaintTracker()
        # Taint rax initially (coming from VM bytecode)
        tracker.taint_register("rax", TaintTag.VM_OPERAND)
        result = tracker.analyze(lifted)
        assert result.success
        assert result.instructions_analyzed >= 1


# ======================================================================
# 9. End-to-end: Triton trace → DTTExecutor with taint seeding
# ======================================================================

class TestEndToEndTritonDTT:
    """Full path: Triton shared_data → trace_ingestion → DTTExecutor."""

    def test_triton_trace_feeds_dtt(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        from dragonslayer.analysis.taint_tracking.dtt_executor import DTTExecutor

        sd = _make_triton_shared(with_taint=True)
        trace = from_shared_data(sd)
        lifted = trace.to_lifted_instructions()

        taint_flow = sd["triton"].get("taint_flow", [])
        dtt = DTTExecutor()
        result = dtt.execute(lifted, triton_taint_flow=taint_flow)
        assert result["success"]
        assert result["instructions_processed"] >= 1


# ======================================================================
# 10. taint_flow_raw metadata is preserved in trace
# ======================================================================

class TestTaintFlowRawMetadata:
    """_ingest_triton stores taint_flow_raw in trace.metadata."""

    def test_taint_flow_raw_present(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_triton_shared(with_taint=True)
        trace = from_shared_data(sd)
        raw = trace.metadata.get("taint_flow_raw", [])
        assert len(raw) >= 1
        assert raw[0]["address"] == 0x500000

    def test_no_triton_no_taint_flow_raw(self):
        from dragonslayer.analysis.trace_ingestion import from_shared_data
        sd = _make_qiling_shared()
        trace = from_shared_data(sd)
        # taint_flow_raw should be absent or empty
        raw = trace.metadata.get("taint_flow_raw", [])
        assert raw == [] or raw is None or len(raw) == 0


# ======================================================================
# 11. _SimpleInstruction duck-types with registers and is_tainted
# ======================================================================

class TestSimpleInstructionCompatibility:
    """_SimpleInstruction has registers and is_tainted fields."""

    def test_fields_exist(self):
        from dragonslayer.analysis.trace_ingestion import _SimpleInstruction
        si = _SimpleInstruction(
            address=0, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
        )
        assert si.registers == {}
        assert si.is_tainted is False

    def test_fields_settable(self):
        from dragonslayer.analysis.trace_ingestion import _SimpleInstruction
        si = _SimpleInstruction(
            address=0, size=1, mnemonic="nop", operands="",
            category="nop", raw_bytes=b"\x90",
            registers={"rax": 7}, is_tainted=True,
        )
        assert si.registers == {"rax": 7}
        assert si.is_tainted is True


# ======================================================================
# 12. Pipeline stages report trace_source provenance
# ======================================================================

class TestTraceProvenance:
    """Pipeline stages annotate results with trace provenance."""

    def _build_pipeline(self):
        from dragonslayer.core.pipeline import AnalysisPipeline
        return AnalysisPipeline.__new__(AnalysisPipeline)

    def test_symbolic_stage_annotates_plugin_source(self):
        pipe = self._build_pipeline()
        sd = _make_triton_shared()
        sd["vm_discovery"] = {"dispatcher_addresses": []}
        ctx = _make_pipeline_ctx(sd)

        pipe._run_symbolic_execution(b"\x90", ctx)
        sym_data = ctx.shared_data.get("symbolic_execution", {})
        assert sym_data.get("trace_source") == "plugin"
        assert sym_data.get("trace_region_count", 0) >= 1

    def test_symbolic_stage_no_annotation_without_plugins(self):
        pipe = self._build_pipeline()
        sd = {"vm_discovery": {"dispatcher_addresses": []}}
        ctx = _make_pipeline_ctx(sd)

        pipe._run_symbolic_execution(b"\x90" * 8, ctx)
        sym_data = ctx.shared_data.get("symbolic_execution", {})
        assert "trace_source" not in sym_data
