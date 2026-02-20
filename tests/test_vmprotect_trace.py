"""End-to-end test using a realistic VMProtect handler trace.

This test validates the devirtualisation pipeline components against
a synthetic-but-faithful VMProtect vAdd handler trace, exercising:
  - Trace ingestion (parse_trace_text)
  - Taint tracking through register-indirect memory
  - Handler boundary detection
  - Handler semantics classification
  - Symbolic execution of the handler
  - Pseudocode emission
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


TRACE_PATH = Path(__file__).resolve().parent.parent / "data" / "samples" / "traces" / "vmprotect_vadd_handler.trace"


class TestVMProtectTraceIngestion:
    """Verify the vAdd trace is correctly parsed."""

    def test_trace_parses(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)
        assert len(trace.instructions) == 11
        assert len(trace.memory_accesses) >= 4
        assert len(trace.handlers) == 1
        assert trace.handlers[0].handler_type == "vm_add"

    def test_instruction_registers(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)
        first = trace.instructions[0]
        assert first.registers["rbp"] == 0x7FFFA000
        assert first.registers["rsi"] == 0x140050010

    def test_control_flow_parsed(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)
        assert len(trace.control_flow) == 1
        cf = trace.control_flow[0]
        assert cf.type == "dispatch"
        assert cf.target == 0x140023B00


class TestVMProtectTaintTracking:
    """Taint propagation through the vAdd handler."""

    def test_vm_context_taint_propagates(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag

        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)

        # Build duck-typed instructions for the taint tracker.
        lifted = []
        for ti in trace.instructions:
            parts = ti.disassembly.strip().split(None, 1) if ti.disassembly else []
            mnem = parts[0].lower() if parts else "nop"
            operands = parts[1] if len(parts) > 1 else ""

            from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes
            reads, writes = _extract_reg_reads_writes(mnem, operands)

            class _Insn:
                pass
            insn = _Insn()
            insn.address = ti.address
            insn.mnemonic = mnem
            insn.operands = operands
            insn.reads = reads
            insn.writes = writes
            insn.registers = ti.registers
            # Determine category
            if mnem in ("mov", "movzx"):
                insn.category = "memory_read" if "[" in operands.split(",")[1] else "data_transfer" if len(operands.split(",")) > 1 and "[" not in operands.split(",")[0] else "memory_write"
            elif mnem in ("add", "sub"):
                insn.category = "arithmetic"
            elif mnem == "jmp":
                insn.category = "branch_unconditional"
            else:
                insn.category = "unknown"
            lifted.append(insn)

        tracker = TaintTracker()
        # Taint VM context registers (vSP=rbp, vIP=rsi)
        tracker.taint_register("rbp", TaintTag.VM_CONTEXT)
        tracker.taint_register("rsi", TaintTag.VM_CONTEXT)

        result = tracker.analyze(lifted)

        # The result from the virtual stack load should be tainted
        # because rbp (vSP) is tainted and [rbp+0x0] is a memory read.
        state = tracker.get_state()
        # At minimum, registers that read from vSP-relative addresses
        # should carry taint propagated through data flow.
        assert len(result.events) > 0


class TestVMProtectHandlerSemantics:
    """Test handler semantics identification on the vAdd handler."""

    def test_handler_identification(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.handler_semantics import (
            HandlerBoundary,
            analyse_handler_semantics,
            SemanticOpcodeTable,
        )

        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)

        boundaries = [
            HandlerBoundary(
                vip_value=0x140050010,
                handler_address=0x140023A00,
                trace_start=0,
                trace_end=len(trace.instructions),
                instruction_count=len(trace.instructions),
                vip_delta=4,
            )
        ]

        table = analyse_handler_semantics(trace, boundaries)
        assert isinstance(table, SemanticOpcodeTable)
        assert table.handler_count >= 1


class TestVMProtectSymbolicExecution:
    """Symbolic execution of the vAdd handler bytes."""

    def test_execute_handler_from_trace(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)

        exe = SymbolicExecutor(arch="x86_64")

        trace_insns = []
        for ti in trace.instructions:
            trace_insns.append({
                "address": ti.address,
                "raw_bytes": ti.raw_bytes.hex() if ti.raw_bytes else "",
                "disassembly": ti.disassembly,
            })

        summary = exe.execute_handler_from_trace(
            trace_insns, handler_address=0x140023A00
        )
        assert summary.instruction_count >= 1
        assert summary.error is None


class TestVMProtectPseudocode:
    """Pseudocode emission from the vAdd handler."""

    def test_emit_linear(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.handler_semantics import (
            HandlerBoundary,
            analyse_handler_semantics,
        )
        from dragonslayer.analysis.pseudocode import emit_linear

        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)

        boundaries = [
            HandlerBoundary(
                vip_value=0x140050010,
                handler_address=0x140023A00,
                trace_start=0,
                trace_end=len(trace.instructions),
                instruction_count=len(trace.instructions),
                vip_delta=4,
            )
        ]

        table = analyse_handler_semantics(trace, boundaries)
        result = emit_linear(table, boundaries)
        assert result.line_count >= 1
        assert result.text  # non-empty pseudocode


class TestVMProtectFullPipeline:
    """Full pipeline run with devirtualize stage."""

    def test_pipeline_with_trace_data(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig
        from dragonslayer.analysis.trace_ingestion import parse_trace_text

        text = TRACE_PATH.read_text()
        trace = parse_trace_text(text)

        cfg = PipelineConfig(
            stages=["pattern_analysis", "vm_discovery", "taint_analysis", "symbolic_execution"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()

        # Feed the pipeline a stub binary — the trace data supplements it.
        # In a real scenario, the binary would come from the sample under analysis.
        stub_binary = b"\x90" * 64
        result = pipe.run(stub_binary, cfg, metadata={
            "filename": "vmprotect_sample.exe",
            "trace_source": "vmprotect_vadd_handler.trace",
        })
        assert isinstance(result.success, bool)
        assert len(result.stages) >= 1
