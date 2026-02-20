"""Integration tests exercising the full devirtualisation pipeline.

These tests wire together:
- trace_ingestion (from_shared_data / from_triton_result)
- handler_boundaries (identify_vip_register / segment_trace)
- handler_semantics (analyse_handler_semantics)
- pseudocode (emit_pseudocode / emit_c_like)
- mba_simplifier (simplify_mba / verify_equivalence)
- symbolic_execution (execute_handler / Z3Solver)
- ml.classifier (VMClassifier.classify)
- ml.trainer (prepare_training_data / label_from_heuristics)

The goal is to confirm all components interoperate correctly on
synthetic but realistic data.
"""

from __future__ import annotations

import z3
import pytest

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceMemoryAccess,
    from_shared_data,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    identify_vip_register,
    segment_trace,
    HandlerBoundary,
)
from dragonslayer.analysis.handler_semantics import (
    analyse_handler_semantics,
    SemanticOpcodeTable,
    VMOperation,
)
from dragonslayer.analysis.pseudocode import (
    emit_linear,
    emit_structured,
    emit_c_like,
    emit_pseudocode,
)
from dragonslayer.analysis.mba_simplifier import (
    simplify_mba,
    simplify_expr,
    simplify_batch,
    verify_equivalence,
    MBAResult,
)
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    HandlerSymbolicSummary,
)
from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
from dragonslayer.ml.classifier import VMClassifier
from dragonslayer.ml.pipeline import extract_handler_features
from dragonslayer.ml.model import VMHandlerModel, PredictionResult
from dragonslayer.ml.trainer import (
    ModelTrainer,
    prepare_training_data,
    label_from_heuristics,
    TrainingResult,
)


# ---------------------------------------------------------------------------
# Helpers — synthetic traces
# ---------------------------------------------------------------------------

def _make_trace() -> ExecutionTrace:
    """Build a synthetic execution trace with 12 instructions.

    Simulates a VM dispatcher loop → handler pattern:
    - Instructions 0-2: dispatcher (read/modify vIP register rcx)
    - Instructions 3-5: POP handler (push/pop pattern)
    - Instructions 6-8: ADD handler (add pattern)
    - Instructions 9-11: PUSH handler (mov + push pattern)
    """
    insns = [
        # --- Dispatcher (0-2) ---
        TraceInstruction(address=0x4000, size=3,
                         disassembly="mov rax, [rcx]",
                         raw_bytes=b"\x48\x8b\x01",
                         registers={"rcx": 0x100, "rax": 0}),
        TraceInstruction(address=0x4003, size=4,
                         disassembly="add rcx, 4",
                         raw_bytes=b"\x48\x83\xc1\x04",
                         registers={"rcx": 0x104}),
        TraceInstruction(address=0x4007, size=2,
                         disassembly="jmp rax",
                         raw_bytes=b"\xff\xe0",
                         registers={"rcx": 0x104, "rax": 0x5000}),

        # --- Handler 1: POP (3-5) at 0x5000 ---
        TraceInstruction(address=0x5000, size=1,
                         disassembly="pop rbx",
                         raw_bytes=b"\x5b",
                         registers={"rcx": 0x104, "rbx": 0x42}),
        TraceInstruction(address=0x5001, size=4,
                         disassembly="add rcx, 4",
                         raw_bytes=b"\x48\x83\xc1\x04",
                         registers={"rcx": 0x108}),
        TraceInstruction(address=0x5005, size=2,
                         disassembly="jmp 0x4000",
                         raw_bytes=b"\xeb\xe0",
                         registers={"rcx": 0x108}),

        # --- Handler 2: ADD (6-8) at 0x6000 ---
        TraceInstruction(address=0x6000, size=3,
                         disassembly="add rax, rbx",
                         raw_bytes=b"\x48\x01\xd8",
                         registers={"rcx": 0x108, "rax": 0x10, "rbx": 0x42}),
        TraceInstruction(address=0x6003, size=4,
                         disassembly="add rcx, 4",
                         raw_bytes=b"\x48\x83\xc1\x04",
                         registers={"rcx": 0x10C}),
        TraceInstruction(address=0x6007, size=2,
                         disassembly="jmp 0x4000",
                         raw_bytes=b"\xeb\xe0",
                         registers={"rcx": 0x10C}),

        # --- Handler 3: PUSH (9-11) at 0x7000 ---
        TraceInstruction(address=0x7000, size=1,
                         disassembly="push rax",
                         raw_bytes=b"\x50",
                         registers={"rcx": 0x10C, "rax": 0x52}),
        TraceInstruction(address=0x7001, size=4,
                         disassembly="add rcx, 4",
                         raw_bytes=b"\x48\x83\xc1\x04",
                         registers={"rcx": 0x110}),
        TraceInstruction(address=0x7005, size=2,
                         disassembly="jmp 0x4000",
                         raw_bytes=b"\xeb\xe0",
                         registers={"rcx": 0x110}),
    ]
    return ExecutionTrace(instructions=insns)


def _make_triton_shared_data() -> dict:
    """Return shared_data dict mimicking Triton plugin enriched output."""
    return {
        "triton": {
            "instruction_trace": [
                {
                    "address": 0x5000,
                    "size": 1,
                    "disassembly": "pop rbx",
                    "raw_bytes": "5b",
                    "registers": {"rcx": 0x104, "rbx": 0x42},
                    "memory_accesses": [],
                    "is_tainted": False,
                },
                {
                    "address": 0x5001,
                    "size": 3,
                    "disassembly": "add rcx, 4",
                    "raw_bytes": "4883c104",
                    "registers": {"rcx": 0x108},
                    "memory_accesses": [],
                    "is_tainted": True,
                },
            ],
        },
    }


# ---------------------------------------------------------------------------
# End-to-end: trace→vIP→boundaries→semantics→pseudocode
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    """Test the full devirtualisation pipeline with synthetic data."""

    def test_trace_to_pseudocode_linear(self):
        """Full pipeline producing linear pseudocode."""
        trace = _make_trace()
        assert len(trace.instructions) == 12

        # Identify vIP
        vip = identify_vip_register(trace, dispatcher_addresses=[0x4000])
        assert vip is not None

        # Segment
        seg = segment_trace(trace, vip, [0x4000])
        assert len(seg.boundaries) > 0

        # Semantics
        table = analyse_handler_semantics(trace, seg.boundaries)
        assert table.handler_count > 0

        # Pseudocode
        result = emit_linear(table, seg.boundaries)
        assert result.style == "linear"
        assert result.line_count > 0
        assert len(result.text) > 0

    def test_trace_to_pseudocode_c_like(self):
        trace = _make_trace()
        vip = identify_vip_register(trace, dispatcher_addresses=[0x4000])
        assert vip is not None
        seg = segment_trace(trace, vip, [0x4000])
        table = analyse_handler_semantics(trace, seg.boundaries)
        result = emit_c_like(table, seg.boundaries)
        assert result.style == "c_like"
        assert "void" in result.text
        assert "Devirtualised" in result.text

    def test_emit_pseudocode_dispatcher(self):
        """Test the emit_pseudocode dispatcher function."""
        trace = _make_trace()
        vip = identify_vip_register(trace, dispatcher_addresses=[0x4000])
        if vip is None:
            pytest.skip("vIP not identified")
        seg = segment_trace(trace, vip, [0x4000])
        table = analyse_handler_semantics(trace, seg.boundaries)

        for style in ("linear", "c_like"):
            result = emit_pseudocode(table, seg.boundaries, style=style)
            assert result.style == style


# ---------------------------------------------------------------------------
# Trace ingestion from shared_data
# ---------------------------------------------------------------------------

class TestTraceIngestionIntegration:
    def test_from_triton_shared_data(self):
        shared = _make_triton_shared_data()
        trace = from_shared_data(shared)
        assert isinstance(trace, ExecutionTrace)
        assert len(trace.instructions) >= 2
        # Check register data was ingested
        first = trace.instructions[0]
        assert first.registers.get("rcx") == 0x104 or len(first.registers) > 0


# ---------------------------------------------------------------------------
# MBA simplifier integration
# ---------------------------------------------------------------------------

class TestMBAIntegration:
    def test_simplify_and_verify(self):
        """simplify_mba + verify_equivalence round-trip."""
        r = simplify_mba("(x & y) + (x | y)", bit_width=64)
        assert r.proven is True
        # Verify the result independently
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        original = (x & y) + (x | y)
        assert verify_equivalence(original, x + y)

    def test_batch_pipeline(self):
        exprs = ["(x ^ y) + 2 * (x & y)", "x + y"]
        results, stats = simplify_batch(exprs, bit_width=64)
        assert stats.total == 2
        assert stats.simplified >= 1


# ---------------------------------------------------------------------------
# Symbolic execution integration
# ---------------------------------------------------------------------------

class TestSymbolicExecutionIntegration:
    def test_handler_execution(self):
        """execute_handler produces meaningful symbolic summaries."""
        exe = SymbolicExecutor(arch="x86_64")
        # push rbx; pop rax; ret  (moves rbx → rax via stack)
        summary = exe.execute_handler(b"\x53\x58\xc3", handler_address=0x1000)
        assert isinstance(summary, HandlerSymbolicSummary)
        assert summary.instruction_count >= 2
        assert summary.error is None
        # Should have final register values
        assert len(summary.final_registers) > 0

    def test_solver_opaque_predicate(self):
        """Z3Solver.is_opaque_predicate detects trivial conditions."""
        solver = Z3Solver()
        x = solver.bitvec("x", 64)

        # x == x is always true
        result = solver.is_opaque_predicate(x == x)
        assert result is True

        # x == x + 1 is always false
        result = solver.is_opaque_predicate(x == (x + 1))
        assert result is False

        # x > 0 is neither always true nor always false
        result = solver.is_opaque_predicate(x > 0)
        assert result is None


# ---------------------------------------------------------------------------
# ML classifier integration
# ---------------------------------------------------------------------------

class TestMLClassifierIntegration:
    def test_classify_arithmetic_handler(self):
        """Handler with mostly ADD/SUB mnemonics → arithmetic."""
        handler = {
            "mnemonics": ["add", "add", "sub", "mov", "add"],
            "reads": ["rax", "rbx"],
            "writes": ["rax"],
        }
        clf = VMClassifier()
        result = clf.classify(handler)
        assert isinstance(result, PredictionResult)
        assert result.label in ("arithmetic", "load_store", "unknown")
        assert result.confidence > 0

    def test_classify_stack_handler(self):
        handler = {
            "mnemonics": ["push", "push", "pop"],
            "reads": [],
            "writes": [],
        }
        clf = VMClassifier()
        result = clf.classify(handler)
        assert isinstance(result, PredictionResult)

    def test_extract_features(self):
        handler = {
            "mnemonics": ["add", "sub", "xor"],
            "instructions": [],
        }
        fv = extract_handler_features(handler)
        assert fv.dimension == 15
        assert len(fv.feature_names) == 15

    def test_label_from_heuristics(self):
        assert label_from_heuristics({"operation": "vm_add"}) == "arithmetic"
        assert label_from_heuristics({"operation": "vm_push"}) == "stack"
        assert label_from_heuristics({"operation": "vm_jmp"}) == "branch"
        assert label_from_heuristics({"operation": "vm_load"}) == "load_store"
        assert label_from_heuristics({}) == "unknown"
        assert label_from_heuristics({"operation": ""}) == "unknown"

    def test_prepare_training_data(self):
        handlers = [
            {"operation": "vm_add", "mnemonics": ["add", "add"]},
            {"operation": "vm_push", "mnemonics": ["push"]},
            {"operation": "vm_jmp", "mnemonics": ["jmp"]},
        ]
        features, labels = prepare_training_data(handlers)
        assert len(features) == 3
        assert labels == ["arithmetic", "stack", "branch"]

    def test_trainer_heuristic_validation(self):
        """ModelTrainer validates heuristic accuracy without sklearn."""
        handlers = [
            {"operation": "vm_add", "mnemonics": ["add", "sub", "add", "add", "mov"]},
            {"operation": "vm_push", "mnemonics": ["push", "push", "pop"]},
        ]
        features, labels = prepare_training_data(handlers)
        trainer = ModelTrainer()
        result = trainer.train(features, labels)
        assert isinstance(result, TrainingResult)
        assert result.metrics.get("n_samples") == 2


# ---------------------------------------------------------------------------
# Cross-module validation
# ---------------------------------------------------------------------------

class TestCrossModuleValidation:
    """Validate that modules agree on shared data structures."""

    def test_trace_instruction_has_all_fields(self):
        """TraceInstruction used by ingestion, semantics, and boundaries."""
        insn = TraceInstruction(
            address=0x1000, size=3,
            disassembly="mov rax, rbx",
            raw_bytes=b"\x48\x89\xd8",
            registers={"rax": 0, "rbx": 42},
        )
        assert insn.address == 0x1000
        assert "mov" in insn.disassembly
        assert insn.registers["rbx"] == 42
        assert insn.raw_bytes == b"\x48\x89\xd8"

    def test_handler_boundary_roundtrip(self):
        """HandlerBoundary created by segment_trace, consumed by semantics."""
        b = HandlerBoundary(
            vip_value=0x200,
            handler_address=0x6000,
            trace_start=3,
            trace_end=6,
            instruction_count=3,
            vip_delta=4,
        )
        assert b.vip_delta == 4
        assert b.instruction_count == 3


class TestHasIndirectBranchFeature:
    """Verify has_indirect_branch uses operand info, not positional heuristic."""

    def test_indirect_jmp_register(self):
        handler = {
            "instructions": [
                {"mnemonic": "jmp", "operands": "rax"},
            ],
            "mnemonics": ["jmp"],
        }
        fv = extract_handler_features(handler)
        idx = fv.feature_names.index("has_indirect_branch")
        assert fv.values[idx] == 1.0

    def test_direct_jmp_immediate(self):
        handler = {
            "instructions": [
                {"mnemonic": "jmp", "operands": "0x401000"},
            ],
            "mnemonics": ["jmp"],
        }
        fv = extract_handler_features(handler)
        idx = fv.feature_names.index("has_indirect_branch")
        assert fv.values[idx] == 0.0

    def test_indirect_call_memory(self):
        handler = {
            "instructions": [
                {"mnemonic": "call", "operands": "[rax+8]"},
            ],
            "mnemonics": ["call"],
        }
        fv = extract_handler_features(handler)
        idx = fv.feature_names.index("has_indirect_branch")
        assert fv.values[idx] == 1.0

    def test_no_branch_instructions(self):
        handler = {
            "instructions": [
                {"mnemonic": "add", "operands": "rax, rbx"},
            ],
            "mnemonics": ["add"],
        }
        fv = extract_handler_features(handler)
        idx = fv.feature_names.index("has_indirect_branch")
        assert fv.values[idx] == 0.0
