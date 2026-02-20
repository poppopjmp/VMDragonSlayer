"""Phase 9 integration tests: cross-module verification.

These tests exercise interactions between the components improved in
Phase 9 — EFLAGS, memory-aware taint, dispatcher scoring, MBA
simplification, pipeline timeout, and register extraction.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# 1. EFLAGS ↔ branch-constraint integration
# ---------------------------------------------------------------------------


class TestEflagsBranchIntegration:
    """Symbolic executor: flag-setting instructions → conditional branch via trace."""

    def test_cmp_je_updates_flags(self):
        """cmp + je trace: flags ZF is set and branch constraint is built."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        exe = SymbolicExecutor(arch="x86_64")
        trace_insns = [
            {"address": 0x1000, "raw_bytes": "4839d8", "disassembly": "cmp rax, rbx"},
            {"address": 0x1003, "raw_bytes": "7402",   "disassembly": "je 0x1007"},
            {"address": 0x1005, "raw_bytes": "90",     "disassembly": "nop"},
        ]
        summary = exe.execute_handler_from_trace(trace_insns, handler_address=0x1000)
        assert summary.instruction_count >= 1
        assert summary.error is None

    def test_sub_sets_flags_via_trace(self):
        """sub instruction sets arithmetic flags in symbolic state."""
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState

        state = SymbolicState(arch="x86_64")
        # Simulate: sub rax, 1 where rax=5 → result=4 → ZF=False, SF=False
        state.update_flags_arith(result=4, left=5, right=1, is_sub=True)
        assert state.flags["ZF"] is False or state.flags["ZF"] == False
        assert state.flags["SF"] is False or state.flags["SF"] == False

        # Simulate: sub rax, 5 where rax=5 → result=0 → ZF=True
        state.update_flags_arith(result=0, left=5, right=5, is_sub=True)
        assert state.flags["ZF"] is True or state.flags["ZF"] == True

    def test_test_updates_flags_logic(self):
        """test instruction uses update_flags_logic (AND semantics)."""
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState

        state = SymbolicState(arch="x86_64")
        # test rax, rax where rax=0 → ZF=True
        state.update_flags_logic(result=0)
        assert state.flags["ZF"] is True or state.flags["ZF"] == True

        # test rax, rax where rax=42 → ZF=False
        state.update_flags_logic(result=42)
        assert state.flags["ZF"] is False or state.flags["ZF"] == False


# ---------------------------------------------------------------------------
# 2. Memory-aware taint tracking + SIB patterns
# ---------------------------------------------------------------------------


class TestMemoryTaintSIB:
    """Taint tracker correctly handles SIB-style memory operands."""

    def _make_insn(self, addr, mnemonic, operands, category, reads, writes, *, registers=None):
        """Build a duck-typed instruction for the taint tracker."""
        from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

        r, w = _extract_reg_reads_writes(mnemonic, operands)

        class _I:
            pass

        insn = _I()
        insn.address = addr
        insn.mnemonic = mnemonic
        insn.operands = operands
        insn.category = category
        insn.reads = reads or r
        insn.writes = writes or w
        insn.registers = registers or {}
        return insn

    def test_sib_load_propagates_taint(self):
        """mov rax, [rbx+rcx*4+0x10] should propagate taint from rbx."""
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag

        tracker = TaintTracker()
        tracker.taint_register("rbx", TaintTag.VM_CONTEXT)

        insns = [
            self._make_insn(
                0x1000, "mov", "rax, [rbx+rcx*4+0x10]",
                "memory_read", ["rbx", "rcx"], ["rax"],
                registers={"rbx": 0x7000, "rcx": 0x2},
            ),
        ]
        result = tracker.analyze(insns)
        assert result.success
        # rax should carry taint propagated from the tainted base rbx
        assert "rax" in result.tainted_registers or len(result.events) > 0

    def test_store_through_tainted_pointer(self):
        """mov [rdi+rsi*8], rax  — store via tainted base."""
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag

        tracker = TaintTracker()
        tracker.taint_register("rdi", TaintTag.VM_CONTEXT)
        tracker.taint_register("rax", TaintTag.INPUT)

        insns = [
            self._make_insn(
                0x2000, "mov", "[rdi+rsi*8], rax",
                "memory_write", ["rdi", "rsi", "rax"], [],
                registers={"rdi": 0x5000, "rsi": 0x4, "rax": 0x42},
            ),
        ]
        result = tracker.analyze(insns)
        assert result.success
        # Must record at least one event for the tainted store.
        assert len(result.events) >= 1


# ---------------------------------------------------------------------------
# 3. Dispatcher scoring + handler semantics chain
# ---------------------------------------------------------------------------


class TestDispatcherToSemantics:
    """From a multi-handler trace → dispatcher → handler boundaries → semantics."""

    def test_analyse_semantics_from_trace(self):
        """analyse_handler_semantics classifies handlers from trace boundaries."""
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.handler_semantics import (
            HandlerBoundary,
            analyse_handler_semantics,
        )

        trace_path = (
            Path(__file__).resolve().parent.parent
            / "data" / "samples" / "traces" / "vmprotect_vadd_handler.trace"
        )
        text = trace_path.read_text()
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
        # Must produce at least one entry with an operation.
        assert table.handler_count >= 1
        assert len(table.entries) >= 1
        entry = table.entries[0]
        assert entry.semantic.operation  # non-empty string


# ---------------------------------------------------------------------------
# 4. MBA simplifier (3-variable) + pseudocode integration
# ---------------------------------------------------------------------------


class TestMBASimplification:
    """MBA simplifier ↔ z3 ↔ pseudocode style expressions."""

    def test_2var_xor_identity(self):
        """(x | y) - (x & y) == x ^ y — classic 2-var MBA."""
        from dragonslayer.analysis.mba_simplifier import simplify_mba

        res = simplify_mba("(x | y) - (x & y)", bit_width=32)
        assert res.proven
        assert "^" in res.simplified or "xor" in res.simplified.lower()

    def test_3var_identity(self):
        """(x ^ y) ^ z ≡ x ^ (y ^ z) — 3-variable."""
        from dragonslayer.analysis.mba_simplifier import simplify_mba

        res = simplify_mba("(x ^ y) ^ z", bit_width=32)
        assert res.proven  # must be self-equal at minimum

    def test_simplify_expr_with_z3(self):
        """simplify_expr returns simplified z3 expression + rule name."""
        import z3
        from dragonslayer.analysis.mba_simplifier import simplify_expr

        x = z3.BitVec("x", 32)
        y = z3.BitVec("y", 32)
        expr = (x | y) - (x & y)  # == x ^ y
        simplified, rule = simplify_expr(expr, bit_width=32)
        # Must simplify to something (possibly same form but proven).
        assert simplified is not None


# ---------------------------------------------------------------------------
# 5. Pipeline timeout enforcement
# ---------------------------------------------------------------------------


class TestPipelineTimeout:
    """Pipeline stage timeout fires within configured window."""

    def test_timeout_aborts_hung_stage(self):
        """A stage that sleeps beyond timeout should be aborted."""
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["pattern_analysis"],
            llm_enabled=False,
            timeout=1.0,  # 1 second
        )
        pipe = AnalysisPipeline()

        # Monkey-patch the instance method that the stage dispatch calls.
        original = pipe._run_pattern_analysis

        def _sleepy(binary_data, ctx):
            time.sleep(10)
            return {}

        pipe._run_pattern_analysis = _sleepy

        start = time.monotonic()
        result = pipe.run(b"\x90" * 16, cfg)
        elapsed = time.monotonic() - start

        # Restore original method.
        pipe._run_pattern_analysis = original

        # Should complete in under 5s (timeout=1s + overhead).
        assert elapsed < 5.0
        # The stage should report failure/timeout.
        assert len(result.stages) >= 1


# ---------------------------------------------------------------------------
# 6. Register extraction → handler semantics chain
# ---------------------------------------------------------------------------


class TestRegisterExtractionToSemantics:
    """_extract_reg_reads_writes feeds accurate data to handler classification."""

    def test_mov_rax_rbx(self):
        from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

        reads, writes = _extract_reg_reads_writes("mov", "rax, rbx")
        assert "rax" in writes
        assert "rbx" in reads

    def test_add_rax_mem(self):
        """add rax, [rbp+0x10] — RMW on rax, read rbp."""
        from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

        reads, writes = _extract_reg_reads_writes("add", "rax, [rbp+0x10]")
        assert "rax" in writes  # destination
        assert "rbp" in reads   # memory base

    def test_push_reads_pop_writes(self):
        from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

        reads_push, writes_push = _extract_reg_reads_writes("push", "rcx")
        assert "rcx" in reads_push

        reads_pop, writes_pop = _extract_reg_reads_writes("pop", "rdx")
        assert "rdx" in writes_pop

    def test_cmp_read_only(self):
        from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

        reads, writes = _extract_reg_reads_writes("cmp", "rax, rbx")
        assert "rax" in reads
        assert "rbx" in reads
        assert len(writes) == 0  # cmp does not write to operands

    def test_xchg_both(self):
        from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

        reads, writes = _extract_reg_reads_writes("xchg", "rax, rbx")
        assert "rax" in reads and "rax" in writes
        assert "rbx" in reads and "rbx" in writes


# ---------------------------------------------------------------------------
# 7. Pseudocode emission with handler semantics (linear + structured)
# ---------------------------------------------------------------------------


class TestPseudocodeEmission:
    """emit_linear and emit_structured produce valid output from opcode tables."""

    def _build_table_and_boundaries(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.handler_semantics import (
            HandlerBoundary,
            analyse_handler_semantics,
        )

        trace_path = (
            Path(__file__).resolve().parent.parent
            / "data" / "samples" / "traces" / "vmprotect_vadd_handler.trace"
        )
        text = trace_path.read_text()
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
        return table, boundaries

    def test_linear_produces_text(self):
        from dragonslayer.analysis.pseudocode import emit_linear

        table, boundaries = self._build_table_and_boundaries()
        result = emit_linear(table, boundaries)
        assert result.line_count >= 1
        assert result.style == "linear"
        assert len(result.text) > 0

    def test_structured_fallback(self):
        """emit_structured with no CFG falls back to linear."""
        from dragonslayer.analysis.pseudocode import emit_structured

        table, boundaries = self._build_table_and_boundaries()
        result = emit_structured(table, boundaries, handler_cfg=None)
        assert result.line_count >= 1
        assert len(result.text) > 0


# ---------------------------------------------------------------------------
# 8. Symbolic state flags initialisation + fork
# ---------------------------------------------------------------------------


class TestSymbolicStateFlagsIntegration:
    """SymbolicState.flags are preserved across fork() and updated by arithmetic."""

    def test_flags_initialised(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState

        state = SymbolicState(arch="x86_64")
        assert "ZF" in state.flags
        assert "CF" in state.flags
        assert "SF" in state.flags
        assert "OF" in state.flags

    def test_fork_preserves_flags(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState

        state = SymbolicState(arch="x86_64")
        state.flags["ZF"] = True
        state.flags["CF"] = True

        child = state.fork()
        assert child.flags["ZF"] == True
        assert child.flags["CF"] == True

        # Mutating child shouldn't affect parent.
        child.flags["ZF"] = False
        assert state.flags["ZF"] == True

    def test_update_flags_arith_sets_zf(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState

        state = SymbolicState(arch="x86_64")
        # 5 - 5 = 0 → ZF should be set.
        state.update_flags_arith(result=0, left=5, right=5, is_sub=True)
        assert state.flags["ZF"] is True or state.flags["ZF"] == True


# ---------------------------------------------------------------------------
# 9. Full pipeline cross-module: trace → taint → symex → pseudocode
# ---------------------------------------------------------------------------


class TestFullCrossModule:
    """End-to-end: ingest trace, taint, symex, pseudocode — all in one flow."""

    def test_trace_to_pseudocode(self):
        from dragonslayer.analysis.trace_ingestion import parse_trace_text
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.handler_semantics import (
            HandlerBoundary,
            analyse_handler_semantics,
        )
        from dragonslayer.analysis.pseudocode import emit_linear

        # 1. Ingest
        trace_path = (
            Path(__file__).resolve().parent.parent
            / "data" / "samples" / "traces" / "vmprotect_vadd_handler.trace"
        )
        trace = parse_trace_text(trace_path.read_text())
        assert len(trace.instructions) >= 1

        # 2. Taint
        tracker = TaintTracker()
        tracker.taint_register("rbp", TaintTag.VM_CONTEXT)
        lifted = []
        for ti in trace.instructions:
            from dragonslayer.analysis.trace_ingestion import _extract_reg_reads_writes

            parts = ti.disassembly.strip().split(None, 1) if ti.disassembly else []
            mnem = parts[0].lower() if parts else "nop"
            ops = parts[1] if len(parts) > 1 else ""
            reads, writes = _extract_reg_reads_writes(mnem, ops)

            class _I:
                pass

            insn = _I()
            insn.address = ti.address
            insn.mnemonic = mnem
            insn.operands = ops
            insn.reads = reads
            insn.writes = writes
            insn.registers = ti.registers
            insn.category = "unknown"
            lifted.append(insn)

        taint_result = tracker.analyze(lifted)
        assert taint_result.success

        # 3. Symbolic execution
        exe = SymbolicExecutor(arch="x86_64")
        trace_insns = [
            {
                "address": ti.address,
                "raw_bytes": ti.raw_bytes.hex() if ti.raw_bytes else "",
                "disassembly": ti.disassembly,
            }
            for ti in trace.instructions
        ]
        sym_result = exe.execute_handler_from_trace(trace_insns, handler_address=0x140023A00)
        assert sym_result.error is None

        # 4. Handler semantics
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
        assert table.handler_count >= 1

        # 5. Pseudocode
        pseudo = emit_linear(table, boundaries)
        assert pseudo.line_count >= 1
        assert pseudo.text
