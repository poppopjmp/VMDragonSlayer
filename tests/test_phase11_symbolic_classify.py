"""Tests for symbolic handler classification (Phase 11).

Verifies that `_classify_from_symbolic` correctly identifies VM
operations from z3 expression trees, and that `analyse_handler_semantics`
properly integrates symbolic summaries with heuristic fallback.
"""

from __future__ import annotations

import pytest

from dragonslayer.analysis.handler_semantics import (
    HandlerSemantic,
    VMOperation,
    _classify_from_symbolic,
    analyse_handler_semantics,
)


# ---------------------------------------------------------------------------
# _classify_from_symbolic unit tests
# ---------------------------------------------------------------------------

class TestClassifyFromSymbolic:
    """Pattern-matching on symbolic expression strings."""

    def _make_summary(self, **overrides):
        base = {
            "address": 0x401000,
            "instruction_count": 5,
            "final_registers": {},
            "simplified_registers": {},
            "memory_writes": [],
            "constraints": [],
            "input_symbols": {},
            "error": None,
        }
        base.update(overrides)
        return base

    def test_add_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax + init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.ADD
        assert result.confidence >= 0.9

    def test_sub_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax - init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.SUB

    def test_xor_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax ^ init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.XOR

    def test_and_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax & init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.AND

    def test_or_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax | init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.OR

    def test_not_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "~init_rax"},
            input_symbols={"rax": "init_rax"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.NOT

    def test_neg_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "-init_rax"},
            input_symbols={"rax": "init_rax"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.NEG

    def test_shl_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax << init_rcx"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.SHL

    def test_shr_lshr_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "LShR(init_rax, init_rcx)"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.SHR

    def test_mul_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "init_rax * init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.MUL

    def test_div_pattern(self):
        s = self._make_summary(
            final_registers={"rax": "UDiv(init_rax, init_rcx)"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.DIV

    def test_store_pattern(self):
        """Handler that writes to non-stack memory → STORE."""
        s = self._make_summary(
            final_registers={"rax": "init_rax"},
            input_symbols={"rax": "init_rax"},
            memory_writes=[{"address": "init_rbx", "value": "init_rax", "size": 8}],
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.STORE

    def test_push_pattern(self):
        """Handler that writes to stack → PUSH."""
        s = self._make_summary(
            final_registers={"rax": "init_rax"},
            input_symbols={"rax": "init_rax"},
            memory_writes=[{"address": "init_rsp - 8", "value": "init_rax", "size": 8}],
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.PUSH

    def test_load_mem_pattern(self):
        """Handler whose output comes from mem_* symbol → LOAD."""
        s = self._make_summary(
            final_registers={"rax": "mem_42"},
            input_symbols={"rax": "init_rax"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.LOAD

    def test_identity_output_ignored(self):
        """Registers that stay unchanged (identity) should be skipped."""
        s = self._make_summary(
            final_registers={"rax": "init_rax", "rbx": "init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is None  # no interesting changes → fallback

    def test_error_returns_none(self):
        s = self._make_summary(error="no code bytes")
        result = _classify_from_symbolic(0x401000, s)
        assert result is None

    def test_none_summary(self):
        result = _classify_from_symbolic(0x401000, None)
        assert result is None

    def test_simplified_preferred_over_final(self):
        """simplified_registers should take priority."""
        s = self._make_summary(
            simplified_registers={"rax": "init_rax + init_rbx"},
            final_registers={"rax": "some_complex_expr"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.ADD

    def test_rotate_left(self):
        s = self._make_summary(
            final_registers={"rax": "RotateLeft(init_rax, init_rcx)"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.ROL

    def test_rotate_right(self):
        s = self._make_summary(
            final_registers={"rax": "RotateRight(init_rax, init_rcx)"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        result = _classify_from_symbolic(0x401000, s)
        assert result is not None
        assert result.operation == VMOperation.ROR


# ---------------------------------------------------------------------------
# Integration: analyse_handler_semantics with symbolic_summaries
# ---------------------------------------------------------------------------

class TestAnalyseWithSymbolicSummaries:
    """Verify symbolic summaries are wired into the public API."""

    def test_symbolic_overrides_histogram(self):
        """When symbolic summary matches, it should take priority."""
        from dragonslayer.analysis.trace_ingestion import ExecutionTrace, TraceInstruction
        from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary

        # Minimal trace with misleading mnemonic histogram
        # (handler consists of `mov` instructions, but symbolically it's ADD)
        instrs = [
            TraceInstruction(address=0x1000, disassembly="mov rax, rsi",
                             registers={}, raw_bytes="", size=3),
            TraceInstruction(address=0x1002, disassembly="mov rbx, rdi",
                             registers={}, raw_bytes="", size=3),
        ]
        trace = ExecutionTrace(instructions=instrs)
        boundary = HandlerBoundary(
            vip_value=0x5000,
            handler_address=0x1000,
            trace_start=0,
            trace_end=2,
            instruction_count=2,
            vip_delta=4,
        )

        sym = {
            0x1000: {
                "address": 0x1000,
                "instruction_count": 2,
                "final_registers": {"rax": "init_rax + init_rbx"},
                "simplified_registers": {"rax": "init_rax + init_rbx"},
                "memory_writes": [],
                "constraints": [],
                "input_symbols": {"rax": "init_rax", "rbx": "init_rbx"},
                "error": None,
            }
        }

        table = analyse_handler_semantics(
            trace, [boundary], symbolic_summaries=sym,
        )
        assert len(table.entries) == 1
        assert table.entries[0].semantic.operation == VMOperation.ADD
        assert table.entries[0].semantic.confidence >= 0.9

    def test_fallback_to_histogram_when_no_match(self):
        """If symbolic summary can't match, histogram is used."""
        from dragonslayer.analysis.trace_ingestion import ExecutionTrace, TraceInstruction
        from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary

        instrs = [
            TraceInstruction(address=0x2000, disassembly="add rax, rbx",
                             registers={}, raw_bytes="", size=3),
        ]
        trace = ExecutionTrace(instructions=instrs)
        boundary = HandlerBoundary(
            vip_value=0x6000,
            handler_address=0x2000,
            trace_start=0,
            trace_end=1,
            instruction_count=1,
            vip_delta=2,
        )

        # Symbolic summary with only identity outputs → no match
        sym = {
            0x2000: {
                "address": 0x2000,
                "instruction_count": 1,
                "final_registers": {"rax": "init_rax", "rbx": "init_rbx"},
                "simplified_registers": {},
                "memory_writes": [],
                "constraints": [],
                "input_symbols": {"rax": "init_rax", "rbx": "init_rbx"},
                "error": None,
            }
        }

        table = analyse_handler_semantics(
            trace, [boundary], symbolic_summaries=sym,
        )
        assert len(table.entries) == 1
        # Should fall back to histogram → ADD from the `add` mnemonic
        assert table.entries[0].semantic.operation == VMOperation.ADD
