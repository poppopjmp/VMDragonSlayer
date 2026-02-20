"""Tests for symbolic vIP identification in handler_boundaries.

Validates:
- ``score_vip_from_symbolic()`` standalone scoring
- ``identify_vip_register()`` integration with symbolic summaries
- VIPCandidate.symbolic_score field
"""

from __future__ import annotations

import pytest

from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    VIPCandidate,
    identify_vip_register,
    score_vip_from_symbolic,
)
from dragonslayer.analysis.symbolic_execution.executor import HandlerSymbolicSummary
from dragonslayer.analysis.trace_ingestion import ExecutionTrace, TraceInstruction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_summary(
    final_registers: dict[str, str],
    address: int = 0x401000,
) -> HandlerSymbolicSummary:
    """Build a minimal HandlerSymbolicSummary for testing."""
    return HandlerSymbolicSummary(
        address=address,
        instruction_count=5,
        final_registers=final_registers,
        simplified_registers={},
        memory_writes=[],
        constraints=[],
        input_symbols={},
    )


def _make_trace_with_registers(
    register_values: list[dict[str, int]],
    base_addr: int = 0x401000,
) -> ExecutionTrace:
    """Build a trace where each step has the given register snapshot."""
    instructions = []
    for i, regs in enumerate(register_values):
        instructions.append(TraceInstruction(
            address=base_addr + i * 4,
            size=4,
            raw_bytes=b"\x90\x90\x90\x90",
            disassembly="nop",
            registers=regs,
        ))
    return ExecutionTrace(instructions=instructions)


# ---------------------------------------------------------------------------
# Tests: score_vip_from_symbolic
# ---------------------------------------------------------------------------

class TestScoreVipFromSymbolic:
    """Test the standalone symbolic vIP scoring function."""

    def test_empty_summaries(self):
        scores = score_vip_from_symbolic([])
        assert scores == {}

    def test_single_handler_self_advance(self):
        """RSI updates itself (in_rsi + 4) → strong self-advance signal."""
        summary = _make_summary({
            "rsi": "in_rsi + 4",
            "rax": "Mem(in_rsi)",
            "rbx": "in_rbx",
        })
        scores = score_vip_from_symbolic([summary])
        assert "rsi" in scores
        # Self-advance: rsi expression contains in_rsi and only 1 mention
        assert scores["rsi"] > 0.3
        # rax doesn't self-advance (expression doesn't contain in_rax)
        # but rsi is referenced by rax → cross-ref bonus
        assert scores.get("rax", 0.0) == 0.0 or scores.get("rax", 0.0) < scores["rsi"]

    def test_no_self_advance(self):
        """Register that never self-advances scores 0 for self-advance."""
        summary = _make_summary({
            "rax": "in_rbx + in_rcx",
            "rbx": "in_rcx",
        })
        scores = score_vip_from_symbolic([summary])
        # Neither rax nor rbx self-advance
        assert scores.get("rax", 0.0) == 0.0

    def test_multiple_handlers_consistent_advance(self):
        """RSI self-advances in all handlers → maximum self-advance score."""
        summaries = [
            _make_summary({"rsi": "in_rsi + 2", "rax": "Mem(in_rsi)"}),
            _make_summary({"rsi": "in_rsi + 4", "rax": "Mem(in_rsi)"}),
            _make_summary({"rsi": "in_rsi + 1", "rbx": "Mem(in_rsi)"}),
        ]
        scores = score_vip_from_symbolic(summaries)
        # RSI self-advances in all 3 → ratio = 1.0
        assert scores["rsi"] >= 0.5

    def test_cross_reference_bonus(self):
        """Register referenced by other regs gets cross-ref bonus."""
        summary = _make_summary({
            "rsi": "in_rsi + 4",
            "rax": "Load(in_rsi)",
            "rbx": "Load(in_rsi + 2)",
        })
        scores = score_vip_from_symbolic([summary])
        # rsi is referenced by rax and rbx → high cross-ref
        assert scores["rsi"] > 0.5

    def test_candidate_filter(self):
        """Only score requested candidates."""
        summary = _make_summary({
            "rsi": "in_rsi + 4",
            "rdi": "in_rdi + 2",
        })
        scores = score_vip_from_symbolic([summary], candidates=["rsi"])
        assert "rsi" in scores
        assert "rdi" not in scores

    def test_error_summaries_ignored(self):
        """Summaries with errors are skipped."""
        summary = HandlerSymbolicSummary(
            address=0x401000,
            error="execution failed",
        )
        scores = score_vip_from_symbolic([summary])
        assert scores == {}

    def test_complex_expression_self_advance(self):
        """Self-advance with more complex expression still detected."""
        summary = _make_summary({
            "rsi": "(in_rsi + (Mem(in_rsi) & 0xff))",
            "rax": "in_rbx ^ in_rcx",
        })
        scores = score_vip_from_symbolic([summary])
        # in_rsi appears in rsi output → self-advance
        assert scores.get("rsi", 0.0) > 0.0

    def test_multiple_inputs_reduces_score(self):
        """Register with >2 input symbols in expression is not self-advance."""
        summary = _make_summary({
            "rsi": "in_rsi + in_rax + in_rbx + in_rcx",
        })
        scores = score_vip_from_symbolic([summary])
        # >2 mentions → not counted as self-advance
        assert scores.get("rsi", 0.0) < 0.3


# ---------------------------------------------------------------------------
# Tests: identify_vip_register with symbolic summaries
# ---------------------------------------------------------------------------

class TestIdentifyVipWithSymbolic:
    """Test that symbolic summaries enhance vIP identification."""

    def test_symbolic_boosts_correct_register(self):
        """RSI monotonically increases AND self-advances symbolically."""
        register_values = [
            {"rsi": 0x1000, "rdi": 0x2000},
            {"rsi": 0x1004, "rdi": 0x2001},
            {"rsi": 0x1008, "rdi": 0x1999},
            {"rsi": 0x100C, "rdi": 0x2004},
            {"rsi": 0x1010, "rdi": 0x2003},
        ]
        trace = _make_trace_with_registers(register_values)
        summaries = [
            _make_summary({"rsi": "in_rsi + 4", "rax": "Mem(in_rsi)"}),
            _make_summary({"rsi": "in_rsi + 4", "rbx": "Mem(in_rsi)"}),
        ]
        vip = identify_vip_register(
            trace, symbolic_summaries=summaries,
        )
        assert vip is not None
        assert vip.name == "rsi"
        assert vip.symbolic_score > 0.0

    def test_symbolic_score_field_present(self):
        """VIPCandidate includes symbolic_score even without summaries."""
        register_values = [
            {"rsi": 0x1000},
            {"rsi": 0x1004},
            {"rsi": 0x1008},
        ]
        trace = _make_trace_with_registers(register_values)
        vip = identify_vip_register(trace)
        assert vip is not None
        assert hasattr(vip, "symbolic_score")
        assert vip.symbolic_score == 0.0

    def test_no_symbolic_summaries_backward_compat(self):
        """Without summaries, scoring works exactly as before."""
        register_values = [
            {"rsi": 0x1000, "rdi": 0x2000},
            {"rsi": 0x1004, "rdi": 0x2008},
            {"rsi": 0x1008, "rdi": 0x2010},
            {"rsi": 0x100C, "rdi": 0x2018},
        ]
        trace = _make_trace_with_registers(register_values)
        vip = identify_vip_register(trace)
        assert vip is not None
        # Both monotonic; the winner depends on prior weight
        assert vip.name in {"rsi", "rdi"}

    def test_symbolic_disambiguates_tie(self):
        """Two registers with equal trace scores: symbolic breaks tie."""
        # Both registers increase by 4 each step → equal trace scores.
        register_values = [
            {"rsi": 0x1000, "rbx": 0x2000},
            {"rsi": 0x1004, "rbx": 0x2004},
            {"rsi": 0x1008, "rbx": 0x2008},
            {"rsi": 0x100C, "rbx": 0x200C},
        ]
        trace = _make_trace_with_registers(register_values)
        # Only RSI self-advances symbolically
        summaries = [
            _make_summary({"rsi": "in_rsi + 4", "rbx": "Mem(in_rsi)"}),
            _make_summary({"rsi": "in_rsi + 4", "rbx": "42"}),
        ]
        vip = identify_vip_register(
            trace, symbolic_summaries=summaries,
        )
        assert vip is not None
        assert vip.name == "rsi"
        assert vip.symbolic_score > 0.0
