"""
Tests for B55 — Inter-procedural Taint Summaries & Backward Taint.

Covers:
  1. Tag-aware HandlerTaintSummary fields
  2. Transfer function in build_handler_summary
  3. Backward tag-aware propagation
  4. compose_summaries chaining
  5. Integration with existing forward propagation
"""

from __future__ import annotations

import pytest

from dragonslayer.analysis.taint_tracking.inter_handler import (
    HandlerTaintSummary,
    InterHandlerDataFlow,
    InterHandlerFlowResult,
    build_handler_summary,
    compose_summaries,
    canonicalize_reg,
)
from dragonslayer.analysis.taint_tracking.tracker import TaintTag


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Tag-aware summary fields
# ═══════════════════════════════════════════════════════════════════════════════

class TestTagAwareSummary:
    """HandlerTaintSummary has B55 tag_in/tag_out/transfer fields."""

    def test_default_tag_in_empty(self):
        s = HandlerTaintSummary()
        assert s.tag_in == {}

    def test_default_tag_out_empty(self):
        s = HandlerTaintSummary()
        assert s.tag_out == {}

    def test_default_transfer_empty(self):
        s = HandlerTaintSummary()
        assert s.transfer == {}

    def test_tag_in_assignment(self):
        s = HandlerTaintSummary()
        s.tag_in = {"rax": TaintTag.INPUT, "rbx": TaintTag.VM_CONTEXT}
        assert s.tag_in["rax"] == TaintTag.INPUT
        assert s.tag_in["rbx"] == TaintTag.VM_CONTEXT

    def test_tag_out_assignment(self):
        s = HandlerTaintSummary()
        s.tag_out = {"rax": TaintTag.INPUT | TaintTag.COMPUTED}
        assert s.tag_out["rax"] & TaintTag.COMPUTED

    def test_to_dict_includes_tags(self):
        s = HandlerTaintSummary(handler_id=1)
        s.tag_in = {"rax": TaintTag.INPUT}
        s.tag_out = {"rbx": TaintTag.COMPUTED}
        d = s.to_dict()
        assert "tag_in" in d
        assert "tag_out" in d
        assert d["tag_in"]["rax"] == int(TaintTag.INPUT)
        assert d["tag_out"]["rbx"] == int(TaintTag.COMPUTED)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Transfer function from build_handler_summary
# ═══════════════════════════════════════════════════════════════════════════════

class TestTransferFunction:
    """build_handler_summary populates transfer function."""

    def test_transfer_from_symbolic(self):
        sym = {
            "final_registers": {"rax": "init_rbx + 1"},
            "input_symbols": {"init_rbx": "rbx"},
        }
        s = build_handler_summary(1, symbolic_summary=sym)
        assert s.defs == {"rax"}
        assert s.uses == {"rbx"}
        # Transfer: rbx → {rax}
        assert "rbx" in s.transfer
        assert "rax" in s.transfer["rbx"]

    def test_transfer_from_instructions(self):
        insns = [
            {"reads": ["rsi"], "writes": ["rdi"]},
            {"reads": ["rdi"], "writes": ["rax"]},
        ]
        s = build_handler_summary(2, instructions=insns)
        assert "rsi" in s.uses
        assert "rax" in s.defs
        # Conservative: every use maps to every def
        assert "rsi" in s.transfer

    def test_no_transfer_when_no_uses(self):
        sym = {
            "final_registers": {"rax": "0x42"},
            "input_symbols": {},
        }
        s = build_handler_summary(3, symbolic_summary=sym)
        assert s.transfer == {}


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Backward tag-aware propagation
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardPropagate:
    """InterHandlerDataFlow.backward_propagate() tests."""

    def _make_chain(self):
        """Three-handler chain: rsi → rax → rbx."""
        s1 = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rsi"},
            kill={"rax"},
            transfer={"rsi": {"rax"}},
        )
        s2 = HandlerTaintSummary(
            handler_id=2, defs={"rbx"}, uses={"rax"},
            kill={"rbx"},
            transfer={"rax": {"rbx"}},
        )
        s3 = HandlerTaintSummary(
            handler_id=3, defs={"rcx"}, uses={"rbx"},
            kill={"rcx"},
            transfer={"rbx": {"rcx"}},
        )
        return [s1, s2, s3]

    def test_backward_finds_contributing_handlers(self):
        flow = InterHandlerDataFlow()
        chain = self._make_chain()
        result = flow.backward_propagate(chain, target_reg="rcx")
        assert 3 in result["contributing_handlers"]
        assert 2 in result["contributing_handlers"]
        assert 1 in result["contributing_handlers"]

    def test_backward_finds_required_inputs(self):
        flow = InterHandlerDataFlow()
        chain = self._make_chain()
        result = flow.backward_propagate(chain, target_reg="rcx")
        # Final required input should be rsi
        assert "rsi" in result["required_inputs"]

    def test_backward_demand_chain_not_empty(self):
        flow = InterHandlerDataFlow()
        chain = self._make_chain()
        result = flow.backward_propagate(chain, target_reg="rcx")
        assert len(result["demand_chain"]) > 0

    def test_backward_with_specific_tag(self):
        flow = InterHandlerDataFlow()
        chain = self._make_chain()
        result = flow.backward_propagate(
            chain, target_reg="rcx", target_tag=TaintTag.VM_CONTEXT,
        )
        # Should still find required inputs with the specified tag
        for reg, tag in result["required_inputs"].items():
            assert tag & TaintTag.VM_CONTEXT

    def test_backward_no_match(self):
        flow = InterHandlerDataFlow()
        chain = self._make_chain()
        # rdx is not produced by any handler
        result = flow.backward_propagate(chain, target_reg="rdx")
        assert result["contributing_handlers"] == []

    def test_backward_single_handler(self):
        flow = InterHandlerDataFlow()
        s = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rbx", "rcx"},
            kill={"rax"},
            transfer={"rbx": {"rax"}, "rcx": {"rax"}},
        )
        result = flow.backward_propagate([s], target_reg="rax")
        assert 1 in result["contributing_handlers"]
        assert "rbx" in result["required_inputs"]
        assert "rcx" in result["required_inputs"]


# ═══════════════════════════════════════════════════════════════════════════════
# 4. compose_summaries
# ═══════════════════════════════════════════════════════════════════════════════

class TestComposeSummaries:
    """compose_summaries chaining tests."""

    def test_empty_summaries(self):
        result = compose_summaries([])
        assert result["input_tags"] == {}
        assert result["output_tags"] == {}

    def test_single_handler_passthrough(self):
        s = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rsi"},
            kill={"rax"},
            transfer={"rsi": {"rax"}},
        )
        result = compose_summaries([s])
        # rsi is an input
        assert "rsi" in result["input_tags"]
        # rax should appear in output (computed from rsi)
        assert "rax" in result["output_tags"]

    def test_two_handler_chain(self):
        s1 = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rsi"},
            kill={"rax"},
            transfer={"rsi": {"rax"}},
        )
        s2 = HandlerTaintSummary(
            handler_id=2, defs={"rbx"}, uses={"rax"},
            kill={"rbx"},
            transfer={"rax": {"rbx"}},
        )
        result = compose_summaries([s1, s2])
        # rsi flows through rax to rbx
        assert "rsi" in result["composed_transfer"]
        out_regs = result["composed_transfer"]["rsi"]
        assert "rbx" in out_regs

    def test_custom_initial_tags(self):
        s = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rsi"},
            kill={"rax"},
            transfer={"rsi": {"rax"}},
        )
        result = compose_summaries(
            [s],
            initial_tags={"rsi": TaintTag.VM_CONTEXT},
        )
        # Output should carry VM_CONTEXT tag
        out_tag = result["output_tags"].get("rax", 0)
        assert out_tag & int(TaintTag.VM_CONTEXT)

    def test_kill_stops_propagation(self):
        s1 = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses=set(),
            kill={"rax", "rbx"},
        )
        result = compose_summaries(
            [s1],
            initial_tags={"rbx": TaintTag.INPUT},
        )
        # rbx is killed; should not appear in output
        assert "rbx" not in result["output_tags"]


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Integration with forward propagation
# ═══════════════════════════════════════════════════════════════════════════════

class TestForwardBackwardIntegration:
    """Forward propagate, then backward propagate, results consistent."""

    def test_forward_then_backward(self):
        s1 = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rsi"},
            kill={"rax"},
            transfer={"rsi": {"rax"}},
        )
        s2 = HandlerTaintSummary(
            handler_id=2, defs={"rbx"}, uses={"rax"},
            kill={"rbx"},
            transfer={"rax": {"rbx"}},
        )

        flow = InterHandlerDataFlow()
        # Forward
        fwd_result = flow.propagate([s1, s2], initial_taint={"rsi"})
        assert fwd_result.converged
        assert "rbx" in s2.taint_out

        # Backward
        bwd_result = flow.backward_propagate([s1, s2], target_reg="rbx")
        assert "rsi" in bwd_result["required_inputs"]
        assert 1 in bwd_result["contributing_handlers"]
        assert 2 in bwd_result["contributing_handlers"]

    def test_compose_matches_forward(self):
        """compose_summaries output tags align with forward propagation."""
        s1 = HandlerTaintSummary(
            handler_id=1, defs={"rax"}, uses={"rsi"},
            kill={"rax"}, transfer={"rsi": {"rax"}},
        )
        s2 = HandlerTaintSummary(
            handler_id=2, defs={"rbx"}, uses={"rax"},
            kill={"rbx"}, transfer={"rax": {"rbx"}},
        )

        flow = InterHandlerDataFlow()
        flow.propagate([s1, s2], initial_taint={"rsi"})

        result = compose_summaries([s1, s2])
        # Forward says rbx is tainted; compose should agree
        assert "rbx" in result["output_tags"]
