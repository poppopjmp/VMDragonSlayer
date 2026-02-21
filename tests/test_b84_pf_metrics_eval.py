"""B84 — PF flag, static CFG LoopTree, AnalysisMetrics, ML evaluation.

Tests cover:
  1. PF (parity flag) in update_flags_arith/logic and _evaluate_condition
  2. build_static_cfg wires LoopTree correctly
  3. AnalysisMetrics timing/phase tracking
  4. evaluate_model.evaluate() on ground-truth samples
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# PF flag tests
# ---------------------------------------------------------------------------
from dragonslayer.analysis.symbolic_execution.state import SymbolicState
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    LiftedInstruction,
)

try:
    import z3 as _z3
    _HAS_Z3 = True
except ImportError:
    _z3 = None  # type: ignore[assignment]
    _HAS_Z3 = False


def _make_state(arch: str = "x86_64") -> SymbolicState:
    return SymbolicState(arch=arch, bit_width=64, initial_pc=0)


def _insn(mnemonic: str, ops: str = "") -> LiftedInstruction:
    operands = [o.strip() for o in ops.split(",")] if ops else []
    return LiftedInstruction(
        address=0, mnemonic=mnemonic, operands=operands,
        category="", raw_bytes=b"", size=0,
    )


class TestParityFlagConcrete:
    """PF parity flag in concrete (non-z3) mode."""

    def test_pf_set_even_parity(self):
        """Result 0x03 = 0b00000011 → 2 bits set → even → PF=True."""
        state = _make_state()
        state.update_flags_arith(3, 2, 1, is_sub=False)
        assert state.flags["PF"] is True

    def test_pf_clear_odd_parity(self):
        """Result 0x01 = 0b00000001 → 1 bit set → odd → PF=False."""
        state = _make_state()
        state.update_flags_arith(1, 1, 0, is_sub=False)
        assert state.flags["PF"] is False

    def test_pf_zero_is_even_parity(self):
        """Result 0 → 0 bits set → even → PF=True."""
        state = _make_state()
        state.update_flags_arith(0, 0, 0, is_sub=False)
        assert state.flags["PF"] is True

    def test_pf_0xff_even_parity(self):
        """Result 0xFF = 8 bits → even → PF=True."""
        state = _make_state()
        state.update_flags_arith(0xFF, 0xFE, 1, is_sub=False)
        assert state.flags["PF"] is True

    def test_pf_logic_and(self):
        """PF after logical AND."""
        state = _make_state()
        state.update_flags_logic(0x03)  # 2 bits → PF=True
        assert state.flags["PF"] is True

    def test_pf_logic_xor(self):
        state = _make_state()
        state.update_flags_logic(0x07)  # 3 bits → PF=False
        assert state.flags["PF"] is False


@pytest.mark.skipif(not _HAS_Z3, reason="z3 not available")
class TestParityFlagZ3:
    """PF flag with z3 symbolic values."""

    def test_pf_concrete_via_z3(self):
        state = _make_state()
        a = _z3.BitVecVal(2, 64)
        b = _z3.BitVecVal(1, 64)
        result = a + b  # = 3 = 0b11 → PF should be True
        state.update_flags_arith(result, a, b, is_sub=False)
        pf = state.flags["PF"]
        assert _z3.is_true(_z3.simplify(pf))

    def test_pf_logic_z3(self):
        state = _make_state()
        result = _z3.BitVecVal(0x07, 64)  # 3 bits → PF=False
        state.update_flags_logic(result)
        pf = state.flags["PF"]
        assert _z3.is_false(_z3.simplify(pf))


class TestEvaluateConditionPF:
    """_evaluate_condition uses PF for 'p'/'np' conditions."""

    def test_jp_set(self):
        ex = SymbolicExecutor(arch="x86_64")
        state = _make_state()
        state.update_flags_arith(0x03, 2, 1, is_sub=False)  # PF=True
        result = ex._evaluate_condition(state, "p")
        assert result is True or result == True  # noqa: E712

    def test_jnp_clear(self):
        ex = SymbolicExecutor(arch="x86_64")
        state = _make_state()
        state.update_flags_arith(0x01, 1, 0, is_sub=False)  # PF=False
        result = ex._evaluate_condition(state, "np")
        assert result is True or result == True  # noqa: E712


# ---------------------------------------------------------------------------
# Static CFG LoopTree wiring
# ---------------------------------------------------------------------------
from dragonslayer.analysis.bytecode_cfg import (
    build_static_cfg,
    HandlerCFG,
    LoopTree,
)


class TestStaticCFGLoopTree:
    """build_static_cfg(...) should produce a HandlerCFG with loop_tree."""

    def test_empty_bytecode(self):
        # Minimal: empty returns HandlerCFG with no loop_tree
        from dragonslayer.analysis.handler_semantics import SemanticOpcodeTable
        table = SemanticOpcodeTable()
        cfg = build_static_cfg(b"", table)
        assert isinstance(cfg, HandlerCFG)
        # Empty → no loops → loop_tree should be None
        assert cfg.loop_tree is None

    def test_handler_cfg_has_loop_tree_field(self):
        """HandlerCFG dataclass has loop_tree attribute of correct type."""
        lt = LoopTree([{"header": 0, "back_edge_source": 1, "body": {0, 1}}])
        cfg = HandlerCFG(loop_tree=lt)
        assert cfg.loop_tree is lt
        assert cfg.loop_tree.loop_count == 1


# ---------------------------------------------------------------------------
# AnalysisMetrics
# ---------------------------------------------------------------------------
from dragonslayer.utils.metrics import AnalysisMetrics, PhaseMetric


class TestAnalysisMetrics:
    """Phase timing and serialisation."""

    def test_phase_context_manager(self):
        m = AnalysisMetrics(run_id="test-1")
        with m.phase("discovery") as pm:
            pm.item_count = 5
            time.sleep(0.01)
        assert m.phase_count == 1
        assert m.get_phase("discovery") is not None
        assert m.get_phase("discovery").elapsed_s >= 0.005

    def test_multiple_phases(self):
        m = AnalysisMetrics()
        with m.phase("a") as pm:
            pm.item_count = 1
        with m.phase("b") as pm:
            pm.item_count = 2
        assert m.phase_count == 2

    def test_to_dict(self):
        m = AnalysisMetrics(run_id="r1")
        with m.phase("x"):
            pass
        m.finalise()
        d = m.to_dict()
        assert d["run_id"] == "r1"
        assert d["phase_count"] == 1
        assert isinstance(d["total_elapsed_s"], float)
        assert len(d["phases"]) == 1

    def test_summary_string(self):
        m = AnalysisMetrics()
        with m.phase("alpha"):
            pass
        s = m.summary()
        assert "total=" in s
        assert "alpha=" in s

    def test_empty_metrics(self):
        m = AnalysisMetrics()
        assert m.phase_count == 0
        assert m.total_elapsed_s >= 0

    def test_error_counting(self):
        m = AnalysisMetrics()
        with pytest.raises(ValueError):
            with m.phase("fail") as pm:
                raise ValueError("boom")
        pm_result = m.get_phase("fail")
        assert pm_result is not None
        assert pm_result.error_count == 1

    def test_repeated_phase_merges(self):
        m = AnalysisMetrics()
        with m.phase("loop") as pm:
            pm.item_count = 3
        with m.phase("loop") as pm:
            pm.item_count = 2
        assert m.phase_count == 1
        assert m.get_phase("loop").item_count == 5

    def test_start_stop_manual(self):
        m = AnalysisMetrics()
        m.start_phase("manual")
        time.sleep(0.01)
        m.stop_phase("manual")
        assert m.get_phase("manual").elapsed_s >= 0.005

    def test_repr(self):
        m = AnalysisMetrics()
        assert "AnalysisMetrics" in repr(m)


# ---------------------------------------------------------------------------
# ML evaluation
# ---------------------------------------------------------------------------


class TestMLEvaluation:
    """Test tools/evaluate_model.py evaluate() function."""

    def test_evaluate_accuracy(self):
        # Import inline to avoid import errors if tools/ not on path
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from tools.evaluate_model import evaluate, load_ground_truth
        from dragonslayer.ml.model import VMHandlerModel

        gt_path = Path(__file__).resolve().parent.parent / "data" / "ground_truth" / "handler_labels.json"
        if not gt_path.exists():
            pytest.skip("Ground truth file not found")

        samples = load_ground_truth(gt_path)
        model = VMHandlerModel()
        results = evaluate(model, samples)

        assert "accuracy" in results
        assert 0.0 <= results["accuracy"] <= 1.0
        assert results["total_samples"] == len(samples)
        assert "per_category" in results

    def test_per_category_fields(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from tools.evaluate_model import evaluate
        from dragonslayer.ml.model import VMHandlerModel

        simple = [
            {"label": "arithmetic", "features": {"arith_ratio": 0.6, "logic_ratio": 0.0, "stack_ratio": 0.0, "branch_ratio": 0.0, "mem_read_ratio": 0.0, "mem_write_ratio": 0.0, "instruction_count": 5, "unique_opcodes": 2}},
        ]
        model = VMHandlerModel()
        results = evaluate(model, simple)
        # Must have per_category with at least 1 entry
        assert len(results["per_category"]) >= 1
        for cat, m in results["per_category"].items():
            assert "precision" in m
            assert "recall" in m
            assert "f1" in m
            assert "support" in m


class TestPhaseMetricDataclass:
    def test_to_dict(self):
        pm = PhaseMetric(name="test", elapsed_s=1.234, item_count=10)
        d = pm.to_dict()
        assert d["name"] == "test"
        assert d["elapsed_s"] == 1.234
        assert d["item_count"] == 10
