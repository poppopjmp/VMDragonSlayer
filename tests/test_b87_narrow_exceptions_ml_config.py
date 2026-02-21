"""
B87 tests — Narrowed exception handlers + configurable ML heuristics
=====================================================================

Validates:
1.  executor.py ``_Z3_EVAL_ERRORS``, ``_Z3_SOLVE_ERRORS``, ``_INSN_ERRORS``
    module-level tuples exist and contain the correct exception types.
2.  state.py ``_Z3_EVAL_ERRORS``, ``_Z3_SOLVE_ERRORS`` tuples exist.
3.  solver.py exception handlers use specific z3 exception types.
4.  orchestrator.py ``_ENGINE_ERRORS`` tuple covers its exception hierarchy.
5.  tracker.py narrows alias-oracle errors to ``(ValueError, TypeError, …)``.
6.  handler_classifier.py heuristic config is default-populated, overridable,
    and loadable from JSON.
7.  The refactored heuristic still classifies canonical patterns identically.
"""

from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# 1. executor.py — exception tuple validation
# ---------------------------------------------------------------------------

class TestExecutorExceptionTuples:
    """Verify module-level narrowed exception tuples in executor.py."""

    def test_z3_eval_errors_defined(self):
        from dragonslayer.analysis.symbolic_execution import executor
        assert hasattr(executor, "_Z3_EVAL_ERRORS")
        assert isinstance(executor._Z3_EVAL_ERRORS, tuple)
        # Must always include base Python errors
        assert ValueError in executor._Z3_EVAL_ERRORS
        assert TypeError in executor._Z3_EVAL_ERRORS
        assert AttributeError in executor._Z3_EVAL_ERRORS

    def test_z3_solve_errors_defined(self):
        from dragonslayer.analysis.symbolic_execution import executor
        assert hasattr(executor, "_Z3_SOLVE_ERRORS")
        assert isinstance(executor._Z3_SOLVE_ERRORS, tuple)
        assert ValueError in executor._Z3_SOLVE_ERRORS
        assert ArithmeticError in executor._Z3_SOLVE_ERRORS

    def test_insn_errors_defined(self):
        from dragonslayer.analysis.symbolic_execution import executor
        assert hasattr(executor, "_INSN_ERRORS")
        assert isinstance(executor._INSN_ERRORS, tuple)
        assert KeyError in executor._INSN_ERRORS
        assert IndexError in executor._INSN_ERRORS
        assert ValueError in executor._INSN_ERRORS

    def test_z3_exception_included_when_z3_available(self):
        from dragonslayer.analysis.symbolic_execution import executor
        if executor._HAS_Z3:
            import z3
            assert z3.Z3Exception in executor._Z3_EVAL_ERRORS
            assert z3.Z3Exception in executor._Z3_SOLVE_ERRORS
            assert z3.Z3Exception in executor._INSN_ERRORS

    def test_no_blanket_exception_in_tuples(self):
        """Ensure Exception itself is NOT in the narrowed tuples."""
        from dragonslayer.analysis.symbolic_execution import executor
        assert Exception not in executor._Z3_EVAL_ERRORS
        assert Exception not in executor._Z3_SOLVE_ERRORS
        assert Exception not in executor._INSN_ERRORS


# ---------------------------------------------------------------------------
# 2. state.py — exception tuple validation
# ---------------------------------------------------------------------------

class TestStateExceptionTuples:
    def test_z3_eval_errors_defined(self):
        from dragonslayer.analysis.symbolic_execution import state
        assert hasattr(state, "_Z3_EVAL_ERRORS")
        assert isinstance(state._Z3_EVAL_ERRORS, tuple)
        assert ValueError in state._Z3_EVAL_ERRORS

    def test_z3_solve_errors_defined(self):
        from dragonslayer.analysis.symbolic_execution import state
        assert hasattr(state, "_Z3_SOLVE_ERRORS")
        assert isinstance(state._Z3_SOLVE_ERRORS, tuple)
        assert ValueError in state._Z3_SOLVE_ERRORS

    def test_z3_exception_in_state_tuples(self):
        from dragonslayer.analysis.symbolic_execution import state
        if state._Z3_AVAILABLE:
            import z3
            assert z3.Z3Exception in state._Z3_EVAL_ERRORS
            assert z3.Z3Exception in state._Z3_SOLVE_ERRORS


# ---------------------------------------------------------------------------
# 3. solver.py — confirm narrowed except clauses compile
# ---------------------------------------------------------------------------

class TestSolverNarrowedExceptions:
    def test_solver_imports_cleanly(self):
        """solver.py should import without errors after B87 changes."""
        from dragonslayer.analysis.symbolic_execution import solver  # noqa: F401
        assert hasattr(solver, "Z3Solver")

    def test_unsat_core_returns_list(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        s = Z3Solver(timeout_ms=500)
        core = s.unsat_core()
        assert isinstance(core, list)

    def test_check_feasibility_returns_bool(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        import z3
        s = Z3Solver(timeout_ms=500)
        x = z3.BitVec("x_feas", 32)
        assert s.check_feasibility(x > 0) in (True, False)


# ---------------------------------------------------------------------------
# 4. orchestrator.py — _ENGINE_ERRORS tuple
# ---------------------------------------------------------------------------

class TestOrchestratorEngineErrors:
    def test_engine_errors_tuple_defined(self):
        from dragonslayer.core import orchestrator
        assert hasattr(orchestrator, "_ENGINE_ERRORS")
        assert isinstance(orchestrator._ENGINE_ERRORS, tuple)

    def test_engine_errors_includes_core_exceptions(self):
        from dragonslayer.core import orchestrator
        from dragonslayer.core.exceptions import (
            AnalysisError,
            AnalysisTimeoutError,
            ConfigurationError,
            InvalidDataError,
        )
        for exc_cls in (AnalysisError, AnalysisTimeoutError, ConfigurationError,
                        InvalidDataError, ValueError, TypeError, KeyError,
                        IndexError, RuntimeError, OSError):
            assert exc_cls in orchestrator._ENGINE_ERRORS

    def test_engine_errors_excludes_base_exception(self):
        from dragonslayer.core import orchestrator
        assert Exception not in orchestrator._ENGINE_ERRORS
        assert BaseException not in orchestrator._ENGINE_ERRORS


# ---------------------------------------------------------------------------
# 5. tracker.py — narrowed alias oracle errors
# ---------------------------------------------------------------------------

class TestTrackerNarrowedExceptions:
    def test_tracker_imports_cleanly(self):
        from dragonslayer.analysis.taint_tracking import tracker  # noqa: F401

    def test_alias_oracle_catches_value_error(self):
        """Taint query should survive a ValueError from the alias oracle."""
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        t = TaintTracker()
        # Wire an alias oracle that raises ValueError
        t._alias_oracle = MagicMock(side_effect=ValueError("bad addr"))
        t._mem_taint[0x1000] = TaintTag.MEMORY
        # Should not raise — the ValueError is caught
        result = t._query_memory_taint_via_oracle(0x2000)
        assert result == TaintTag.CLEAN


# ---------------------------------------------------------------------------
# 6. handler_classifier.py — configurable heuristic thresholds
# ---------------------------------------------------------------------------

class TestHeuristicConfig:
    def test_default_config_populated(self):
        from dragonslayer.ml.handler_classifier import _DEFAULT_HEURISTIC_CONFIG
        assert "rules" in _DEFAULT_HEURISTIC_CONFIG
        assert len(_DEFAULT_HEURISTIC_CONFIG["rules"]) > 0
        assert "default_label" in _DEFAULT_HEURISTIC_CONFIG
        assert "default_confidence" in _DEFAULT_HEURISTIC_CONFIG

    def test_model_has_heuristic_config(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        m = TrainedHandlerModel()
        assert hasattr(m, "_heuristic_config")
        assert "rules" in m._heuristic_config

    def test_configure_heuristics_overrides_rules(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        m = TrainedHandlerModel()
        custom = {"rules": [{"label": "custom_op", "confidence": 0.99, "max_insn": 1}]}
        m.configure_heuristics(custom)
        assert m._heuristic_config["rules"] == custom["rules"]

    def test_configure_heuristics_preserves_unset_keys(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        m = TrainedHandlerModel()
        original_default = m._heuristic_config["default_label"]
        m.configure_heuristics({"rules": []})
        assert m._heuristic_config["default_label"] == original_default

    def test_load_heuristic_config_from_json(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        config = {
            "rules": [{"label": "test_cat", "confidence": 0.88, "max_insn": 5}],
            "default_label": "fallback",
            "default_confidence": 0.1,
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()
            loaded = TrainedHandlerModel.load_heuristic_config(f.name)
        assert loaded["rules"][0]["label"] == "test_cat"
        assert loaded["default_confidence"] == 0.1

    def test_invalid_json_raises(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{bad json!!")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                TrainedHandlerModel.load_heuristic_config(f.name)


# ---------------------------------------------------------------------------
# 7. Heuristic prediction parity with original logic
# ---------------------------------------------------------------------------

class TestHeuristicPredictionParity:
    """Verify the config-driven heuristic produces the same labels as
    the original hardcoded decision tree for canonical inputs."""

    @staticmethod
    def _predict(insn_count: float, vip_delta: float, density: float = 0.0):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        m = TrainedHandlerModel()
        names = ["instruction_count", "vip_delta", "abs_vip_delta", "insn_density"]
        values = [insn_count, vip_delta, abs(vip_delta), density]
        return m._predict_heuristic(values, names)

    def test_nop_handler(self):
        r = self._predict(2, 1)
        assert r.label == "nop"
        assert r.confidence == 0.70

    def test_control_flow_zero_delta(self):
        r = self._predict(10, 0)
        assert r.label == "control_flow"
        assert r.confidence == 0.50

    def test_arithmetic_small_delta(self):
        r = self._predict(6, 1)
        assert r.label == "arithmetic"
        assert r.confidence == 0.60

    def test_comparison_large_insn(self):
        r = self._predict(10, 2)
        assert r.label == "comparison"
        assert r.confidence == 0.50

    def test_memory_mid_delta(self):
        r = self._predict(10, 4)
        assert r.label == "memory"
        assert r.confidence == 0.55

    def test_control_flow_large_delta(self):
        r = self._predict(20, 8)
        assert r.label == "control_flow"
        assert r.confidence == 0.50

    def test_bitwise_high_density(self):
        r = self._predict(14, 10, density=0.9)
        assert r.label == "bitwise"
        assert r.confidence == 0.45

    def test_system_many_insn(self):
        # 25 insns, delta=3 (< 6 so skips control_flow rule), density=0.3
        r = self._predict(25, 3, density=0.3)
        assert r.label == "system"
        assert r.confidence == 0.40

    def test_unknown_fallback(self):
        # 15 insns, delta=10, density=0.5 — doesn't match any rule
        r = self._predict(15, 10, density=0.5)
        assert r.label == "unknown"
        assert r.confidence == 0.30

    def test_custom_config_changes_prediction(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel
        m = TrainedHandlerModel()
        m.configure_heuristics({
            "rules": [{"label": "crypto", "confidence": 0.95, "max_insn": 100}],
        })
        names = ["instruction_count", "vip_delta", "abs_vip_delta", "insn_density"]
        values = [50, 10, 10, 0.5]
        r = m._predict_heuristic(values, names)
        assert r.label == "crypto"
        assert r.confidence == 0.95


# ---------------------------------------------------------------------------
# 8. build_handler_classifier with heuristic_config_path
# ---------------------------------------------------------------------------

class TestBuildHandlerClassifier:
    def test_accepts_heuristic_config_path(self):
        from dragonslayer.ml.handler_classifier import build_handler_classifier
        import inspect
        sig = inspect.signature(build_handler_classifier)
        assert "heuristic_config_path" in sig.parameters

    def test_loads_heuristic_config(self):
        from dragonslayer.ml.handler_classifier import build_handler_classifier
        config = {
            "rules": [{"label": "test_load", "confidence": 0.77, "max_insn": 2}],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()
            clf = build_handler_classifier(heuristic_config_path=f.name)
        # The inner model should have the custom config
        assert clf.model._heuristic_config["rules"][0]["label"] == "test_load"

    def test_bad_config_path_does_not_crash(self):
        from dragonslayer.ml.handler_classifier import build_handler_classifier
        # Should warn but not crash
        clf = build_handler_classifier(heuristic_config_path="/nonexistent/path.json")
        assert clf is not None


# ---------------------------------------------------------------------------
# 9. Probability distribution in heuristic prediction
# ---------------------------------------------------------------------------

class TestHeuristicProbDistribution:
    def test_probabilities_sum_to_one(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel, HANDLER_CATEGORIES
        m = TrainedHandlerModel()
        names = ["instruction_count", "vip_delta", "abs_vip_delta", "insn_density"]
        values = [5, 1, 1, 0.3]
        r = m._predict_heuristic(values, names)
        total = sum(r.probabilities.values())
        assert abs(total - 1.0) < 0.01

    def test_all_categories_in_probabilities(self):
        from dragonslayer.ml.handler_classifier import TrainedHandlerModel, HANDLER_CATEGORIES
        m = TrainedHandlerModel()
        names = ["instruction_count", "vip_delta", "abs_vip_delta", "insn_density"]
        values = [5, 1, 1, 0.3]
        r = m._predict_heuristic(values, names)
        for cat in HANDLER_CATEGORIES:
            assert cat in r.probabilities
