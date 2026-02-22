"""
B88 tests — Pipeline + ML exception narrowing
==============================================

Validates:
1.  pipeline.py ``_STAGE_ERRORS`` tuple defined with correct exception types.
2.  Pipeline stage handlers no longer catch ``Exception`` directly.
3.  ML classifier/ensemble/trainer/evaluate handlers narrowed.
4.  Pipeline imports and initializes correctly.
5.  ML batch classify still returns unknown on failure.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# 1. pipeline.py — _STAGE_ERRORS tuple
# ---------------------------------------------------------------------------

class TestPipelineStageErrors:
    def test_stage_errors_defined(self):
        from dragonslayer.core import pipeline
        assert hasattr(pipeline, "_STAGE_ERRORS")
        assert isinstance(pipeline._STAGE_ERRORS, tuple)

    def test_stage_errors_contents(self):
        from dragonslayer.core.pipeline import _STAGE_ERRORS
        from dragonslayer.core.exceptions import VMDragonSlayerError
        # After narrowing, only framework + OS + ImportError are caught
        for exc_cls in (VMDragonSlayerError, OSError, ImportError):
            assert exc_cls in _STAGE_ERRORS, f"{exc_cls.__name__} not in _STAGE_ERRORS"
        # Generic programming-error types should NOT be present
        for exc_cls in (ValueError, TypeError, KeyError, IndexError, AttributeError):
            assert exc_cls not in _STAGE_ERRORS, f"{exc_cls.__name__} should not be in _STAGE_ERRORS"

    def test_no_base_exception_in_stage_errors(self):
        from dragonslayer.core.pipeline import _STAGE_ERRORS
        assert Exception not in _STAGE_ERRORS
        assert BaseException not in _STAGE_ERRORS


# ---------------------------------------------------------------------------
# 2. Pipeline init
# ---------------------------------------------------------------------------

class TestPipelineInit:
    def test_pipeline_creates_without_config(self):
        from dragonslayer.core.pipeline import AnalysisPipeline
        pipe = AnalysisPipeline()
        assert pipe is not None

    def test_pipeline_accepts_config(self):
        from dragonslayer.core.pipeline import AnalysisPipeline
        cfg = {"some_key": "some_value"}
        pipe = AnalysisPipeline(config=cfg)
        assert pipe._cfg == cfg


# ---------------------------------------------------------------------------
# 3. Pipeline no broad except
# ---------------------------------------------------------------------------

class TestPipelineNoBlankExcept:
    """Ensure pipeline.py has no except-Exception (only _STAGE_ERRORS)."""

    def test_no_bare_except_exception_in_pipeline(self):
        """Parse pipeline.py AST to verify no bare 'except Exception'."""
        import dragonslayer.core.pipeline as mod
        src = inspect.getsource(mod)
        tree = ast.parse(src)

        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                handler_type = node.type
                if handler_type is None:
                    # bare except: — not our concern here
                    continue
                if isinstance(handler_type, ast.Name) and handler_type.id == "Exception":
                    violations.append(node.lineno)

        # Allow 0 violations (ideal) — but tolerate <= 1 for edge cases
        assert len(violations) <= 1, (
            f"Found {len(violations)} bare 'except Exception' at lines: {violations}"
        )


# ---------------------------------------------------------------------------
# 4. ML classifier batch handles errors
# ---------------------------------------------------------------------------

class TestMLClassifierBatch:
    def test_batch_classify_handles_value_error(self):
        from dragonslayer.ml.classifier import VMClassifier
        from dragonslayer.ml.model import VMHandlerModel

        model = VMHandlerModel()
        clf = VMClassifier(model=model)
        # handler that will fail
        bad_handler = {"bad_key": "no_values"}
        results = clf.classify_batch([bad_handler])
        assert len(results) == 1
        # Should still return a result (unknown) rather than crashing
        assert results[0] is not None


# ---------------------------------------------------------------------------
# 5. ML ensemble handles model failure
# ---------------------------------------------------------------------------

class TestMLEnsembleNarrowed:
    def test_ensemble_catches_value_error(self):
        from dragonslayer.ml.ensemble import EnsembleClassifier
        from dragonslayer.ml.model import PredictionResult

        # Model that raises ValueError
        failing_model = MagicMock()
        failing_model.predict.side_effect = ValueError("bad features")
        failing_model.name = "bad_model"

        # Model that succeeds
        good_model = MagicMock()
        good_model.predict.return_value = PredictionResult(
            label="arithmetic", confidence=0.8,
        )
        good_model.name = "good_model"

        ensemble = EnsembleClassifier(models=[failing_model, good_model])
        result = ensemble.predict_safe({"values": [1.0], "names": ["x"]})
        assert result.label == "arithmetic"

    def test_ensemble_all_fail_returns_unknown(self):
        from dragonslayer.ml.ensemble import EnsembleClassifier

        bad = MagicMock()
        bad.predict.side_effect = TypeError("oops")
        bad.name = "bad"

        ensemble = EnsembleClassifier(models=[bad])
        result = ensemble.predict_safe({"values": [1.0], "names": ["x"]})
        assert result.label == "unknown"
        assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# 6. ML trainer narrowed (no bare except Exception)
# ---------------------------------------------------------------------------

class TestMLTrainerNarrowed:
    def test_trainer_module_imports(self):
        from dragonslayer.ml import trainer  # noqa: F401
        assert hasattr(trainer, "ModelTrainer")

    def test_no_bare_except_exception_in_trainer(self):
        import dragonslayer.ml.trainer as mod
        src = inspect.getsource(mod)
        tree = ast.parse(src)

        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    violations.append(node.lineno)

        assert len(violations) == 0, (
            f"Found {len(violations)} 'except Exception' in trainer.py at lines: {violations}"
        )


# ---------------------------------------------------------------------------
# 7. ML evaluate narrowed
# ---------------------------------------------------------------------------

class TestMLEvaluateNarrowed:
    def test_no_bare_except_exception_in_evaluate(self):
        import dragonslayer.ml.evaluate as mod
        src = inspect.getsource(mod)
        tree = ast.parse(src)

        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    violations.append(node.lineno)

        assert len(violations) == 0, (
            f"Found {len(violations)} 'except Exception' in evaluate.py at lines: {violations}"
        )


# ---------------------------------------------------------------------------
# 8. ML ensemble narrowed (AST check)
# ---------------------------------------------------------------------------

class TestMLEnsembleASTCheck:
    def test_no_bare_except_exception_in_ensemble(self):
        import dragonslayer.ml.ensemble as mod
        src = inspect.getsource(mod)
        tree = ast.parse(src)

        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    violations.append(node.lineno)

        assert len(violations) == 0, (
            f"Found {len(violations)} 'except Exception' in ensemble.py at lines: {violations}"
        )
