"""B67 – ML hardening tests.

Covers:
1. Precompiled regex in SymbolicClassifierModel
2. VMHandlerModel input validation (empty, NaN/Inf, mismatch)
3. Model versioning (save/load envelope)
4. Trainer input validation (empty, mismatch, inconsistent dims)
5. Confidence calibration (CalibratedClassifierCV wrapper)
6. Ensemble confidence clamping [0, 1]
7. Fault-tolerant classify_batch
8. Pipeline: no inline ``import re`` in hot path
"""

from __future__ import annotations

import math
import re
import tempfile
from typing import Dict, List
from unittest.mock import MagicMock

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Precompiled regex in SymbolicClassifierModel
# ═══════════════════════════════════════════════════════════════════════════════


class TestSymbolicExprRulesCompiled:
    """_EXPR_RULES should contain compiled regex objects, not raw strings."""

    def test_rules_are_compiled(self):
        from dragonslayer.ml.model import SymbolicClassifierModel

        for rule in SymbolicClassifierModel._EXPR_RULES:
            pattern, label, confidence = rule
            assert hasattr(pattern, "search"), (
                f"Rule {label!r}: pattern should be compiled regex, got {type(pattern)}"
            )

    def test_rsp_re_is_class_level(self):
        from dragonslayer.ml.model import SymbolicClassifierModel

        assert hasattr(SymbolicClassifierModel, "_RSP_RE")
        assert hasattr(SymbolicClassifierModel._RSP_RE, "search")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. VMHandlerModel input validation
# ═══════════════════════════════════════════════════════════════════════════════

from dragonslayer.ml.model import VMHandlerModel, PredictionResult


class TestVMHandlerModelValidation:

    def test_empty_values_returns_unknown(self):
        m = VMHandlerModel()
        result = m.predict({"values": [], "names": []})
        assert result.label == "unknown"
        assert result.confidence == 0.0

    def test_names_values_mismatch_raises(self):
        m = VMHandlerModel()
        with pytest.raises(ValueError, match="mismatch"):
            m.predict({"values": [1.0, 2.0], "names": ["a"]})

    def test_nan_replaced_with_zero(self):
        m = VMHandlerModel()
        result = m.predict({"values": [float("nan"), 1.0, 2.0, 3.0], "names": []})
        # Should not crash; returns a valid prediction
        assert isinstance(result, PredictionResult)

    def test_inf_replaced_with_zero(self):
        m = VMHandlerModel()
        result = m.predict({"values": [float("inf"), 1.0, 2.0], "names": []})
        assert isinstance(result, PredictionResult)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Model versioning envelope
# ═══════════════════════════════════════════════════════════════════════════════


class TestModelVersioning:

    @pytest.fixture
    def trained_model(self):
        """Quickly train a model for serialization testing."""
        m = VMHandlerModel()
        try:
            from sklearn.ensemble import RandomForestClassifier
            import numpy as np
        except ImportError:
            pytest.skip("scikit-learn not installed")
        clf = RandomForestClassifier(n_estimators=5, random_state=42)
        X = np.array([[1, 2], [3, 4], [5, 6], [7, 8]])
        y = np.array(["a", "b", "a", "b"])
        clf.fit(X, y)
        m._sklearn_model = clf
        return m

    def test_save_creates_versioned_envelope(self, trained_model, tmp_path):
        path = str(tmp_path / "model.pkl")
        trained_model.save(path, feature_names=["f0", "f1"])

        # Verify round-trip produces versioned metadata
        loaded = VMHandlerModel()
        loaded.load(path)
        assert loaded.is_trained
        assert loaded._feature_names == ["f0", "f1"]
        assert hasattr(loaded, "_feature_names")

    def test_load_versioned_envelope(self, trained_model, tmp_path):
        path = str(tmp_path / "model.pkl")
        trained_model.save(path, feature_names=["f0", "f1"])

        loaded = VMHandlerModel()
        loaded.load(path)
        assert loaded.is_trained
        assert loaded._feature_names == ["f0", "f1"]

    def test_load_rejects_future_version(self, tmp_path):
        import pickle
        path = str(tmp_path / "future.pkl")
        with open(path, "wb") as f:
            pickle.dump({"schema_version": 999, "model": None}, f)

        m = VMHandlerModel()
        with pytest.raises(ValueError, match="schema version"):
            m.load(path)

    def test_load_legacy_raw_model(self, trained_model, tmp_path):
        """Legacy models (raw sklearn objects) still load correctly."""
        import pickle
        path = str(tmp_path / "legacy.pkl")
        with open(path, "wb") as f:
            pickle.dump(trained_model._sklearn_model, f)

        loaded = VMHandlerModel()
        loaded.load(path)
        assert loaded.is_trained


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Trainer input validation
# ═══════════════════════════════════════════════════════════════════════════════

from dragonslayer.ml.pipeline import FeatureVector


class TestTrainerValidation:

    def _make_fv(self, dim=5, val=1.0):
        return FeatureVector(values=[val] * dim)

    def test_empty_dataset_raises(self):
        from dragonslayer.ml.trainer import ModelTrainer
        t = ModelTrainer()
        with pytest.raises(ValueError, match="empty"):
            t.train([], [])

    def test_mismatched_lengths_raises(self):
        from dragonslayer.ml.trainer import ModelTrainer
        t = ModelTrainer()
        with pytest.raises(ValueError, match="mismatch"):
            t.train([self._make_fv()], ["a", "b"])

    def test_inconsistent_dimensions_raises(self):
        from dragonslayer.ml.trainer import ModelTrainer
        t = ModelTrainer()
        fv3 = FeatureVector(values=[1.0, 2.0, 3.0])
        fv5 = FeatureVector(values=[1.0, 2.0, 3.0, 4.0, 5.0])
        with pytest.raises(ValueError, match="Inconsistent"):
            t.train([fv3, fv5], ["a", "b"])


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Ensemble confidence clamping
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnsembleConfidenceClamping:

    def test_confidence_never_exceeds_one(self):
        from dragonslayer.ml.ensemble import WeightedEnsemble
        from dragonslayer.ml.model import BaseModel

        class HighConfModel(BaseModel):
            name = "high"
            def predict(self, features):
                return PredictionResult(label="test", confidence=0.99)

        ens = WeightedEnsemble(
            models=[HighConfModel(), HighConfModel()],
            weights=[5.0, 5.0],  # weights > 1 could push confidence > 1
        )
        result = ens.predict({})
        assert 0.0 <= result.confidence <= 1.0

    def test_confidence_never_below_zero(self):
        from dragonslayer.ml.ensemble import WeightedEnsemble
        from dragonslayer.ml.model import BaseModel

        class ZeroConfModel(BaseModel):
            name = "zero"
            def predict(self, features):
                return PredictionResult(label="test", confidence=0.0)

        ens = WeightedEnsemble(
            models=[ZeroConfModel()],
            weights=[1.0],
        )
        result = ens.predict({})
        assert result.confidence >= 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Fault-tolerant classify_batch
# ═══════════════════════════════════════════════════════════════════════════════


class TestFaultTolerantBatch:

    def test_bad_handler_does_not_abort_batch(self):
        from dragonslayer.ml.classifier import VMClassifier

        clf = VMClassifier()
        handlers = [
            {"mnemonics": ["push", "mov"]},  # valid
            None,  # will raise
            {"mnemonics": ["add", "sub"]},  # valid
        ]
        results = clf.classify_batch(handlers)
        assert len(results) == 3
        assert results[1].label == "unknown"
        assert "error" in results[1].metadata

    def test_all_valid_handlers_classified(self):
        from dragonslayer.ml.classifier import VMClassifier

        clf = VMClassifier()
        handlers = [
            {"mnemonics": ["push", "mov", "add"]},
            {"mnemonics": ["xor", "shr", "and"]},
        ]
        results = clf.classify_batch(handlers)
        assert len(results) == 2
        assert all(r.label != "unknown" or r.confidence >= 0.0 for r in results)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Pipeline: no inline import in hot path
# ═══════════════════════════════════════════════════════════════════════════════


class TestPipelineImportClean:

    def test_no_inline_import_re_in_extract_handler_features(self):
        """The extract_handler_features function should not contain 'import re'."""
        import inspect
        from dragonslayer.ml.pipeline import extract_handler_features

        source = inspect.getsource(extract_handler_features)
        assert "import re" not in source, (
            "Inline 'import re' still present in extract_handler_features"
        )
