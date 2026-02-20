"""
B50 — Trained ML Classifier Tests
===================================

Tests for:
1. GradientBoosting training via ModelTrainer
2. Per-class metrics in TrainingResult
3. train_full_pipeline with algorithm selection
4. Model predict via trained sklearn estimator
5. Feature importance extraction
6. Model save/load cycle
7. Prediction accuracy on synthetic data
"""

import os
import tempfile

import pytest

from dragonslayer.ml.trainer import (
    ModelTrainer,
    TrainingResult,
    generate_synthetic_handlers,
    prepare_extended_training_data,
    train_full_pipeline,
    feature_importance,
    _HAS_SKLEARN,
)
from dragonslayer.ml.model import VMHandlerModel
from dragonslayer.ml.pipeline import extract_extended_features, EXTENDED_FEATURE_NAMES

pytestmark = pytest.mark.skipif(not _HAS_SKLEARN, reason="scikit-learn not installed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def synthetic_data():
    """Generate synthetic handlers once for all tests."""
    handlers = generate_synthetic_handlers(n_per_category=30, seed=123)
    features, labels = prepare_extended_training_data(handlers, label_key="category")
    return features, labels, handlers


@pytest.fixture(scope="module")
def gb_model_and_result(synthetic_data):
    """Train a GradientBoosting model once."""
    features, labels, _ = synthetic_data
    model = VMHandlerModel()
    trainer = ModelTrainer(model)
    result = trainer.train(features, labels, n_estimators=50, algorithm="gb")
    return model, result


@pytest.fixture(scope="module")
def rf_model_and_result(synthetic_data):
    """Train a RandomForest model once."""
    features, labels, _ = synthetic_data
    model = VMHandlerModel()
    trainer = ModelTrainer(model)
    result = trainer.train(features, labels, n_estimators=50, algorithm="rf")
    return model, result


# ---------------------------------------------------------------------------
# 1. GradientBoosting training
# ---------------------------------------------------------------------------

class TestGradientBoostingTraining:
    def test_gb_trains(self, gb_model_and_result):
        model, result = gb_model_and_result
        assert result.accuracy > 0.5  # Should be reasonable on synthetic data
        assert model.is_trained

    def test_gb_algorithm_in_metrics(self, gb_model_and_result):
        _, result = gb_model_and_result
        assert result.metrics.get("algorithm") == "GradientBoosting"

    def test_rf_trains(self, rf_model_and_result):
        model, result = rf_model_and_result
        assert result.accuracy > 0.5
        assert model.is_trained

    def test_rf_algorithm_in_metrics(self, rf_model_and_result):
        _, result = rf_model_and_result
        assert result.metrics.get("algorithm") == "RandomForest"


# ---------------------------------------------------------------------------
# 2. Per-class metrics
# ---------------------------------------------------------------------------

class TestPerClassMetrics:
    def test_per_class_present(self, gb_model_and_result):
        _, result = gb_model_and_result
        per_class = result.metrics.get("per_class", {})
        assert isinstance(per_class, dict)
        assert len(per_class) > 0

    def test_per_class_has_precision_recall(self, gb_model_and_result):
        _, result = gb_model_and_result
        per_class = result.metrics.get("per_class", {})
        # Check at least one category has precision/recall/f1
        for cls_name, metrics in per_class.items():
            if isinstance(metrics, dict) and "precision" in metrics:
                assert "recall" in metrics
                assert "f1-score" in metrics
                break
        else:
            pytest.fail("No per-class metrics with precision/recall found")


# ---------------------------------------------------------------------------
# 3. train_full_pipeline
# ---------------------------------------------------------------------------

class TestTrainFullPipeline:
    def test_auto_pipeline(self):
        model, result, importances = train_full_pipeline(
            n_per_category=20, seed=99, algorithm="auto",
        )
        assert model.is_trained
        assert result.accuracy > 0.4
        assert len(importances) > 0

    def test_gb_pipeline(self):
        model, result, importances = train_full_pipeline(
            n_per_category=20, seed=99, algorithm="gb",
        )
        assert result.metrics.get("algorithm") == "GradientBoosting"

    def test_rf_pipeline(self):
        model, result, importances = train_full_pipeline(
            n_per_category=20, seed=99, algorithm="rf",
        )
        assert result.metrics.get("algorithm") == "RandomForest"

    def test_pipeline_with_save(self, tmp_path):
        save_file = str(tmp_path / "test_model.pkl")
        model, result, _ = train_full_pipeline(
            n_per_category=20, seed=99, save_path=save_file,
        )
        assert os.path.exists(save_file)


# ---------------------------------------------------------------------------
# 4. Model prediction via trained estimator
# ---------------------------------------------------------------------------

class TestTrainedPrediction:
    def test_predict_returns_label(self, gb_model_and_result, synthetic_data):
        model, _ = gb_model_and_result
        features, labels, _ = synthetic_data
        fv = features[0]
        pred = model.predict({"values": fv.values, "names": fv.feature_names})
        assert pred.label in (
            "arithmetic", "bitwise", "stack", "load_store", "branch",
            "vm_entry_exit", "context", "crypto", "nop",
            "memory", "control_flow", "vm_control", "comparison",
            "unknown",
        )
        assert 0 <= pred.confidence <= 1.0

    def test_predict_probability_distribution(self, gb_model_and_result, synthetic_data):
        model, _ = gb_model_and_result
        features, labels, _ = synthetic_data
        fv = features[0]
        pred = model.predict({"values": fv.values, "names": fv.feature_names})
        # probabilities should sum to ~1.0
        if pred.probabilities:
            total = sum(pred.probabilities.values())
            assert abs(total - 1.0) < 0.05

    def test_batch_accuracy(self, gb_model_and_result, synthetic_data):
        model, _ = gb_model_and_result
        features, labels, _ = synthetic_data
        correct = 0
        for fv, true_label in zip(features, labels):
            pred = model.predict({"values": fv.values, "names": fv.feature_names})
            if pred.label == true_label:
                correct += 1
        accuracy = correct / len(labels) if labels else 0
        # Trained model should do better than random (9 categories)
        assert accuracy > 0.3


# ---------------------------------------------------------------------------
# 5. Feature importance
# ---------------------------------------------------------------------------

class TestFeatureImportance:
    def test_import_extraction(self, gb_model_and_result):
        model, _ = gb_model_and_result
        importances = feature_importance(model, feature_names=EXTENDED_FEATURE_NAMES)
        assert len(importances) > 0
        # Top feature should have positive importance
        assert importances[0][1] > 0

    def test_importance_sorted_descending(self, gb_model_and_result):
        model, _ = gb_model_and_result
        importances = feature_importance(model, feature_names=EXTENDED_FEATURE_NAMES, top_n=10)
        for i in range(len(importances) - 1):
            assert importances[i][1] >= importances[i + 1][1]

    def test_importance_names_match(self, gb_model_and_result):
        model, _ = gb_model_and_result
        importances = feature_importance(model, feature_names=EXTENDED_FEATURE_NAMES, top_n=5)
        for name, _ in importances:
            assert name in EXTENDED_FEATURE_NAMES


# ---------------------------------------------------------------------------
# 6. Model save/load
# ---------------------------------------------------------------------------

class TestSaveLoad:
    def test_save_and_reload(self, gb_model_and_result, synthetic_data, tmp_path):
        model, _ = gb_model_and_result
        features, labels, _ = synthetic_data

        save_file = str(tmp_path / "model.pkl")
        model.save(save_file)
        assert os.path.exists(save_file)

        # Load into a fresh model
        new_model = VMHandlerModel()
        new_model.load(save_file)
        assert new_model.is_trained

        # Predictions should match
        fv = features[0]
        pred_orig = model.predict({"values": fv.values, "names": fv.feature_names})
        pred_loaded = new_model.predict({"values": fv.values, "names": fv.feature_names})
        assert pred_orig.label == pred_loaded.label


# ---------------------------------------------------------------------------
# 7. Accuracy comparison: GB vs RF
# ---------------------------------------------------------------------------

class TestAlgorithmComparison:
    def test_both_algorithms_reasonable(self, gb_model_and_result, rf_model_and_result):
        _, gb_result = gb_model_and_result
        _, rf_result = rf_model_and_result
        # Both should achieve reasonable accuracy
        assert gb_result.accuracy > 0.3
        assert rf_result.accuracy > 0.3
