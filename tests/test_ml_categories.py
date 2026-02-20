"""Tests for ML handler categories + model serialization (Batch 34).

Validates new handler categories (vm_entry_exit, context, crypto),
updated op-to-label mappings, synthetic data generation for all
9 categories, and model save/load round-trip.
"""

import pytest

from dragonslayer.ml.model import HANDLER_CATEGORIES, VMHandlerModel
from dragonslayer.ml.trainer import (
    ModelTrainer,
    TrainingResult,
    _OP_TO_LABEL,
    _HANDLER_TEMPLATES,
    generate_synthetic_handlers,
    label_from_heuristics,
    prepare_training_data,
    prepare_extended_training_data,
    feature_importance,
    train_full_pipeline,
)

try:
    import sklearn  # noqa: F401
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

sklearn_required = pytest.mark.skipif(not _HAS_SKLEARN, reason="scikit-learn not installed")


# ---------------------------------------------------------------------------
# Category registration
# ---------------------------------------------------------------------------

class TestCategories:
    """New handler categories are registered properly."""

    def test_vm_entry_exit_in_categories(self):
        assert "vm_entry_exit" in HANDLER_CATEGORIES

    def test_context_in_categories(self):
        assert "context" in HANDLER_CATEGORIES

    def test_crypto_in_categories(self):
        assert "crypto" in HANDLER_CATEGORIES

    def test_total_categories(self):
        assert len(HANDLER_CATEGORIES) >= 10

    def test_all_template_keys_in_categories(self):
        for cat in _HANDLER_TEMPLATES:
            assert cat in HANDLER_CATEGORIES, f"{cat} has templates but not in categories"


# ---------------------------------------------------------------------------
# OP_TO_LABEL mapping
# ---------------------------------------------------------------------------

class TestOpToLabel:
    """New operation → label mappings cover VMProtect operations."""

    @pytest.mark.parametrize("op,label", [
        ("vm_enter", "vm_entry_exit"),
        ("vm_exit", "vm_entry_exit"),
        ("vm_ctx_save", "context"),
        ("vm_ctx_restore", "context"),
        ("vm_fetch_opcode", "context"),
        ("vm_dispatch", "context"),
        ("vm_decrypt", "crypto"),
        ("vm_key_update", "crypto"),
        ("vm_cpuid", "crypto"),
        ("vm_rdtsc", "crypto"),
        ("vm_nand", "logic"),
        ("vm_nor", "logic"),
    ])
    def test_mapping(self, op, label):
        assert _OP_TO_LABEL[op] == label

    def test_label_from_heuristics_vm_enter(self):
        assert label_from_heuristics({"operation": "vm_enter"}) == "vm_entry_exit"

    def test_label_from_heuristics_vm_decrypt(self):
        assert label_from_heuristics({"operation": "vm_decrypt"}) == "crypto"

    def test_label_from_heuristics_partial_match(self):
        # "vm_ctx_save" partial match
        assert label_from_heuristics({"operation": "vm_ctx_save"}) == "context"


# ---------------------------------------------------------------------------
# Synthetic data generation
# ---------------------------------------------------------------------------

class TestSyntheticGeneration:
    """Synthetic handler generation covers all 9 categories."""

    def test_generates_all_categories(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=42)
        cats = {h["category"] for h in handlers}
        expected = set(_HANDLER_TEMPLATES.keys())
        assert expected.issubset(cats)

    def test_count_per_category(self):
        n = 20
        handlers = generate_synthetic_handlers(n_per_category=n, seed=42)
        from collections import Counter
        counts = Counter(h["category"] for h in handlers)
        for cat in _HANDLER_TEMPLATES:
            assert counts.get(cat, 0) == n, f"{cat} should have {n} samples"

    def test_vm_entry_exit_has_push_pop(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=42)
        entry_exit = [h for h in handlers if h["category"] == "vm_entry_exit"]
        assert len(entry_exit) == 10
        # At least some should contain push or pop mnemonics
        all_mnems = set()
        for h in entry_exit:
            all_mnems.update(h["mnemonics"])
        assert "push" in all_mnems or "pop" in all_mnems

    def test_crypto_has_xor_or_rol(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=42)
        crypto = [h for h in handlers if h["category"] == "crypto"]
        all_mnems = set()
        for h in crypto:
            all_mnems.update(h["mnemonics"])
        assert "xor" in all_mnems or "rol" in all_mnems or "imul" in all_mnems

    def test_context_has_movzx_or_lea(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=42)
        context = [h for h in handlers if h["category"] == "context"]
        all_mnems = set()
        for h in context:
            all_mnems.update(h["mnemonics"])
        assert "movzx" in all_mnems or "lea" in all_mnems or "sub" in all_mnems


# ---------------------------------------------------------------------------
# Training pipeline with new categories
# ---------------------------------------------------------------------------

class TestTrainingPipeline:
    """Training pipeline handles 9 categories."""

    @sklearn_required
    def test_train_full_pipeline_9_categories(self):
        model, result, imp = train_full_pipeline(n_per_category=30, seed=42)
        assert result.accuracy > 0.7
        assert model.is_trained

    @sklearn_required
    def test_model_predicts_new_categories(self):
        from dragonslayer.ml.pipeline import extract_extended_features

        model, _, _ = train_full_pipeline(n_per_category=50, seed=42)
        handlers = generate_synthetic_handlers(n_per_category=5, seed=99)

        # Test that new categories appear in predictions
        predicted_cats = set()
        for h in handlers:
            fv = extract_extended_features(h)
            pred = model.predict({"values": fv.values, "names": fv.feature_names})
            predicted_cats.add(pred.label)

        # Should predict at least 5 distinct categories
        assert len(predicted_cats) >= 5

    @sklearn_required
    def test_feature_importance_non_empty(self):
        _, _, imp = train_full_pipeline(n_per_category=30, seed=42)
        assert len(imp) >= 5

    def test_prepare_extended_training_data_new_cats(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=42)
        features, labels = prepare_extended_training_data(handlers, label_key="category")
        assert "vm_entry_exit" in labels
        assert "crypto" in labels
        assert "context" in labels


# ---------------------------------------------------------------------------
# Model serialization
# ---------------------------------------------------------------------------

class TestModelSerialization:
    """Model save/load round-trip."""

    def test_save_raises_without_model(self):
        model = VMHandlerModel()
        with pytest.raises(RuntimeError, match="No trained model"):
            model.save("/tmp/nonexistent.pkl")

    def test_is_trained_false_initially(self):
        model = VMHandlerModel()
        assert not model.is_trained

    @sklearn_required
    def test_save_load_roundtrip(self, tmp_path):
        model, result, _ = train_full_pipeline(n_per_category=20, seed=42)
        path = str(tmp_path / "model.pkl")
        model.save(path)

        model2 = VMHandlerModel()
        model2.load(path)
        assert model2.is_trained

    @sklearn_required
    def test_saved_model_predicts(self, tmp_path):
        from dragonslayer.ml.pipeline import extract_extended_features

        model, _, _ = train_full_pipeline(n_per_category=30, seed=42)
        path = str(tmp_path / "model.pkl")
        model.save(path)

        model2 = VMHandlerModel()
        model2.load(path)

        handler = generate_synthetic_handlers(n_per_category=1, seed=99)[0]
        fv = extract_extended_features(handler)
        pred = model2.predict({"values": fv.values, "names": fv.feature_names})
        assert pred.label in HANDLER_CATEGORIES
        assert pred.confidence > 0.0

    @sklearn_required
    def test_train_full_pipeline_with_save(self, tmp_path):
        path = str(tmp_path / "auto_saved.pkl")
        model, result, _ = train_full_pipeline(
            n_per_category=20, seed=42, save_path=path
        )
        import os
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# Heuristic rules for new categories
# ---------------------------------------------------------------------------

class TestHeuristicRules:
    """Heuristic scorer handles new categories."""

    def test_heuristic_returns_new_category(self):
        """Scoring should include new categories as possible outputs."""
        from dragonslayer.ml.model import _score_rules
        # A feature vector with high stack_ratio + high instruction_count
        # should give non-zero score for vm_entry_exit
        names = ["stack_ratio", "instruction_count", "mem_ratio",
                 "arith_ratio", "logic_ratio", "branch_ratio",
                 "nop_ratio", "has_memory_read", "has_memory_write",
                 "has_indirect_branch"]
        vals = [0.7, 16.0, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        scores = _score_rules(vals, names)
        assert "vm_entry_exit" in scores
        assert scores["vm_entry_exit"] > 0

    def test_crypto_heuristic(self):
        from dragonslayer.ml.model import _score_rules
        names = ["logic_ratio", "arith_ratio", "instruction_count",
                 "stack_ratio", "mem_ratio", "branch_ratio",
                 "nop_ratio", "has_memory_read", "has_memory_write",
                 "has_indirect_branch"]
        vals = [0.5, 0.3, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        scores = _score_rules(vals, names)
        assert "crypto" in scores
        assert scores["crypto"] > 0
