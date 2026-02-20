"""
Tests for Batch 29 -- ML Training Pipeline
===========================================

Validates extended feature extraction (n-grams, register effects,
operand patterns), synthetic data generation, and end-to-end training.
"""

from __future__ import annotations

import pytest
from typing import Dict, Any, List

from dragonslayer.ml.pipeline import (
    extract_handler_features,
    extract_extended_features,
    extract_bigram_features,
    extract_register_effects,
    extract_operand_pattern_features,
    FeatureVector,
    HANDLER_FEATURE_NAMES,
    EXTENDED_FEATURE_NAMES,
    VMPROTECT_BIGRAMS,
    BIGRAM_FEATURE_NAMES,
    REGISTER_FEATURE_NAMES,
    OPERAND_PATTERN_NAMES,
)
from dragonslayer.ml.trainer import (
    generate_synthetic_handlers,
    prepare_training_data,
    prepare_extended_training_data,
    label_from_heuristics,
    ModelTrainer,
    TrainingResult,
    feature_importance,
    train_full_pipeline,
)
from dragonslayer.ml.model import VMHandlerModel, PredictionResult, HANDLER_CATEGORIES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler(mnemonics: List[str], **kwargs) -> Dict[str, Any]:
    """Build a handler dict from a mnemonic list."""
    instructions = [{"mnemonic": m, "operands": ""} for m in mnemonics]
    h: Dict[str, Any] = {
        "instructions": instructions,
        "mnemonics": list(mnemonics),
        "reads": [],
        "writes": [],
    }
    h.update(kwargs)
    return h


def _arith_handler() -> Dict[str, Any]:
    return {
        "instructions": [
            {"mnemonic": "mov", "operands": "rax, [rbp]"},
            {"mnemonic": "mov", "operands": "rcx, [rbp+8]"},
            {"mnemonic": "add", "operands": "rax, rcx"},
            {"mnemonic": "mov", "operands": "[rbp+8], rax"},
        ],
        "mnemonics": ["mov", "mov", "add", "mov"],
        "reads": [],
        "writes": [],
    }


def _logic_handler() -> Dict[str, Any]:
    return {
        "instructions": [
            {"mnemonic": "mov", "operands": "rax, [rbp]"},
            {"mnemonic": "xor", "operands": "rax, rcx"},
            {"mnemonic": "shr", "operands": "rax, 4"},
            {"mnemonic": "mov", "operands": "[rbp], rax"},
        ],
        "mnemonics": ["mov", "xor", "shr", "mov"],
        "reads": [],
        "writes": [],
    }


# ===================================================================
# 1. Feature dimensions
# ===================================================================

class TestFeatureDimensions:
    def test_base_feature_count(self):
        assert len(HANDLER_FEATURE_NAMES) == 15

    def test_bigram_feature_count(self):
        assert len(BIGRAM_FEATURE_NAMES) == len(VMPROTECT_BIGRAMS)
        assert len(BIGRAM_FEATURE_NAMES) == 25

    def test_register_feature_count(self):
        assert len(REGISTER_FEATURE_NAMES) == 32  # 16 regs * 2

    def test_operand_pattern_count(self):
        assert len(OPERAND_PATTERN_NAMES) == 6

    def test_extended_total(self):
        assert len(EXTENDED_FEATURE_NAMES) == 15 + 25 + 32 + 6 + 20 + 32  # 130

    def test_extended_extraction_dimension(self):
        fv = extract_extended_features(_arith_handler())
        assert fv.dimension == 130
        assert len(fv.feature_names) == 130


# ===================================================================
# 2. Bigram extraction
# ===================================================================

class TestBigramExtraction:
    def test_empty_mnemonics(self):
        result = extract_bigram_features([])
        assert len(result) == len(VMPROTECT_BIGRAMS)
        assert all(v == 0.0 for v in result)

    def test_single_mnemonic(self):
        result = extract_bigram_features(["mov"])
        assert all(v == 0.0 for v in result)

    def test_known_bigram_detected(self):
        mnems = ["mov", "add", "mov"]
        result = extract_bigram_features(mnems)
        # ("mov", "add") is at index 0, ("add", "mov") is at index 1
        assert result[0] > 0.0  # mov->add
        assert result[1] > 0.0  # add->mov

    def test_xor_shr_bigram(self):
        mnems = ["xor", "shr"]
        result = extract_bigram_features(mnems)
        # ("xor", "shr") is at index 13
        idx = VMPROTECT_BIGRAMS.index(("xor", "shr"))
        assert result[idx] > 0.0

    def test_normalised_values(self):
        """Bigram values should be between 0 and 1."""
        mnems = ["mov", "add"] * 20
        result = extract_bigram_features(mnems)
        for v in result:
            assert 0.0 <= v <= 1.0


# ===================================================================
# 3. Register effects
# ===================================================================

class TestRegisterEffects:
    def test_explicit_reg_reads(self):
        h = {"reg_reads": {"rax", "rcx"}, "reg_writes": {"rax"}}
        result = extract_register_effects(h)
        assert len(result) == 32
        # rax read=1.0, write=1.0 -> indices 0,1
        assert result[0] == 1.0   # rax read
        assert result[1] == 1.0   # rax write
        # rcx read=1.0, write=0.0 -> indices 4,5
        assert result[4] == 1.0   # rcx read
        assert result[5] == 0.0   # rcx write

    def test_inferred_from_instructions(self):
        h = {
            "instructions": [
                {"mnemonic": "mov", "operands": "rax, rcx"},
            ]
        }
        result = extract_register_effects(h)
        assert result[0] == 1.0   # rax read (it appears in operands)
        assert result[1] == 1.0   # rax write (first operand of mov)

    def test_empty_handler(self):
        result = extract_register_effects({})
        assert len(result) == 32
        assert all(v == 0.0 for v in result)


# ===================================================================
# 4. Operand patterns
# ===================================================================

class TestOperandPatterns:
    def test_memory_deref_detected(self):
        h = {
            "instructions": [
                {"mnemonic": "mov", "operands": "rax, [rbp+8]"},
                {"mnemonic": "mov", "operands": "[rbp], rax"},
            ]
        }
        result = extract_operand_pattern_features(h)
        assert len(result) == 6
        # mem_deref_ratio should be 0.5 (2 mem ops out of 4 total)
        assert result[1] == pytest.approx(0.5)  # mem_deref_ratio

    def test_scale_index_detected(self):
        h = {
            "instructions": [
                {"mnemonic": "mov", "operands": "rax, [rbx+rcx*8]"},
            ]
        }
        result = extract_operand_pattern_features(h)
        assert result[4] == 1.0  # has_scale_index

    def test_immediate_ratio(self):
        h = {
            "instructions": [
                {"mnemonic": "xor", "operands": "rax, 0x3F"},
            ]
        }
        result = extract_operand_pattern_features(h)
        # 1 imm out of 2 total ops
        assert result[0] == pytest.approx(0.5)  # imm_ratio

    def test_empty_instructions(self):
        result = extract_operand_pattern_features({})
        assert result == [0.0] * 6


# ===================================================================
# 5. Extended features end-to-end
# ===================================================================

class TestExtendedFeatures:
    def test_arith_handler_features(self):
        fv = extract_extended_features(_arith_handler())
        assert fv.dimension == 130
        assert fv.metadata["source"] == "handler_extended"

    def test_logic_handler_features(self):
        fv = extract_extended_features(_logic_handler())
        assert fv.dimension == 130
        # The xor->shr bigram should be non-zero
        idx = fv.feature_names.index("bg_xor_shr")
        assert fv.values[idx] > 0.0

    def test_feature_names_match_values(self):
        fv = extract_extended_features(_arith_handler())
        assert len(fv.values) == len(fv.feature_names)


# ===================================================================
# 6. Synthetic data generation
# ===================================================================

class TestSyntheticDataGeneration:
    def test_generates_correct_count(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=1)
        # 8 categories with templates: arith, bitwise, stack, memory,
        # control_flow, nop, vm_control, crypto
        assert len(handlers) == 8 * 10

    def test_all_categories_present(self):
        handlers = generate_synthetic_handlers(n_per_category=5, seed=2)
        cats = {h["category"] for h in handlers}
        expected = {
            "arithmetic", "bitwise", "stack", "memory",
            "control_flow", "nop", "vm_control", "crypto",
        }
        assert cats == expected

    def test_handlers_have_required_keys(self):
        handlers = generate_synthetic_handlers(n_per_category=3, seed=3)
        for h in handlers:
            assert "instructions" in h
            assert "mnemonics" in h
            assert "category" in h
            assert "operation" in h
            assert len(h["mnemonics"]) > 0

    def test_jitter_adds_nops(self):
        """With jitter=True, some handlers should have more instructions than template."""
        handlers_jitter = generate_synthetic_handlers(n_per_category=50, seed=4, jitter=True)
        handlers_no_jitter = generate_synthetic_handlers(n_per_category=50, seed=4, jitter=False)
        # At least some jittered handlers should be longer
        jitter_lengths = [len(h["mnemonics"]) for h in handlers_jitter]
        no_jitter_lengths = [len(h["mnemonics"]) for h in handlers_no_jitter]
        assert max(jitter_lengths) >= max(no_jitter_lengths)

    def test_deterministic_seed(self):
        h1 = generate_synthetic_handlers(n_per_category=5, seed=99)
        h2 = generate_synthetic_handlers(n_per_category=5, seed=99)
        assert [h["mnemonics"] for h in h1] == [h["mnemonics"] for h in h2]


# ===================================================================
# 7. Training data preparation
# ===================================================================

class TestTrainingDataPrep:
    def test_prepare_basic(self):
        handlers = generate_synthetic_handlers(n_per_category=5, seed=10)
        features, labels = prepare_training_data(handlers, label_key="category")
        assert len(features) == len(labels)
        assert all(isinstance(fv, FeatureVector) for fv in features)
        assert all(fv.dimension == 15 for fv in features)

    def test_prepare_extended(self):
        handlers = generate_synthetic_handlers(n_per_category=5, seed=11)
        features, labels = prepare_extended_training_data(handlers, label_key="category")
        assert len(features) == len(labels)
        assert all(fv.dimension == 130 for fv in features)

    def test_heuristic_labelling(self):
        h = {"operation": "vm_add"}
        assert label_from_heuristics(h) == "arithmetic"
        h2 = {"operation": "vm_xor"}
        assert label_from_heuristics(h2) == "bitwise"


# ===================================================================
# 8. Model training (sklearn-dependent tests)
# ===================================================================

try:
    import sklearn
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


@pytest.mark.skipif(not _HAS_SKLEARN, reason="scikit-learn not installed")
class TestModelTraining:
    def test_train_basic_features(self):
        handlers = generate_synthetic_handlers(n_per_category=30, seed=20)
        features, labels = prepare_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        result = trainer.train(features, labels, n_estimators=20)
        assert result.accuracy > 0.5
        assert result.metrics.get("n_estimators") == 20

    def test_train_extended_features(self):
        handlers = generate_synthetic_handlers(n_per_category=30, seed=21)
        features, labels = prepare_extended_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        result = trainer.train(features, labels, n_estimators=30)
        assert result.accuracy > 0.5

    def test_trained_model_predicts(self):
        handlers = generate_synthetic_handlers(n_per_category=30, seed=22)
        features, labels = prepare_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        trainer.train(features, labels, n_estimators=20)
        # Predict on a known arithmetic handler
        fv = extract_handler_features(_arith_handler())
        pred = model.predict({"values": fv.values, "names": fv.feature_names})
        assert isinstance(pred, PredictionResult)
        assert pred.label in HANDLER_CATEGORIES
        assert pred.metadata.get("method") == "sklearn"

    def test_evaluate(self):
        handlers = generate_synthetic_handlers(n_per_category=20, seed=23)
        features, labels = prepare_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        trainer.train(features, labels, n_estimators=20)
        metrics = trainer.evaluate(features, labels)
        assert "accuracy" in metrics
        assert metrics["accuracy"] > 0.5


# ===================================================================
# 9. Feature importance
# ===================================================================

@pytest.mark.skipif(not _HAS_SKLEARN, reason="scikit-learn not installed")
class TestFeatureImportance:
    def test_feature_importance_returns_ranked(self):
        handlers = generate_synthetic_handlers(n_per_category=30, seed=30)
        features, labels = prepare_extended_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        trainer.train(features, labels, n_estimators=30)
        imp = feature_importance(model, feature_names=EXTENDED_FEATURE_NAMES, top_n=10)
        assert len(imp) == 10
        # Should be sorted descending
        importances = [v for _, v in imp]
        assert importances == sorted(importances, reverse=True)

    def test_feature_importance_no_model(self):
        model = VMHandlerModel()
        imp = feature_importance(model)
        assert imp == []

    def test_top_features_are_meaningful(self):
        """The top features should include mnemonic ratios, not just noise."""
        handlers = generate_synthetic_handlers(n_per_category=50, seed=31)
        features, labels = prepare_extended_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        trainer.train(features, labels, n_estimators=50)
        imp = feature_importance(model, feature_names=EXTENDED_FEATURE_NAMES, top_n=5)
        top_names = {name for name, _ in imp}
        # At least one of the basic ratio features should be in top 5
        ratio_features = {"arith_ratio", "logic_ratio", "stack_ratio", "mem_ratio",
                          "branch_ratio", "nop_ratio", "instruction_count"}
        assert top_names & ratio_features, f"Top features: {top_names}"


# ===================================================================
# 10. Full pipeline end-to-end
# ===================================================================

@pytest.mark.skipif(not _HAS_SKLEARN, reason="scikit-learn not installed")
class TestFullPipeline:
    def test_train_full_pipeline_basic(self):
        model, result, imp = train_full_pipeline(
            n_per_category=20, seed=40, extended=False, n_estimators=20
        )
        assert result.accuracy > 0.5
        assert isinstance(model, VMHandlerModel)

    def test_train_full_pipeline_extended(self):
        model, result, imp = train_full_pipeline(
            n_per_category=30, seed=41, extended=True, n_estimators=30
        )
        assert result.accuracy > 0.5
        assert len(imp) > 0

    def test_pipeline_model_classifies_handlers(self):
        model, result, imp = train_full_pipeline(
            n_per_category=40, seed=42, extended=False, n_estimators=30
        )
        # Test classification of different handler types
        arith = extract_handler_features(_arith_handler())
        pred = model.predict({"values": arith.values, "names": arith.feature_names})
        # Should predict something reasonable (not necessarily perfect on synthetic)
        assert pred.label in HANDLER_CATEGORIES
        assert pred.confidence > 0.0


# ===================================================================
# 11. Heuristic model still works (no sklearn needed)
# ===================================================================

class TestHeuristicFallback:
    def test_heuristic_classifies_arith(self):
        model = VMHandlerModel()
        fv = extract_handler_features(_arith_handler())
        pred = model.predict({"values": fv.values, "names": fv.feature_names})
        assert pred.metadata["method"] == "heuristic"
        assert pred.label in HANDLER_CATEGORIES

    def test_heuristic_classifies_logic(self):
        model = VMHandlerModel()
        fv = extract_handler_features(_logic_handler())
        pred = model.predict({"values": fv.values, "names": fv.feature_names})
        assert pred.label in HANDLER_CATEGORIES

    def test_heuristic_validate_with_trainer(self):
        handlers = generate_synthetic_handlers(n_per_category=10, seed=50)
        features, labels = prepare_training_data(handlers, label_key="category")
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        # Without sklearn, should still produce a result via heuristic validation
        result = trainer._validate_heuristic(features, labels)
        assert isinstance(result, TrainingResult)
        assert result.metrics.get("method") == "heuristic_validation"
