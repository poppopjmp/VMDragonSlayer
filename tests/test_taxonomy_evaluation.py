"""Tests for B42: Canonical taxonomy, ground-truth evaluation, and label alignment.

Validates:
- taxonomy.py: canoncalize(), CANONICAL_CATEGORIES, CANONICAL_SET, is_canonical
- evaluate.py: load_ground_truth, evaluate_model, EvaluationReport, ClassMetrics
- Label alignment: all models produce canonical labels
- Ground-truth JSON: loads, has ≥50 entries, all labels canonical
- SymbolicClassifierModel F1 ≥ 0.80 on ground truth
"""

import json
import pytest
from pathlib import Path

from dragonslayer.ml.taxonomy import (
    CANONICAL_CATEGORIES,
    CANONICAL_SET,
    canonicalize,
    is_canonical,
)
from dragonslayer.ml.evaluate import (
    ClassMetrics,
    EvaluationReport,
    GroundTruthEntry,
    evaluate_model,
    load_ground_truth,
)
from dragonslayer.ml.model import (
    HANDLER_CATEGORIES,
    PredictionResult,
    SymbolicClassifierModel,
    VMHandlerModel,
)
from dragonslayer.ml.ensemble import WeightedEnsemble
from dragonslayer.ml.handler_classifier import (
    HANDLER_CATEGORIES as HC_CATEGORIES,
)


# ═══════════════════════════════════════════════════════════════════════════
# Taxonomy tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCanonicalTaxonomy:
    """taxonomy.py exports correct canonical category set."""

    def test_at_least_10_categories(self):
        assert len(CANONICAL_CATEGORIES) >= 10

    def test_set_matches_list(self):
        assert CANONICAL_SET == frozenset(CANONICAL_CATEGORIES)

    def test_essential_categories_present(self):
        for cat in ("arithmetic", "bitwise", "memory", "stack",
                     "control_flow", "comparison", "crypto",
                     "vm_control", "nop", "unknown"):
            assert cat in CANONICAL_SET

    def test_canonicalize_identity(self):
        for cat in CANONICAL_CATEGORIES:
            assert canonicalize(cat) == cat

    def test_canonicalize_legacy_logic(self):
        assert canonicalize("logic") == "bitwise"

    def test_canonicalize_legacy_load_store(self):
        assert canonicalize("load_store") == "memory"

    def test_canonicalize_legacy_branch(self):
        assert canonicalize("branch") == "control_flow"

    def test_canonicalize_legacy_vm_entry_exit(self):
        assert canonicalize("vm_entry_exit") == "vm_control"

    def test_canonicalize_legacy_context(self):
        assert canonicalize("context") == "vm_control"

    def test_canonicalize_legacy_compare(self):
        assert canonicalize("compare") == "comparison"

    def test_canonicalize_legacy_call(self):
        assert canonicalize("call") == "control_flow"

    def test_canonicalize_unknown_input(self):
        assert canonicalize("totally_made_up") == "unknown"

    def test_canonicalize_case_insensitive(self):
        assert canonicalize("ARITHMETIC") == "arithmetic"
        assert canonicalize("Logic") == "bitwise"

    def test_is_canonical_true(self):
        assert is_canonical("arithmetic")
        assert is_canonical("bitwise")

    def test_is_canonical_false(self):
        assert not is_canonical("logic")
        assert not is_canonical("load_store")


# ═══════════════════════════════════════════════════════════════════════════
# Label alignment: all model category lists now use canonical labels
# ═══════════════════════════════════════════════════════════════════════════

class TestLabelAlignment:
    """All model-level HANDLER_CATEGORIES use canonical labels."""

    def test_model_categories_are_canonical(self):
        for cat in HANDLER_CATEGORIES:
            assert is_canonical(cat), f"model.py HANDLER_CATEGORIES has non-canonical '{cat}'"

    def test_handler_classifier_categories_are_canonical(self):
        for cat in HC_CATEGORIES:
            assert is_canonical(cat), f"handler_classifier.py has non-canonical '{cat}'"

    def test_vmhandler_heuristic_produces_canonical(self):
        model = VMHandlerModel()
        names = ["arith_ratio", "logic_ratio", "stack_ratio",
                 "mem_ratio", "branch_ratio", "nop_ratio",
                 "instruction_count", "has_memory_read",
                 "has_memory_write", "has_indirect_branch"]
        # High arith_ratio → should predict "arithmetic"
        result = model.predict({"values": [0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 5, 0, 0, 0],
                                "names": names})
        assert is_canonical(result.label)

    def test_symbolic_produces_canonical(self):
        model = SymbolicClassifierModel()
        summary = {
            "simplified_registers": {"rax": "init_rax + init_rbx"},
            "memory_writes": [],
            "input_symbols": {"rax": "init_rax", "rbx": "init_rbx"},
        }
        result = model.predict({"symbolic_summary": summary})
        assert is_canonical(result.label)

    def test_ensemble_produces_canonical(self):
        ens = WeightedEnsemble(
            models=[VMHandlerModel(), SymbolicClassifierModel()],
            weights=[0.4, 0.6],
        )
        result = ens.predict({
            "values": [0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 5, 0, 0, 0, 0, 0, 0],
            "names": ["arith_ratio", "logic_ratio", "stack_ratio",
                      "mem_ratio", "branch_ratio", "nop_ratio",
                      "instruction_count", "has_memory_read",
                      "has_memory_write", "has_indirect_branch",
                      "x1", "x2", "x3"],
            "symbolic_summary": {
                "simplified_registers": {"rax": "init_rax + init_rbx"},
                "memory_writes": [],
                "input_symbols": {"rax": "init_rax", "rbx": "init_rbx"},
            },
        })
        assert is_canonical(result.label)


# ═══════════════════════════════════════════════════════════════════════════
# Ground truth loading
# ═══════════════════════════════════════════════════════════════════════════

class TestGroundTruth:
    """handler_labels.json loads and has ≥50 valid entries."""

    def test_loads_default(self):
        gt = load_ground_truth()
        assert len(gt) >= 50

    def test_all_labels_canonical(self):
        gt = load_ground_truth()
        for entry in gt:
            assert is_canonical(entry.label), f"{entry.id} has non-canonical label '{entry.label}'"

    def test_entries_have_fields(self):
        gt = load_ground_truth()
        for entry in gt:
            assert entry.id
            assert entry.label

    def test_category_coverage(self):
        gt = load_ground_truth()
        labels = {e.label for e in gt}
        # Should have at least 8 distinct categories
        assert len(labels) >= 8

    def test_symbolic_summaries_present(self):
        gt = load_ground_truth()
        with_summary = [e for e in gt if e.symbolic_summary]
        assert len(with_summary) >= 50

    def test_to_features(self):
        gt = load_ground_truth()
        for entry in gt:
            feat = entry.to_features()
            assert isinstance(feat, dict)


# ═══════════════════════════════════════════════════════════════════════════
# ClassMetrics unit tests
# ═══════════════════════════════════════════════════════════════════════════

class TestClassMetrics:
    def test_precision_recall_f1(self):
        m = ClassMetrics(label="test", tp=8, fp=2, fn=1)
        assert abs(m.precision - 0.80) < 0.01
        assert abs(m.recall - 8/9) < 0.01
        assert m.f1 > 0.0

    def test_zero_division(self):
        m = ClassMetrics(label="test", tp=0, fp=0, fn=0)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0

    def test_perfect(self):
        m = ClassMetrics(label="test", tp=10, fp=0, fn=0)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0


# ═══════════════════════════════════════════════════════════════════════════
# EvaluationReport unit tests
# ═══════════════════════════════════════════════════════════════════════════

class TestEvaluationReport:
    def test_accuracy(self):
        r = EvaluationReport(total=10, correct=8)
        assert abs(r.accuracy - 0.8) < 0.01

    def test_to_dict(self):
        r = EvaluationReport(
            total=10, correct=8,
            per_class={"arithmetic": ClassMetrics("arithmetic", tp=5, fp=1, fn=0)},
        )
        d = r.to_dict()
        assert "accuracy" in d
        assert "per_class" in d
        assert "arithmetic" in d["per_class"]

    def test_summary_string(self):
        r = EvaluationReport(
            total=10, correct=8,
            per_class={"arithmetic": ClassMetrics("arithmetic", tp=5, fp=1, fn=0)},
        )
        s = r.summary()
        assert "Accuracy" in s
        assert "arithmetic" in s


# ═══════════════════════════════════════════════════════════════════════════
# Full model evaluation against ground truth
# ═══════════════════════════════════════════════════════════════════════════

class TestModelEvaluation:
    """Evaluate SymbolicClassifierModel against ground truth — F1 ≥ 0.80."""

    def test_symbolic_weighted_f1(self):
        model = SymbolicClassifierModel()
        gt = load_ground_truth()
        report = evaluate_model(model, gt)
        assert report.weighted_f1 >= 0.80, (
            f"SymbolicClassifierModel weighted-F1 = {report.weighted_f1:.4f} < 0.80\n"
            f"{report.summary()}"
        )

    def test_symbolic_accuracy(self):
        model = SymbolicClassifierModel()
        gt = load_ground_truth()
        report = evaluate_model(model, gt)
        assert report.accuracy >= 0.70, (
            f"Accuracy = {report.accuracy:.4f} < 0.70"
        )

    def test_ensemble_weighted_f1(self):
        """Ensemble should do at least as well as symbolic alone."""
        sym = SymbolicClassifierModel()
        ens = WeightedEnsemble(
            models=[VMHandlerModel(), SymbolicClassifierModel()],
            weights=[0.4, 0.6],
        )
        gt = load_ground_truth()
        sym_report = evaluate_model(sym, gt)
        ens_report = evaluate_model(ens, gt)
        # Ensemble shouldn't be significantly worse
        assert ens_report.weighted_f1 >= sym_report.weighted_f1 - 0.10

    def test_per_class_coverage(self):
        model = SymbolicClassifierModel()
        gt = load_ground_truth()
        report = evaluate_model(model, gt)
        # Should have metrics for most categories
        active = [k for k, v in report.per_class.items() if v.support > 0]
        assert len(active) >= 7

    def test_confusion_matrix_populated(self):
        model = SymbolicClassifierModel()
        gt = load_ground_truth()
        report = evaluate_model(model, gt)
        assert len(report.confusion) > 0

    def test_report_summary_format(self):
        model = SymbolicClassifierModel()
        gt = load_ground_truth()
        report = evaluate_model(model, gt)
        s = report.summary()
        assert "Accuracy" in s
        assert "Macro-F1" in s
        assert "Weighted-F1" in s


# ═══════════════════════════════════════════════════════════════════════════
# Import verification
# ═══════════════════════════════════════════════════════════════════════════

class TestImports:
    def test_taxonomy_from_ml_package(self):
        from dragonslayer.ml import canonicalize, CANONICAL_CATEGORIES, is_canonical
        assert callable(canonicalize)
        assert len(CANONICAL_CATEGORIES) >= 10
        assert callable(is_canonical)

    def test_evaluate_from_ml_package(self):
        from dragonslayer.ml import evaluate_model, load_ground_truth, EvaluationReport
        assert callable(evaluate_model)
        assert callable(load_ground_truth)
        assert EvaluationReport is not None
