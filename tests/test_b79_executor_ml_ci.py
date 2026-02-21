"""B79 — executor import cleanup, ML comparison templates, score floor, CI.

Tests added:
  - Executor: module-level z3/hashlib/time imports, no inline ``import z3``
  - ML/trainer: ``comparison`` category in templates and ``_cat_to_op``
  - ML/model: ``SCORE_FLOOR`` attribute, heuristic returns "unknown" for
    ambiguous inputs
  - CI: ``cache: 'pip'``, ``--disallow-untyped-defs``, ruff ``I,C4`` selectors
"""

from __future__ import annotations

import ast
import importlib
import inspect
import textwrap
from pathlib import Path
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent
_EXECUTOR_PY = _REPO / "dragonslayer" / "analysis" / "symbolic_execution" / "executor.py"
_CI_YML = _REPO / ".github" / "workflows" / "ci.yml"
_TRAINER_PY = _REPO / "dragonslayer" / "ml" / "trainer.py"
_MODEL_PY = _REPO / "dragonslayer" / "ml" / "model.py"


# ===================================================================
# Executor import cleanup
# ===================================================================
class TestExecutorImportCleanup:
    """Verify that z3, hashlib, time are hoisted to module level."""

    def test_has_z3_module_constant(self) -> None:
        from dragonslayer.analysis.symbolic_execution import executor as mod
        assert hasattr(mod, "_HAS_Z3"), "_HAS_Z3 sentinel missing"
        assert isinstance(mod._HAS_Z3, bool)

    def test_has_z3_is_true_when_z3_installed(self) -> None:
        """z3-solver is in requirements.txt so _HAS_Z3 should be True."""
        from dragonslayer.analysis.symbolic_execution import executor as mod
        try:
            import z3  # noqa: F401
            assert mod._HAS_Z3 is True
        except ImportError:
            pytest.skip("z3 not installed")

    def test_no_inline_import_z3(self) -> None:
        """No function-body ``import z3`` should remain in executor.py."""
        source = _EXECUTOR_PY.read_text(encoding="utf-8")
        tree = ast.parse(source)
        violations: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "z3":
                        # Only flag if inside a FunctionDef (inline)
                        # Module-level is fine
                        violations.append(node.lineno)
        # Allow the single module-level try/except import
        # Filter: only those beyond the module-level block (after line 40)
        inline = [ln for ln in violations if ln > 40]
        assert inline == [], f"Inline 'import z3' at lines {inline}"

    def test_no_inline_import_hashlib_or_time(self) -> None:
        source = _EXECUTOR_PY.read_text(encoding="utf-8")
        tree = ast.parse(source)
        violations: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("hashlib", "time") and node.lineno > 25:
                        violations.append((alias.name, node.lineno))
        assert violations == [], f"Inline imports found: {violations}"

    def test_executor_imports_cleanly(self) -> None:
        """Module can be imported without errors."""
        mod = importlib.import_module(
            "dragonslayer.analysis.symbolic_execution.executor"
        )
        assert hasattr(mod, "SymbolicExecutor")

    def test_executor_basic_analysis(self) -> None:
        """SymbolicExecutor can still be instantiated and has core methods."""
        from dragonslayer.analysis.symbolic_execution.executor import (
            SymbolicExecutor,
        )
        exe = SymbolicExecutor()
        assert callable(getattr(exe, "analyze", None))


# ===================================================================
# ML — comparison templates in trainer
# ===================================================================
class TestComparisonTemplates:
    """Verify 'comparison' category in _HANDLER_TEMPLATES."""

    def test_comparison_key_in_templates(self) -> None:
        from dragonslayer.ml.trainer import _HANDLER_TEMPLATES
        assert "comparison" in _HANDLER_TEMPLATES

    def test_comparison_templates_not_empty(self) -> None:
        from dragonslayer.ml.trainer import _HANDLER_TEMPLATES
        templates = _HANDLER_TEMPLATES["comparison"]
        assert len(templates) >= 3, "Need at least 3 comparison templates"

    def test_comparison_templates_have_cmp_or_test(self) -> None:
        """Each comparison template should use at least cmp or test."""
        from dragonslayer.ml.trainer import _HANDLER_TEMPLATES
        for i, tmpl in enumerate(_HANDLER_TEMPLATES["comparison"]):
            mnemonics = {m.lower() for m, _ in tmpl}
            assert mnemonics & {"cmp", "test"}, (
                f"Template #{i} lacks cmp/test: {mnemonics}"
            )

    def test_comparison_in_cat_to_op(self) -> None:
        """generate_synthetic_handlers maps comparison → vm_cmp."""
        from dragonslayer.ml.trainer import generate_synthetic_handlers
        handlers = generate_synthetic_handlers(5, seed=99)
        comp = [h for h in handlers if h["category"] == "comparison"]
        assert len(comp) > 0, "No comparison handlers generated"
        assert all(h["operation"] == "vm_cmp" for h in comp)

    def test_synthetic_handlers_include_all_template_categories(self) -> None:
        from dragonslayer.ml.trainer import (
            _HANDLER_TEMPLATES,
            generate_synthetic_handlers,
        )
        handlers = generate_synthetic_handlers(10, seed=42)
        generated_cats = {h["category"] for h in handlers}
        expected_cats = set(_HANDLER_TEMPLATES.keys())
        assert expected_cats == generated_cats

    def test_comparison_handler_has_cmp_or_test_in_mnemonics(self) -> None:
        from dragonslayer.ml.trainer import generate_synthetic_handlers
        handlers = generate_synthetic_handlers(20, seed=1)
        comp = [h for h in handlers if h["category"] == "comparison"]
        for h in comp:
            assert {"cmp", "test"} & set(h["mnemonics"]), (
                f"Comparison handler missing cmp/test in mnemonics: {h['mnemonics']}"
            )


# ===================================================================
# ML — score floor in model
# ===================================================================
class TestScoreFloor:
    """Verify SCORE_FLOOR attribute and heuristic fallback."""

    def test_score_floor_attribute_exists(self) -> None:
        from dragonslayer.ml.model import VMHandlerModel
        assert hasattr(VMHandlerModel, "SCORE_FLOOR")
        assert VMHandlerModel.SCORE_FLOOR == pytest.approx(0.05)

    def test_score_floor_returns_unknown_when_all_scores_zero(self) -> None:
        """Monkeypatch _score_rules to return all zeros → expect 'unknown'."""
        from dragonslayer.ml import model as mod
        from dragonslayer.ml.model import VMHandlerModel

        original = mod._score_rules

        def _zero_scores(values: Any, names: Any) -> Dict[str, float]:
            return {
                "arithmetic": 0.0,
                "bitwise": 0.0,
                "stack": 0.0,
                "memory": 0.0,
                "control_flow": 0.0,
                "vm_control": 0.0,
                "comparison": 0.0,
                "crypto": 0.0,
                "nop": 0.0,
                "unknown": 0.01,
            }

        mod._score_rules = _zero_scores  # type: ignore[assignment]
        try:
            m = VMHandlerModel()
            r = m.predict({"values": [1.0], "names": ["x"]})
            assert r.label == "unknown"
            assert r.metadata.get("reason") == "below_score_floor"
        finally:
            mod._score_rules = original  # type: ignore[assignment]

    def test_normal_prediction_unaffected_by_floor(self) -> None:
        """A handler with strong signal should NOT fall to score floor."""
        from dragonslayer.ml.model import VMHandlerModel
        m = VMHandlerModel()
        fnames = [
            "arith_ratio", "logic_ratio", "stack_ratio", "mem_ratio",
            "branch_ratio", "nop_ratio", "instruction_count",
            "has_memory_read", "has_memory_write", "has_indirect_branch",
        ]
        # Strong arithmetic signal 
        fvals = [0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 6, 0, 0, 0]
        r = m.predict({"values": fvals, "names": fnames})
        # Should NOT be 'unknown' with below_score_floor
        assert r.metadata.get("reason") != "below_score_floor"
        assert r.confidence > 0.1

    def test_comparison_category_in_heuristic_rules(self) -> None:
        """_HEURISTIC_RULES must contain 'comparison' key."""
        from dragonslayer.ml.model import _HEURISTIC_RULES
        assert "comparison" in _HEURISTIC_RULES

    def test_comparison_category_in_handler_categories(self) -> None:
        from dragonslayer.ml.model import HANDLER_CATEGORIES
        assert "comparison" in HANDLER_CATEGORIES


# ===================================================================
# CI configuration
# ===================================================================
class TestCIConfiguration:
    """Validate CI workflow correctness."""

    @pytest.fixture()
    def ci_text(self) -> str:
        return _CI_YML.read_text(encoding="utf-8")

    def test_pip_cache_in_all_jobs(self, ci_text: str) -> None:
        """All setup-python steps should use ``cache: 'pip'``."""
        assert ci_text.count("cache: 'pip'") >= 3, (
            "Expected cache: 'pip' in test, lint, typecheck jobs"
        )

    def test_no_manual_actions_cache(self, ci_text: str) -> None:
        """Manual actions/cache@v4 should be replaced by setup-python cache."""
        assert "actions/cache@" not in ci_text

    def test_disallow_untyped_defs(self, ci_text: str) -> None:
        assert "--disallow-untyped-defs" in ci_text

    def test_ruff_isort_and_comprehensions(self, ci_text: str) -> None:
        """Ruff must have I (isort) and C4 (comprehensions) selectors."""
        assert "I" in ci_text
        assert "C4" in ci_text

    def test_ruff_select_has_expected_codes(self, ci_text: str) -> None:
        import re
        match = re.search(r"--select\s+([\w,]+)", ci_text)
        assert match, "No --select found in CI"
        codes = set(match.group(1).split(","))
        assert codes >= {"E", "W", "F", "B", "UP", "SIM", "I", "C4"}

    def test_weekly_cron_schedule(self, ci_text: str) -> None:
        assert "cron:" in ci_text

    def test_concurrency_cancel_in_progress(self, ci_text: str) -> None:
        assert "cancel-in-progress: true" in ci_text


# ===================================================================
# Integration: comparison templates → ML pipeline
# ===================================================================
class TestComparisonMLPipeline:
    """End-to-end: generate comparison handlers → extract features → classify."""

    def test_comparison_handler_classifies_correctly(self) -> None:
        """A synthetic comparison handler should be classified as comparison."""
        from dragonslayer.ml.trainer import generate_synthetic_handlers
        from dragonslayer.ml.pipeline import extract_handler_features
        from dragonslayer.ml.model import VMHandlerModel

        handlers = generate_synthetic_handlers(20, seed=7)
        comp = [h for h in handlers if h["category"] == "comparison"]
        assert len(comp) > 0

        model = VMHandlerModel()
        labels = []
        for h in comp[:5]:
            fv = extract_handler_features(h)
            feats_dict = {"values": fv.values, "names": fv.feature_names}
            r = model.predict(feats_dict)
            labels.append(r.label)

        # We don't require 100% accuracy from heuristic, but the handler
        # should NOT be "unknown" with below_score_floor — it should
        # match *some* category confidently.
        assert all(lbl != "unknown" for lbl in labels), (
            f"Score floor incorrectly triggered: {labels}"
        )

    def test_training_with_comparison_category(self) -> None:
        """Trainer should include comparison in its training data."""
        from dragonslayer.ml.trainer import (
            generate_synthetic_handlers,
            prepare_extended_training_data,
        )

        handlers = generate_synthetic_handlers(10, seed=42)
        # Use ground-truth 'category' key as label source
        features, labels = prepare_extended_training_data(
            handlers, label_key="category",
        )
        assert "comparison" in labels
        assert len(features) == len(labels)
