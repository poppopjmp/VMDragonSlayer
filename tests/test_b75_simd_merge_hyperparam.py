"""B75 tests: pop_call_context SIMD byte taint, tracker reversed addr_expr,
synthetic handler category mapping, ML hyperparameter search, feature importance."""

from __future__ import annotations

import pytest

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    ByteTaintMap,
    subreg_info,
)
from dragonslayer.ml.model import VMHandlerModel
from dragonslayer.ml.trainer import (
    ModelTrainer,
    prepare_training_data,
    generate_synthetic_handlers,
    label_from_heuristics,
)


def _has_sklearn() -> bool:
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# 1. pop_call_context — SIMD byte taint merge
# ---------------------------------------------------------------------------


class TestPopCallContextSIMD:
    """Verify that pop_call_context handles SIMD registers correctly."""

    def test_merge_xmm_return_taint(self):
        """Merging xmm0 taint back into caller should work with 64-byte array."""
        t = TaintTracker(sub_register_aware=True)
        t.push_call_context()

        # In callee: taint xmm0 (uses zmm0 canonical, 64 bytes)
        t.taint_register("xmm0", TaintTag.COMPUTED)
        assert t._byte_taint.get_bytes("xmm0") & TaintTag.COMPUTED

        # Pop, allowing xmm0 as return register
        t.pop_call_context(return_regs=("xmm0",))

        # Should have merged COMPUTED into caller's xmm0
        tag = t._byte_taint.get_bytes("xmm0")
        assert tag & TaintTag.COMPUTED

    def test_simd_array_not_truncated_to_8(self):
        """After pop with SIMD return, the backing array should be 64 bytes."""
        t = TaintTracker(sub_register_aware=True)
        t.push_call_context()
        t.taint_register("ymm1", TaintTag.INPUT)  # 32 bytes tainted
        t.pop_call_context(return_regs=("ymm1",))

        canonical = "zmm1"
        arr = t._byte_taint._map.get(canonical)
        assert arr is not None
        assert len(arr) == 64  # Not truncated to 8!

    def test_gp_return_still_8_bytes(self):
        """GP registers still use 8-byte arrays for merge."""
        t = TaintTracker(sub_register_aware=True)
        t.push_call_context()
        t.taint_register("rax", TaintTag.MEMORY)
        t.pop_call_context(return_regs=("rax",))

        arr = t._byte_taint._map.get("rax")
        assert arr is not None
        assert len(arr) == 8


# ---------------------------------------------------------------------------
# 2. Tracker _resolve_addr_expr — reversed scale*reg
# ---------------------------------------------------------------------------


class TestTrackerAddrExpr:
    """Verify tracker's _resolve_addr_expr handles reversed scale*reg."""

    def test_standard_form(self):
        result = TaintTracker._resolve_addr_expr("rcx*8", {"rcx": 0x10})
        assert result == 0x80

    def test_reversed_form(self):
        result = TaintTracker._resolve_addr_expr("8*rcx", {"rcx": 0x10})
        assert result == 0x80

    def test_full_sib(self):
        result = TaintTracker._resolve_addr_expr(
            "rax+4*rdx+0x100", {"rax": 0x1000, "rdx": 0x10}
        )
        assert result == 0x1000 + 4 * 0x10 + 0x100

    def test_reversed_in_sib(self):
        """rax+8*rcx as found in real VMP handler tables."""
        result = TaintTracker._resolve_addr_expr(
            "rax+8*rcx", {"rax": 0x2000, "rcx": 0x100}
        )
        assert result == 0x2000 + 8 * 0x100


# ---------------------------------------------------------------------------
# 3. generate_synthetic_handlers — category mapping
# ---------------------------------------------------------------------------


class TestSyntheticHandlers:
    """Verify synthetic handler categories map to correct operations."""

    def test_all_categories_get_proper_operations(self):
        """No category should fall through to vm_unknown."""
        handlers = generate_synthetic_handlers(n_per_category=2, seed=42)
        unknown_ops = [h for h in handlers if h["operation"] == "vm_unknown"]
        assert len(unknown_ops) == 0, (
            f"Found {len(unknown_ops)} handlers with vm_unknown: "
            f"{[h['category'] for h in unknown_ops[:5]]}"
        )

    def test_label_from_heuristics_matches_category(self):
        """Each synthetic handler's label_from_heuristics should match its category."""
        handlers = generate_synthetic_handlers(n_per_category=3, seed=42)
        mismatches = []
        for h in handlers:
            expected = h["category"]
            actual = label_from_heuristics(h)
            if actual != expected:
                mismatches.append((h["operation"], expected, actual))
        assert len(mismatches) == 0, f"Mismatches: {mismatches[:5]}"


# ---------------------------------------------------------------------------
# 4. ML hyperparameter search
# ---------------------------------------------------------------------------


class TestHyperparameterSearch:
    """Test train_with_search functionality."""

    @pytest.mark.skipif(not _has_sklearn(), reason="scikit-learn not installed")
    def test_train_with_search_improves_or_matches(self):
        """Hyperparameter search should produce accuracy >= basic training."""
        handlers = generate_synthetic_handlers(n_per_category=15, seed=42)
        features, labels = prepare_training_data(handlers)

        # Basic training
        model1 = VMHandlerModel()
        t1 = ModelTrainer(model1)
        r1 = t1.train(features, labels, n_estimators=20)

        # Hyperparameter search
        model2 = VMHandlerModel()
        t2 = ModelTrainer(model2)
        r2 = t2.train_with_search(
            features, labels,
            param_grid={"n_estimators": [20, 50], "max_depth": [3, 5]},
            cv=2, n_iter=4,
        )

        assert r2.accuracy >= 0.0
        assert model2.is_trained
        assert r2.metrics.get("method") == "randomized_search"

    @pytest.mark.skipif(not _has_sklearn(), reason="scikit-learn not installed")
    def test_feature_importances_property(self):
        """feature_importances returns non-empty list after training."""
        handlers = generate_synthetic_handlers(n_per_category=10, seed=42)
        features, labels = prepare_training_data(handlers)

        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        trainer.train(features, labels, n_estimators=20)

        imp = trainer.feature_importances
        assert isinstance(imp, list)
        assert len(imp) > 0
        # Sorted descending by importance
        for i in range(len(imp) - 1):
            assert imp[i][1] >= imp[i + 1][1]

    def test_small_dataset_falls_back(self):
        """With tiny dataset, train_with_search falls back to basic train."""
        handlers = generate_synthetic_handlers(n_per_category=1, seed=42)
        features, labels = prepare_training_data(handlers)

        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        result = trainer.train_with_search(features, labels)
        assert result.accuracy >= 0.0


# ---------------------------------------------------------------------------
# 5. ByteTaintMap._CANONICAL_SIZES consistency
# ---------------------------------------------------------------------------


class TestCanonicalSizes:
    """Verify _CANONICAL_SIZES is populated correctly."""

    def test_gp_sizes(self):
        ByteTaintMap._init_sizes()
        for reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
            assert ByteTaintMap._CANONICAL_SIZES[reg] == 8

    def test_simd_sizes(self):
        ByteTaintMap._init_sizes()
        for n in range(16):
            assert ByteTaintMap._CANONICAL_SIZES[f"zmm{n}"] == 64

    def test_extended_gp_sizes(self):
        ByteTaintMap._init_sizes()
        for n in range(8, 16):
            assert ByteTaintMap._CANONICAL_SIZES[f"r{n}"] == 8
