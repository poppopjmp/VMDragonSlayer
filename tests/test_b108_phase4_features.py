"""
Phase 4 tests — Plugin dependencies, active learning, speculative executor,
plugin health endpoints.
"""

from __future__ import annotations

import json
import math
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# 1. Plugin Dependency Tracking
# ═══════════════════════════════════════════════════════════════════════════


class TestPluginDependencyAttributes:
    """Plugin ABC exposes depends_on, provides, and version."""

    def test_plugin_has_depends_on(self) -> None:
        from dragonslayer.plugins import Plugin
        assert hasattr(Plugin, "depends_on")
        assert isinstance(Plugin.depends_on, set)

    def test_plugin_has_provides(self) -> None:
        from dragonslayer.plugins import Plugin
        assert hasattr(Plugin, "provides")
        assert isinstance(Plugin.provides, set)

    def test_plugin_has_version(self) -> None:
        from dragonslayer.plugins import Plugin
        assert hasattr(Plugin, "version")
        assert isinstance(Plugin.version, str)

    def test_default_depends_on_empty(self) -> None:
        from dragonslayer.plugins import Plugin, Stage, PluginResult, PluginContext

        class Dummy(Plugin):
            name = "dummy_dep_test"
            stage = Stage.STATIC

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        d = Dummy()
        assert d.depends_on == set()
        assert d.provides == set()
        assert d.version == "0.0.0"


class TestValidatePluginDependencies:
    """validate_plugin_dependencies() checks declared deps."""

    def test_empty_registry_no_problems(self) -> None:
        from dragonslayer.plugins import validate_plugin_dependencies
        # With no plugins discovered, there can be no problems
        problems = validate_plugin_dependencies()
        assert isinstance(problems, dict)

    def test_missing_dep_reported(self) -> None:
        from dragonslayer.plugins import (
            Plugin, Stage, PluginResult, PluginContext,
            register_plugin, validate_plugin_dependencies,
            _REGISTRY,
        )
        # Save and restore registry
        saved = dict(_REGISTRY)
        try:
            _REGISTRY.clear()

            @register_plugin
            class A(Plugin):
                name = "a_test"
                stage = Stage.STATIC
                depends_on = {"nonexistent_plugin"}

                def execute(self, fp, fd, ctx):
                    return PluginResult(plugin=self.name, success=True)

            problems = validate_plugin_dependencies(stage=Stage.STATIC)
            assert "a_test" in problems
            assert "nonexistent_plugin" in problems["a_test"]
        finally:
            _REGISTRY.clear()
            _REGISTRY.update(saved)

    def test_satisfied_dep_no_problems(self) -> None:
        from dragonslayer.plugins import (
            Plugin, Stage, PluginResult,
            register_plugin, validate_plugin_dependencies,
            _REGISTRY,
        )
        saved = dict(_REGISTRY)
        try:
            _REGISTRY.clear()

            @register_plugin
            class B1(Plugin):
                name = "b1_test"
                stage = Stage.STATIC

                def execute(self, fp, fd, ctx):
                    return PluginResult(plugin=self.name, success=True)

            @register_plugin
            class B2(Plugin):
                name = "b2_test"
                stage = Stage.STATIC
                depends_on = {"b1_test"}

                def execute(self, fp, fd, ctx):
                    return PluginResult(plugin=self.name, success=True)

            problems = validate_plugin_dependencies(stage=Stage.STATIC)
            assert len(problems) == 0
        finally:
            _REGISTRY.clear()
            _REGISTRY.update(saved)


class TestSortPluginsByDeps:
    """Topological sort respects depends_on."""

    def test_no_deps_preserves_alpha_order(self) -> None:
        from dragonslayer.plugins import (
            Plugin, Stage, PluginResult, sort_plugins_by_deps,
        )

        class P1(Plugin):
            name = "alpha"
            stage = Stage.STATIC

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        class P2(Plugin):
            name = "beta"
            stage = Stage.STATIC

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        ordered = sort_plugins_by_deps([P2(), P1()])
        assert [p.name for p in ordered] == ["alpha", "beta"]

    def test_deps_enforced(self) -> None:
        from dragonslayer.plugins import (
            Plugin, Stage, PluginResult, sort_plugins_by_deps,
        )

        class P1(Plugin):
            name = "producer"
            stage = Stage.STATIC
            provides = {"result_A"}

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        class P2(Plugin):
            name = "consumer"
            stage = Stage.STATIC
            depends_on = {"producer"}

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        ordered = sort_plugins_by_deps([P2(), P1()])
        names = [p.name for p in ordered]
        assert names.index("producer") < names.index("consumer")

    def test_cycle_returns_original_order(self) -> None:
        from dragonslayer.plugins import (
            Plugin, Stage, PluginResult, sort_plugins_by_deps,
        )

        class A(Plugin):
            name = "cycle_a"
            stage = Stage.STATIC
            depends_on = {"cycle_b"}

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        class B(Plugin):
            name = "cycle_b"
            stage = Stage.STATIC
            depends_on = {"cycle_a"}

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        plugins = [A(), B()]
        ordered = sort_plugins_by_deps(plugins)
        # Cycle → returns original order
        assert [p.name for p in ordered] == ["cycle_a", "cycle_b"]

    def test_empty_list(self) -> None:
        from dragonslayer.plugins import sort_plugins_by_deps
        assert sort_plugins_by_deps([]) == []

    def test_single_plugin(self) -> None:
        from dragonslayer.plugins import Plugin, Stage, PluginResult, sort_plugins_by_deps

        class S(Plugin):
            name = "solo"
            stage = Stage.STATIC

            def execute(self, fp, fd, ctx):
                return PluginResult(plugin=self.name, success=True)

        result = sort_plugins_by_deps([S()])
        assert len(result) == 1


class TestPluginDependencyErrorException:
    """PluginDependencyError carries missing deps."""

    def test_basic_attributes(self) -> None:
        from dragonslayer.core.exceptions import PluginDependencyError
        err = PluginDependencyError(
            "missing deps",
            plugin_name="test_plugin",
            missing=["dep_a", "dep_b"],
        )
        assert err.plugin_name == "test_plugin"
        assert err.missing == ["dep_a", "dep_b"]
        assert "missing deps" in str(err)

    def test_default_missing_is_empty(self) -> None:
        from dragonslayer.core.exceptions import PluginDependencyError
        err = PluginDependencyError("x")
        assert err.missing == []


# ═══════════════════════════════════════════════════════════════════════════
# 2. Active Learning
# ═══════════════════════════════════════════════════════════════════════════


class TestComputeEntropy:
    def test_uniform_distribution(self) -> None:
        from dragonslayer.ml.active_learning import compute_entropy
        # Uniform over 4 classes → max entropy = ln(4)
        probs = [0.25, 0.25, 0.25, 0.25]
        ent = compute_entropy(probs)
        assert abs(ent - math.log(4)) < 1e-6

    def test_certain_distribution(self) -> None:
        from dragonslayer.ml.active_learning import compute_entropy
        # Certain → 0 entropy
        assert compute_entropy([1.0, 0.0, 0.0]) == 0.0

    def test_binary_distribution(self) -> None:
        from dragonslayer.ml.active_learning import compute_entropy
        ent = compute_entropy([0.5, 0.5])
        assert abs(ent - math.log(2)) < 1e-6


class TestComputeMargin:
    def test_clear_winner(self) -> None:
        from dragonslayer.ml.active_learning import compute_margin
        assert compute_margin([0.9, 0.1]) == pytest.approx(0.8)

    def test_tied(self) -> None:
        from dragonslayer.ml.active_learning import compute_margin
        assert compute_margin([0.5, 0.5]) == pytest.approx(0.0)

    def test_single_class(self) -> None:
        from dragonslayer.ml.active_learning import compute_margin
        assert compute_margin([1.0]) == 1.0


class TestSelectUncertainSamples:
    def _make_predictions(self) -> list:
        return [
            {"sample_id": "s1", "confidence": 0.3, "predicted_label": "add",
             "class_probabilities": {"add": 0.3, "sub": 0.3, "mov": 0.4}},
            {"sample_id": "s2", "confidence": 0.95, "predicted_label": "nop",
             "class_probabilities": {"nop": 0.95, "add": 0.05}},
            {"sample_id": "s3", "confidence": 0.5, "predicted_label": "xor",
             "class_probabilities": {"xor": 0.5, "and": 0.5}},
            {"sample_id": "s4", "confidence": 0.1, "predicted_label": "unknown",
             "class_probabilities": {"unknown": 0.1, "add": 0.3, "sub": 0.3, "mov": 0.3}},
        ]

    def test_entropy_strategy(self) -> None:
        from dragonslayer.ml.active_learning import select_uncertain_samples
        preds = self._make_predictions()
        result = select_uncertain_samples(preds, strategy="entropy", k=2)
        assert len(result) == 2
        # s2 is filtered out (confidence 0.95 >= 0.8)
        ids = {s.sample_id for s in result}
        assert "s2" not in ids

    def test_least_confidence_strategy(self) -> None:
        from dragonslayer.ml.active_learning import select_uncertain_samples
        preds = self._make_predictions()
        result = select_uncertain_samples(
            preds, strategy="least_confidence", k=1,
        )
        assert len(result) == 1
        assert result[0].sample_id == "s4"  # lowest confidence

    def test_margin_strategy(self) -> None:
        from dragonslayer.ml.active_learning import select_uncertain_samples
        preds = self._make_predictions()
        result = select_uncertain_samples(preds, strategy="margin", k=1)
        assert len(result) == 1
        # s3 has margin 0.0 (tied), so it's the most uncertain by margin
        assert result[0].sample_id == "s3"

    def test_confidence_threshold(self) -> None:
        from dragonslayer.ml.active_learning import select_uncertain_samples
        preds = self._make_predictions()
        result = select_uncertain_samples(
            preds, strategy="entropy", k=10, confidence_threshold=0.2,
        )
        # Only s4 has confidence < 0.2
        assert len(result) == 1
        assert result[0].sample_id == "s4"

    def test_empty_predictions(self) -> None:
        from dragonslayer.ml.active_learning import select_uncertain_samples
        assert select_uncertain_samples([]) == []


class TestFeedbackStore:
    def test_ingest_and_retrieve(self) -> None:
        from dragonslayer.ml.active_learning import FeedbackStore
        store = FeedbackStore()
        entry = store.ingest("s1", "add", analyst_id="alice")
        assert store.count() == 1
        assert entry.sample_id == "s1"
        assert entry.corrected_label == "add"
        assert entry.analyst_id == "alice"

    def test_get_corrections(self) -> None:
        from dragonslayer.ml.active_learning import FeedbackStore
        store = FeedbackStore()
        store.ingest("s1", "add")
        store.ingest("s2", "sub")
        store.ingest("s1", "mov")  # override s1
        corrections = store.get_corrections()
        assert corrections == {"s1": "mov", "s2": "sub"}

    def test_clear(self) -> None:
        from dragonslayer.ml.active_learning import FeedbackStore
        store = FeedbackStore()
        store.ingest("s1", "add")
        store.clear()
        assert store.count() == 0

    def test_persist_to_file(self, tmp_path: Path) -> None:
        from dragonslayer.ml.active_learning import FeedbackStore
        fp = tmp_path / "feedback.json"

        store = FeedbackStore(path=fp)
        store.ingest("s1", "add")
        store.ingest("s2", "sub")
        assert fp.exists()

        # Reload from disk
        store2 = FeedbackStore(path=fp)
        assert store2.count() == 2
        assert store2.get_corrections() == {"s1": "add", "s2": "sub"}

    def test_corrupt_file_handled(self, tmp_path: Path) -> None:
        from dragonslayer.ml.active_learning import FeedbackStore
        fp = tmp_path / "bad.json"
        fp.write_text("not json", encoding="utf-8")
        store = FeedbackStore(path=fp)
        assert store.count() == 0


class TestExportTrainingSet:
    def test_merge_overrides(self) -> None:
        from dragonslayer.ml.active_learning import FeedbackStore, export_training_set
        store = FeedbackStore()
        store.ingest("s1", "corrected_add")
        existing = {"s1": "add", "s2": "sub"}
        merged = export_training_set(store, existing)
        assert merged["s1"] == "corrected_add"
        assert merged["s2"] == "sub"


class TestUncertainSampleDataclass:
    def test_to_dict(self) -> None:
        from dragonslayer.ml.active_learning import UncertainSample
        s = UncertainSample(
            sample_id="x", predicted_label="add", confidence=0.5,
        )
        d = s.to_dict()
        assert d["sample_id"] == "x"
        assert d["confidence"] == 0.5


class TestFeedbackEntryDataclass:
    def test_to_dict(self) -> None:
        from dragonslayer.ml.active_learning import FeedbackEntry
        e = FeedbackEntry(sample_id="s1", corrected_label="sub")
        d = e.to_dict()
        assert d["sample_id"] == "s1"


# ═══════════════════════════════════════════════════════════════════════════
# 3. Speculative Executor
# ═══════════════════════════════════════════════════════════════════════════


class TestSpeculativeExecutor:
    """Speculative mode parameters accepted by SymbolicExecutor."""

    def test_speculative_defaults(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor()
        assert ex.speculative is False
        assert ex.max_speculative_forks == 8

    def test_speculative_enabled(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor(speculative=True, max_speculative_forks=4)
        assert ex.speculative is True
        assert ex.max_speculative_forks == 4

    def test_execution_result_has_speculative_count(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import ExecutionResult
        r = ExecutionResult(success=True)
        assert r.speculative_paths_explored == 0

    def test_to_dict_includes_speculative(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import ExecutionResult
        r = ExecutionResult(success=True, speculative_paths_explored=3)
        d = r.to_dict()
        assert d["speculative_paths_explored"] == 3

    def test_from_config_reads_speculative(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        mock_config = {
            "symbolic_execution.speculative": True,
            "symbolic_execution.max_speculative_forks": 16,
            "symbolic_execution.max_depth": 500,
            "symbolic_execution.max_paths": 32,
            "symbolic_execution.max_loop_iters": 2,
            "symbolic_execution.solver_timeout_ms": 5000,
            "symbolic_execution.memory_limit_mb": 0,
        }
        ex = SymbolicExecutor.from_config(mock_config)
        assert ex.speculative is True
        assert ex.max_speculative_forks == 16

    def test_non_speculative_analyze(self) -> None:
        """Basic analysis without speculative mode still works."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor(speculative=False)
        # NOP sled — trivial code
        code = bytes([0x90, 0x90, 0x90, 0xC3])
        result = ex.analyze(code, entry_point=0)
        assert result.success is True
        assert result.speculative_paths_explored == 0


# ═══════════════════════════════════════════════════════════════════════════
# 4. API Endpoint Tests (feedback, uncertain, plugins)
# ═══════════════════════════════════════════════════════════════════════════


def _make_mock_api() -> Any:
    """Build a lightweight mock VMDragonSlayerAPI."""
    api = MagicMock()
    api.analyze_binary_data_async = AsyncMock(return_value={
        "success": True, "handlers": [],
    })
    api.run_pipeline_async = AsyncMock(return_value={
        "success": True, "stages": {},
    })
    return api


@pytest.fixture()
def _phase4_client():
    """HTTPX test client for Phase 4 endpoint testing."""
    try:
        import httpx
        from dragonslayer.api.server import app, server_state
    except ImportError:
        pytest.skip("httpx or fastapi not installed")

    server_state.api = _make_mock_api()
    server_state.ready = True

    from starlette.testclient import TestClient
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


class TestRootEndpointPhase4:
    """Root endpoint lists new Phase 4 routes."""

    def test_feedback_in_endpoints(self, _phase4_client) -> None:
        resp = _phase4_client.get("/")
        assert resp.status_code == 200
        endpoints = resp.json()["endpoints"]
        assert "feedback" in endpoints
        assert "uncertain" in endpoints
        assert "plugins" in endpoints
        assert "plugins_health" in endpoints


class TestFeedbackEndpoint:
    def test_submit_feedback(self, _phase4_client) -> None:
        resp = _phase4_client.post("/feedback", json={
            "sample_id": "h_0x401000",
            "corrected_label": "add",
            "analyst_id": "alice",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["entry"]["sample_id"] == "h_0x401000"

    def test_feedback_missing_required_field(self, _phase4_client) -> None:
        resp = _phase4_client.post("/feedback", json={
            "analyst_id": "bob",
        })
        assert resp.status_code == 422


class TestUncertainEndpoint:
    def test_select_uncertain(self, _phase4_client) -> None:
        predictions = [
            {"sample_id": "s1", "confidence": 0.3, "predicted_label": "add"},
            {"sample_id": "s2", "confidence": 0.9, "predicted_label": "nop"},
        ]
        resp = _phase4_client.post("/uncertain", json={
            "predictions": predictions,
            "strategy": "entropy",
            "k": 5,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert data["samples"][0]["sample_id"] == "s1"

    def test_empty_predictions(self, _phase4_client) -> None:
        resp = _phase4_client.post("/uncertain", json={
            "predictions": [],
        })
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


class TestPluginsEndpoint:
    def test_list_plugins(self, _phase4_client) -> None:
        resp = _phase4_client.get("/plugins")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "plugins" in data

    def test_plugins_health(self, _phase4_client) -> None:
        resp = _phase4_client.get("/plugins/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "healthy" in data
        assert "problems" in data


# ═══════════════════════════════════════════════════════════════════════════
# 5. ML module exports
# ═══════════════════════════════════════════════════════════════════════════


class TestMLExportsActiveLearning:
    """Active learning classes are importable from dragonslayer.ml."""

    def test_uncertain_sample_importable(self) -> None:
        from dragonslayer.ml import UncertainSample
        assert UncertainSample is not None

    def test_uncertainty_strategy_importable(self) -> None:
        from dragonslayer.ml import UncertaintyStrategy
        assert UncertaintyStrategy is not None

    def test_feedback_store_importable(self) -> None:
        from dragonslayer.ml import FeedbackStore
        assert FeedbackStore is not None

    def test_select_uncertain_importable(self) -> None:
        from dragonslayer.ml import select_uncertain_samples
        assert select_uncertain_samples is not None

    def test_compute_entropy_importable(self) -> None:
        from dragonslayer.ml import compute_entropy
        assert compute_entropy is not None

    def test_export_training_set_importable(self) -> None:
        from dragonslayer.ml import export_training_set
        assert export_training_set is not None
