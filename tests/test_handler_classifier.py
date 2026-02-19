"""Tests for ML handler classification bridge."""

from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
from dragonslayer.ml.handler_classifier import (
    TrainedHandlerModel,
    classify_handlers,
    build_handler_classifier,
    HANDLER_CATEGORIES,
    SKLEARN_AVAILABLE,
)
from dragonslayer.ml.model import PredictionResult


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _boundary(insn_count=10, vip_delta=4, handler_address=0x6000,
              trace_start=0, trace_end=10, vip_value=0x100):
    return HandlerBoundary(
        vip_value=vip_value,
        handler_address=handler_address,
        trace_start=trace_start,
        trace_end=trace_end,
        instruction_count=insn_count,
        vip_delta=vip_delta,
    )


# ---------------------------------------------------------------------------
# TrainedHandlerModel — heuristic mode
# ---------------------------------------------------------------------------

class TestTrainedHandlerModelHeuristic:
    def test_predict_returns_result(self):
        model = TrainedHandlerModel()
        result = model.predict({
            "values": [10.0, 4.0, 4.0, 10.0, 1.0, 14.0],
            "names": [
                "instruction_count", "vip_delta", "abs_vip_delta",
                "handler_span", "insn_density", "log_handler_addr",
            ],
        })
        assert isinstance(result, PredictionResult)
        assert result.label in HANDLER_CATEGORIES
        assert 0.0 <= result.confidence <= 1.0

    def test_nop_heuristic(self):
        model = TrainedHandlerModel()
        result = model.predict({
            "values": [2.0, 1.0, 1.0, 2.0, 1.0, 14.0],
            "names": [
                "instruction_count", "vip_delta", "abs_vip_delta",
                "handler_span", "insn_density", "log_handler_addr",
            ],
        })
        assert result.label == "nop"

    def test_branch_heuristic(self):
        model = TrainedHandlerModel()
        result = model.predict({
            "values": [10.0, 0.0, 0.0, 10.0, 1.0, 14.0],
            "names": [
                "instruction_count", "vip_delta", "abs_vip_delta",
                "handler_span", "insn_density", "log_handler_addr",
            ],
        })
        # vip_delta=0 → branch
        assert result.label == "branch"

    def test_probabilities_sum_to_one(self):
        model = TrainedHandlerModel()
        result = model.predict({
            "values": [5.0, 2.0, 2.0, 5.0, 1.0, 14.0],
            "names": [
                "instruction_count", "vip_delta", "abs_vip_delta",
                "handler_span", "insn_density", "log_handler_addr",
            ],
        })
        total = sum(result.probabilities.values())
        assert abs(total - 1.0) < 0.01

    def test_metadata_method(self):
        model = TrainedHandlerModel()
        result = model.predict({
            "values": [5.0, 2.0, 2.0, 5.0, 1.0, 14.0],
            "names": [
                "instruction_count", "vip_delta", "abs_vip_delta",
                "handler_span", "insn_density", "log_handler_addr",
            ],
        })
        assert result.metadata["method"] == "heuristic"


# ---------------------------------------------------------------------------
# classify_handlers
# ---------------------------------------------------------------------------

class TestClassifyHandlers:
    def test_basic_classification(self):
        boundaries = [
            _boundary(insn_count=2, vip_delta=1),   # nop
            _boundary(insn_count=10, vip_delta=0),   # branch
            _boundary(insn_count=6, vip_delta=2),     # arithmetic
        ]
        results = classify_handlers(boundaries)
        assert len(results) == 3
        assert all(isinstance(r, PredictionResult) for r in results)
        assert results[0].label == "nop"
        assert results[1].label == "branch"

    def test_empty_list(self):
        results = classify_handlers([])
        assert results == []


# ---------------------------------------------------------------------------
# build_handler_classifier
# ---------------------------------------------------------------------------

class TestBuildHandlerClassifier:
    def test_returns_classifier(self):
        clf = build_handler_classifier()
        assert clf is not None
        assert clf.model is not None
        assert clf.extractor is not None

    def test_nonexistent_model_path(self):
        # Should NOT crash — silently falls back to heuristic.
        clf = build_handler_classifier(model_path="/nonexistent/model.pkl")
        data = {
            "handler_address": 0x6000,
            "instruction_count": 10,
            "vip_delta": 4,
            "trace_start": 0,
            "trace_end": 10,
            "vip_value": 0x100,
        }
        result = clf.classify(data)
        assert isinstance(result, PredictionResult)


# ---------------------------------------------------------------------------
# TrainedHandlerModel — load
# ---------------------------------------------------------------------------

class TestModelLoad:
    def test_load_nonexistent_path(self):
        model = TrainedHandlerModel()
        # Should not raise.
        model.load("/nonexistent/path/model.pkl")
        # Falls back to heuristic.
        result = model.predict({"values": [5.0], "names": ["x"]})
        assert result.metadata["method"] == "heuristic"
