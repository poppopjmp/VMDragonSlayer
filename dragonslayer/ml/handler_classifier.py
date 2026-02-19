"""
Handler Classification Bridge
==============================

Connects the :mod:`~dragonslayer.ml` pipeline to the devirtualisation
analysis path.  Provides:

* :class:`HandlerFeatureExtractor` — feature-spec–backed extractor for
  :class:`~..vm_discovery.handler_boundaries.HandlerBoundary` records.
* :class:`TrainedHandlerModel` — scikit-learn–backed
  :class:`~..ml.model.VMHandlerModel` with heuristic fallback when no
  trained model is available.
* :func:`classify_handlers` — convenience function that classifies a
  list of handler boundaries.

Usage::

    from dragonslayer.ml.handler_classifier import classify_handlers

    results = classify_handlers(boundaries)
    for boundary, prediction in zip(boundaries, results):
        print(f"vIP={boundary.vip_value:#x}  → {prediction.label} "
              f"({prediction.confidence:.0%})")
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dragonslayer.ml.model import BaseModel, PredictionResult, VMHandlerModel
from dragonslayer.ml.pipeline import FeatureExtractor, FeatureVector
from dragonslayer.ml.classifier import VMClassifier
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import RandomForestClassifier as _RFC
    SKLEARN_AVAILABLE = True
except ImportError:
    _RFC = None  # type: ignore[assignment, misc]
    SKLEARN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Feature specification
# ---------------------------------------------------------------------------

# Handler categories we classify into.
HANDLER_CATEGORIES = [
    "arithmetic",
    "bitwise",
    "memory",
    "branch",
    "call",
    "compare",
    "stack",
    "system",
    "nop",
    "unknown",
]

def _safe_int(v: Any) -> int:
    """Parse an int that may be hex string or int."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    return int(v)


def _handler_feature_spec() -> Dict[str, Any]:
    """Build the feature spec dict for FeatureExtractor."""

    return {
        "instruction_count": lambda d: float(d.get("instruction_count", 0)),
        "vip_delta": lambda d: float(d.get("vip_delta", 0)),
        "abs_vip_delta": lambda d: float(abs(d.get("vip_delta", 0))),
        "handler_span": lambda d: float(
            d.get("trace_end", 0) - d.get("trace_start", 0)
        ),
        "insn_density": lambda d: (
            float(d.get("instruction_count", 0))
            / max(float(d.get("trace_end", 1) - d.get("trace_start", 0)), 1)
        ),
        "log_handler_addr": lambda d: (
            math.log2(max(_safe_int(d.get("handler_address", 1)), 1))
        ),
    }


# ---------------------------------------------------------------------------
# Heuristic model (no training needed)
# ---------------------------------------------------------------------------

# Heuristic classification table based on instruction count and vip_delta.
# Thresholds are derived from common VMProtect/Themida handler patterns.
_HEURISTIC_RULES: List[Tuple[str, float, Any]] = [
    # (category, confidence, predicate(features_dict) -> bool)
]


class TrainedHandlerModel(VMHandlerModel):
    """VM handler model with scikit-learn backend and heuristic fallback.

    When :meth:`load` succeeds (a pickled sklearn model exists), all
    predictions go through the forest.  Otherwise a rule-based heuristic
    provides reasonable default classifications.
    """

    name: str = "vm_handler_trained"

    def __init__(self) -> None:
        super().__init__()
        self._sklearn_model: Optional[Any] = None
        self._label_names: List[str] = HANDLER_CATEGORIES

    # ---- load -----------------------------------------------------------

    def load(self, path: str) -> None:
        """Load a pickled scikit-learn model from *path*.

        Silently falls back to heuristic mode if loading fails.
        """
        if not SKLEARN_AVAILABLE:
            logger.info("scikit-learn not available; using heuristic model")
            return
        try:
            import pickle
            from pathlib import Path

            p = Path(path)
            if not p.exists():
                logger.info("Model file %s not found; using heuristic mode", path)
                return
            with open(p, "rb") as fh:
                obj = pickle.load(fh)  # noqa: S301
            if hasattr(obj, "predict_proba"):
                self._sklearn_model = obj
                logger.info("Loaded sklearn model from %s", path)
            else:
                logger.warning("Loaded object has no predict_proba; heuristic mode")
        except Exception as exc:
            logger.warning("Failed to load model from %s: %s", path, exc)

    # ---- predict --------------------------------------------------------

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        """Classify one handler from its feature vector."""
        values = features.get("values", [])
        names = features.get("names", [])

        if self._sklearn_model is not None:
            return self._predict_sklearn(values, names)
        return self._predict_heuristic(values, names)

    def _predict_sklearn(
        self, values: List[float], names: List[str],
    ) -> PredictionResult:
        """Prediction via trained sklearn model."""
        import numpy as np

        X = np.array(values).reshape(1, -1)
        proba = self._sklearn_model.predict_proba(X)[0]
        classes = list(self._sklearn_model.classes_)
        best_idx = int(proba.argmax())
        label = str(classes[best_idx])
        conf = float(proba[best_idx])
        prob_dict = {str(c): float(p) for c, p in zip(classes, proba)}
        return PredictionResult(
            label=label,
            confidence=conf,
            probabilities=prob_dict,
            metadata={"method": "sklearn", "feature_names": names},
        )

    def _predict_heuristic(
        self, values: List[float], names: List[str],
    ) -> PredictionResult:
        """Rule-based classification when no trained model is available."""
        feat = dict(zip(names, values))

        insn_count = feat.get("instruction_count", 0)
        vip_delta = feat.get("vip_delta", 0)
        abs_delta = feat.get("abs_vip_delta", abs(vip_delta))
        density = feat.get("insn_density", 0)

        # Simple heuristic decision tree.
        if insn_count <= 3:
            label, conf = "nop", 0.7
        elif abs_delta == 0:
            label, conf = "branch", 0.5
        elif abs_delta <= 2 and insn_count <= 8:
            label, conf = "arithmetic", 0.6
        elif abs_delta <= 2 and insn_count > 8:
            label, conf = "compare", 0.5
        elif 3 <= abs_delta <= 5 and insn_count <= 12:
            label, conf = "memory", 0.55
        elif abs_delta > 5 and insn_count > 15:
            label, conf = "call", 0.5
        elif density > 0.8:
            label, conf = "bitwise", 0.45
        elif insn_count > 20:
            label, conf = "system", 0.4
        else:
            label, conf = "unknown", 0.3

        # Build probability distribution centred on the chosen label.
        probs = {c: 0.0 for c in HANDLER_CATEGORIES}
        probs[label] = conf
        remaining = 1.0 - conf
        others = [c for c in HANDLER_CATEGORIES if c != label]
        if others:
            share = remaining / len(others)
            for c in others:
                probs[c] = round(share, 4)

        return PredictionResult(
            label=label,
            confidence=conf,
            probabilities=probs,
            metadata={"method": "heuristic", "feature_names": names},
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def build_handler_classifier(
    model_path: Optional[str] = None,
) -> VMClassifier:
    """Create a ready-to-use classifier for handler boundaries.

    Args:
        model_path: Optional path to a trained sklearn model pickle.
            If ``None`` or not found, falls back to heuristic mode.

    Returns:
        A :class:`VMClassifier` configured for handler classification.
    """
    extractor = FeatureExtractor(feature_spec=_handler_feature_spec())
    model = TrainedHandlerModel()
    if model_path:
        model.load(model_path)
    return VMClassifier(model=model, extractor=extractor)


def classify_handlers(
    boundaries: Sequence[HandlerBoundary],
    *,
    model_path: Optional[str] = None,
) -> List[PredictionResult]:
    """Classify a list of handler boundaries.

    Convenience wrapper that builds a classifier and runs it on each
    boundary.

    Args:
        boundaries: Handler boundaries from trace segmentation.
        model_path: Optional trained model path.

    Returns:
        One :class:`PredictionResult` per boundary, in order.
    """
    clf = build_handler_classifier(model_path)
    results: List[PredictionResult] = []
    for b in boundaries:
        data = {
            "handler_address": b.handler_address,
            "instruction_count": b.instruction_count,
            "vip_delta": b.vip_delta,
            "trace_start": b.trace_start,
            "trace_end": b.trace_end,
            "vip_value": b.vip_value,
        }
        results.append(clf.classify(data))
    return results
