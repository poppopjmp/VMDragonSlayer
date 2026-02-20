"""
ML Model Definitions
====================

Base model classes, prediction result container, and concrete
:class:`VMHandlerModel` heuristic classifier for the VM handler
classification pipeline.

:class:`VMHandlerModel` uses **weighted-rule scoring** — no external
ML library required.  When scikit-learn is installed, it can
optionally delegate to a trained ``RandomForestClassifier`` loaded
from disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import logging

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """Container for a single model prediction."""

    label: str = ""
    confidence: float = 0.0
    probabilities: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseModel:
    """Abstract base for all ML models in VMDragonSlayer.

    Subclasses must override :meth:`predict` and :meth:`load`.
    """

    name: str = "base"

    def load(self, path: str) -> None:
        """Load model weights / parameters from *path*."""
        raise NotImplementedError(
            f"{type(self).__name__}.load() is not implemented — "
            "install a training backend and provide a trained model artifact"
        )

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        """Run inference on a single feature dict."""
        raise NotImplementedError(
            f"{type(self).__name__}.predict() is not implemented"
        )

    def predict_batch(self, batch: List[Dict[str, Any]]) -> List[PredictionResult]:
        """Run inference on a batch (default: sequential predict)."""
        return [self.predict(f) for f in batch]


# ---------------------------------------------------------------------------
# Heuristic handler categories
# ---------------------------------------------------------------------------

HANDLER_CATEGORIES: List[str] = [
    "arithmetic",    # ADD, SUB, MUL, DIV, NEG, INC, DEC
    "logic",         # AND, OR, XOR, NOT, SHL, SHR, ROL, ROR
    "stack",         # PUSH, POP
    "load_store",    # MOV [mem] / MOV reg,[mem]
    "branch",        # JMP, JCC, CALL, RET
    "nop",           # NOP / junk
    "unknown",
]

# ---------------------------------------------------------------------------
# Weighted-rule scorer
# ---------------------------------------------------------------------------

# Each rule maps a feature name to (weight, threshold, direction).
# "above" means feature >= threshold contributes positively.
# "below" means feature < threshold contributes positively.
_HEURISTIC_RULES: Dict[str, List[tuple[str, float, float, str]]] = {
    "arithmetic": [
        ("arith_ratio", 3.0, 0.25, "above"),
        ("logic_ratio", -1.0, 0.30, "above"),
        ("stack_ratio", -0.5, 0.40, "above"),
        ("branch_ratio", -1.0, 0.20, "above"),
    ],
    "logic": [
        ("logic_ratio", 3.0, 0.25, "above"),
        ("arith_ratio", -0.5, 0.30, "above"),
        ("branch_ratio", -1.0, 0.20, "above"),
    ],
    "stack": [
        ("stack_ratio", 3.0, 0.30, "above"),
        ("instruction_count", 1.0, 5.0, "below"),
    ],
    "load_store": [
        ("mem_ratio", 3.0, 0.30, "above"),
        ("has_memory_read", 1.5, 0.5, "above"),
        ("has_memory_write", 1.5, 0.5, "above"),
        ("branch_ratio", -1.0, 0.10, "above"),
    ],
    "branch": [
        ("branch_ratio", 3.0, 0.15, "above"),
        ("has_indirect_branch", 1.5, 0.5, "above"),
    ],
    "nop": [
        ("nop_ratio", 4.0, 0.50, "above"),
        ("instruction_count", 1.0, 3.0, "below"),
    ],
}


def _score_rules(
    values: List[float],
    names: List[str],
) -> Dict[str, float]:
    """Score each handler category using the heuristic rules."""
    lookup: Dict[str, float] = dict(zip(names, values))
    scores: Dict[str, float] = {}

    for category, rules in _HEURISTIC_RULES.items():
        s = 0.0
        for feat_name, weight, threshold, direction in rules:
            val = lookup.get(feat_name, 0.0)
            if direction == "above":
                s += weight * max(0.0, val - threshold)
            else:  # below
                s += weight * max(0.0, threshold - val)
        scores[category] = s

    # Ensure 'unknown' has a small baseline
    scores.setdefault("unknown", 0.01)
    return scores


# ---------------------------------------------------------------------------
# VMHandlerModel — concrete classifier
# ---------------------------------------------------------------------------

class VMHandlerModel(BaseModel):
    """Classify VM handlers using weighted-rule heuristics.

    Falls back to a scikit-learn ``RandomForestClassifier`` when a
    trained model is loaded via :meth:`load`.
    """

    name: str = "vm_handler"

    def __init__(self) -> None:
        self._sklearn_model: Any = None

    def load(self, path: str) -> None:
        """Load a scikit-learn model from *path* (joblib or pickle)."""
        try:
            import joblib  # type: ignore[import-untyped]
            self._sklearn_model = joblib.load(path)
            logger.info("Loaded sklearn model from %s", path)
        except ImportError:
            import pickle
            with open(path, "rb") as f:
                self._sklearn_model = pickle.load(f)
            logger.info("Loaded pickled model from %s", path)

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        """Classify a handler from its feature vector.

        *features* should contain ``values`` (list of floats) and
        ``names`` (list of feature name strings).
        """
        values: List[float] = features.get("values", [])
        names: List[str] = features.get("names", [])

        # If a trained sklearn model is loaded, use it.
        if self._sklearn_model is not None:
            return self._predict_sklearn(values)

        # Otherwise fall back to heuristic scoring.
        return self._predict_heuristic(values, names)

    def _predict_heuristic(
        self,
        values: List[float],
        names: List[str],
    ) -> PredictionResult:
        scores = _score_rules(values, names)
        total = sum(max(0, s) for s in scores.values()) or 1.0
        probs = {k: max(0, v) / total for k, v in scores.items()}

        best = max(probs, key=probs.get)  # type: ignore[arg-type]
        return PredictionResult(
            label=best,
            confidence=round(probs[best], 4),
            probabilities=probs,
            metadata={"method": "heuristic"},
        )

    def _predict_sklearn(self, values: List[float]) -> PredictionResult:
        import numpy as np  # type: ignore[import-untyped]
        X = np.array([values])
        label = self._sklearn_model.predict(X)[0]
        probs: Dict[str, float] = {}
        if hasattr(self._sklearn_model, "predict_proba"):
            p = self._sklearn_model.predict_proba(X)[0]
            classes = list(self._sklearn_model.classes_)
            probs = {str(c): float(v) for c, v in zip(classes, p)}
        confidence = probs.get(str(label), 0.9)
        return PredictionResult(
            label=str(label),
            confidence=round(confidence, 4),
            probabilities=probs,
            metadata={"method": "sklearn"},
        )
