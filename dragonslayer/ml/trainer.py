"""
ML Model Trainer
=================

Training infrastructure for the VM handler classification models.

:func:`label_from_heuristics` generates training labels from handler
semantic data so we can bootstrap a classifier without hand-labelled
data.

:class:`ModelTrainer` can train a scikit-learn ``RandomForestClassifier``
when the library is available, or just validate heuristic labels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

import logging

from .model import BaseModel, PredictionResult, VMHandlerModel, HANDLER_CATEGORIES
from .pipeline import FeatureVector, extract_handler_features

logger = logging.getLogger(__name__)

_HAS_SKLEARN = False
try:
    from sklearn.ensemble import RandomForestClassifier  # type: ignore[import-untyped]
    from sklearn.model_selection import cross_val_score  # type: ignore[import-untyped]
    import numpy as np  # type: ignore[import-untyped]
    _HAS_SKLEARN = True
except ImportError:
    pass


@dataclass
class TrainingResult:
    """Summary of a training run."""

    epochs: int = 0
    final_loss: float = 0.0
    accuracy: float = 0.0
    metrics: Dict[str, float] = field(default_factory=dict)
    model_path: str = ""


# ---------------------------------------------------------------------------
# Heuristic labelling
# ---------------------------------------------------------------------------

# Map handler semantic operations (VMOperation values from handler_semantics)
# to classifier categories.
_OP_TO_LABEL: Dict[str, str] = {
    "vm_add": "arithmetic",
    "vm_sub": "arithmetic",
    "vm_mul": "arithmetic",
    "vm_div": "arithmetic",
    "vm_neg": "arithmetic",
    "vm_inc": "arithmetic",
    "vm_dec": "arithmetic",
    "vm_and": "logic",
    "vm_or": "logic",
    "vm_xor": "logic",
    "vm_not": "logic",
    "vm_shl": "logic",
    "vm_shr": "logic",
    "vm_sar": "logic",
    "vm_rol": "logic",
    "vm_ror": "logic",
    "vm_push": "stack",
    "vm_pop": "stack",
    "vm_load": "load_store",
    "vm_store": "load_store",
    "vm_mov": "load_store",
    "vm_jmp": "branch",
    "vm_jcc": "branch",
    "vm_call": "branch",
    "vm_ret": "branch",
    "vm_nop": "nop",
    "vm_unknown": "unknown",
}


def label_from_heuristics(handler: Dict[str, Any]) -> str:
    """Derive a classification label from handler semantic data.

    Checks ``operation``, ``semantic.operation`` or ``category`` keys.
    Falls back to ``"unknown"``.
    """
    op = handler.get("operation", "")
    if not op:
        sem = handler.get("semantic", {})
        if isinstance(sem, dict):
            op = sem.get("operation", "")
    if not op:
        op = handler.get("category", "")

    op_lower = str(op).lower().strip()

    # Direct match in the map
    if op_lower in _OP_TO_LABEL:
        return _OP_TO_LABEL[op_lower]

    # Partial match
    for key, label in _OP_TO_LABEL.items():
        if key in op_lower or op_lower in key:
            return label

    return "unknown"


def prepare_training_data(
    handlers: List[Dict[str, Any]],
    label_key: str = "",
) -> tuple[list[FeatureVector], list[str]]:
    """Convert handler dicts into ``(features, labels)`` for training.

    If *label_key* is set, uses ``handler[label_key]`` as label;
    otherwise applies :func:`label_from_heuristics`.
    """
    features: list[FeatureVector] = []
    labels: list[str] = []

    for h in handlers:
        fv = extract_handler_features(h)
        if label_key and label_key in h:
            lbl = str(h[label_key])
        else:
            lbl = label_from_heuristics(h)
        features.append(fv)
        labels.append(lbl)

    return features, labels


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------

class ModelTrainer:
    """Train a :class:`VMHandlerModel` on labelled feature vectors.

    When scikit-learn is available, trains a ``RandomForestClassifier``
    and attaches it to the model.  Without scikit-learn, validates
    heuristic accuracy against the provided labels.
    """

    def __init__(self, model: BaseModel | None = None) -> None:
        self._model = model or VMHandlerModel()

    def train(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
        *,
        epochs: int = 100,
        n_estimators: int = 100,
        **kwargs: Any,
    ) -> TrainingResult:
        if _HAS_SKLEARN:
            return self._train_sklearn(features, labels, n_estimators=n_estimators)
        return self._validate_heuristic(features, labels)

    def _train_sklearn(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
        n_estimators: int = 100,
    ) -> TrainingResult:
        X = np.array([fv.values for fv in features])
        y = np.array(list(labels))

        clf = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
        clf.fit(X, y)

        # Cross-validation accuracy (if enough data).
        accuracy = 0.0
        if len(y) >= 10:
            scores = cross_val_score(clf, X, y, cv=min(5, len(y)), scoring="accuracy")
            accuracy = float(scores.mean())
        else:
            accuracy = float((clf.predict(X) == y).mean())

        # Attach to the model.
        if isinstance(self._model, VMHandlerModel):
            self._model._sklearn_model = clf

        logger.info("Trained RF with %d estimators, accuracy=%.3f", n_estimators, accuracy)
        return TrainingResult(
            epochs=1,
            accuracy=round(accuracy, 4),
            metrics={"n_estimators": n_estimators, "n_samples": len(y)},
        )

    def _validate_heuristic(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
    ) -> TrainingResult:
        """Validate heuristic predictions against ground-truth labels."""
        model = self._model
        correct = 0
        total = len(labels)
        for fv, true_label in zip(features, labels):
            pred = model.predict({"values": fv.values, "names": fv.feature_names})
            if pred.label == true_label:
                correct += 1

        accuracy = correct / total if total else 0.0
        return TrainingResult(
            epochs=0,
            accuracy=round(accuracy, 4),
            metrics={"method": "heuristic_validation", "n_samples": total, "correct": correct},
        )

    def evaluate(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
    ) -> Dict[str, float]:
        """Evaluate model accuracy on a held-out set."""
        correct = 0
        total = len(labels)
        for fv, true_label in zip(features, labels):
            pred = self._model.predict({"values": fv.values, "names": fv.feature_names})
            if pred.label == true_label:
                correct += 1
        return {"accuracy": correct / total if total else 0.0, "total": total}
