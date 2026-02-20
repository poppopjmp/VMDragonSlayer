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
from .pipeline import (
    FeatureVector,
    extract_handler_features,
    extract_extended_features,
    EXTENDED_FEATURE_NAMES,
    HANDLER_FEATURE_NAMES,
)

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

    # Partial match (skip empty op)
    if op_lower:
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


# ═══════════════════════════════════════════════════════════════════════════
# Synthetic training data generator
# ═══════════════════════════════════════════════════════════════════════════

import random as _random

# Realistic VMProtect handler instruction templates keyed by category.
# Each value is a list of "handler body templates" — lists of (mnemonic, operands)
# tuples that mimic real VM handler bodies.

_HANDLER_TEMPLATES: Dict[str, List[List[tuple[str, str]]]] = {
    "arithmetic": [
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("add", "rax, rcx"),
            ("mov", "[rbp+8], rax"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("sub", "rax, rcx"),
            ("mov", "[rbp+8], rax"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("neg", "rax"),
            ("mov", "[rbp], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("imul", "rax, rcx"),
            ("mov", "[rbp+8], rax"),
        ],
    ],
    "logic": [
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("xor", "rax, rcx"),
            ("mov", "[rbp+8], rax"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("and", "rax, rcx"),
            ("mov", "[rbp+8], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("not", "rax"),
            ("mov", "[rbp], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("mov", "cl, [rbp+8]"),
            ("shl", "rax, cl"),
            ("mov", "[rbp+8], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("mov", "cl, [rbp+8]"),
            ("shr", "rax, cl"),
            ("mov", "[rbp+8], rax"),
        ],
    ],
    "stack": [
        [
            ("mov", "rax, [rsi]"),
            ("sub", "rbp, 8"),
            ("mov", "[rbp], rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("add", "rbp, 8"),
            ("mov", "[rsi], rax"),
        ],
        [
            ("push", "rax"),
            ("mov", "rax, [rsi]"),
            ("mov", "[rbp], rax"),
        ],
    ],
    "load_store": [
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rax]"),
            ("mov", "[rbp], rcx"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("mov", "[rax], rcx"),
            ("add", "rbp, 8"),
        ],
        [
            ("movzx", "eax, byte ptr [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("mov", "[rcx], al"),
        ],
    ],
    "branch": [
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rsi, rax"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("test", "rax, rax"),
            ("cmove", "rsi, rcx"),
        ],
        [
            ("mov", "rax, [rbp]"),
            ("cmp", "rax, 0"),
            ("jne", "0x1234"),
        ],
    ],
    "nop": [
        [
            ("nop", ""),
        ],
        [
            ("nop", ""),
            ("nop", ""),
        ],
    ],
}


def generate_synthetic_handlers(
    n_per_category: int = 50,
    *,
    seed: int = 42,
    jitter: bool = True,
) -> List[Dict[str, Any]]:
    """Generate synthetic VM handler dicts for training.

    For each handler category, produces *n_per_category* handler dicts
    by randomly selecting a template and optionally injecting jitter
    (nop padding, register renaming).

    Returns a list of dicts with keys: ``instructions``, ``mnemonics``,
    ``category``, ``operation``, ``operand_width``, ``block_count``.
    """
    rng = _random.Random(seed)
    handlers: List[Dict[str, Any]] = []

    for cat, templates in _HANDLER_TEMPLATES.items():
        for _ in range(n_per_category):
            tmpl = rng.choice(templates)
            body: List[tuple[str, str]] = list(tmpl)

            if jitter:
                # Possibly insert 0-2 nop instructions at random positions
                n_nops = rng.randint(0, 2)
                for __ in range(n_nops):
                    pos = rng.randint(0, len(body))
                    body.insert(pos, ("nop", ""))

            # Build instruction dicts
            instructions: List[Dict[str, str]] = []
            mnemonics: List[str] = []
            for mnem, ops in body:
                instructions.append({"mnemonic": mnem, "operands": ops})
                mnemonics.append(mnem.lower())

            # Map category to an operation name
            _cat_to_op = {
                "arithmetic": "vm_add",
                "logic": "vm_xor",
                "stack": "vm_push",
                "load_store": "vm_load",
                "branch": "vm_jmp",
                "nop": "vm_nop",
            }

            handlers.append({
                "instructions": instructions,
                "mnemonics": mnemonics,
                "category": cat,
                "operation": _cat_to_op.get(cat, "vm_unknown"),
                "operand_width": rng.choice([4, 8]),
                "block_count": rng.randint(1, 3),
                "reads": [],
                "writes": [],
            })

    rng.shuffle(handlers)
    return handlers


def prepare_extended_training_data(
    handlers: List[Dict[str, Any]],
    label_key: str = "",
) -> tuple[list[FeatureVector], list[str]]:
    """Like :func:`prepare_training_data` but uses extended features."""
    features: list[FeatureVector] = []
    labels: list[str] = []
    for h in handlers:
        fv = extract_extended_features(h)
        if label_key and label_key in h:
            lbl = str(h[label_key])
        else:
            lbl = label_from_heuristics(h)
        features.append(fv)
        labels.append(lbl)
    return features, labels


def feature_importance(
    model: VMHandlerModel,
    feature_names: Sequence[str] | None = None,
    top_n: int = 15,
) -> List[tuple[str, float]]:
    """Return top-N feature importances from a trained sklearn model.

    Returns list of ``(feature_name, importance)`` tuples sorted
    descending.  Returns empty list if no sklearn model is loaded.
    """
    clf = getattr(model, "_sklearn_model", None)
    if clf is None or not hasattr(clf, "feature_importances_"):
        return []

    importances = clf.feature_importances_
    names = list(feature_names) if feature_names else [f"f{i}" for i in range(len(importances))]
    if len(names) != len(importances):
        names = [f"f{i}" for i in range(len(importances))]

    ranked = sorted(zip(names, importances), key=lambda x: x[1], reverse=True)
    return ranked[:top_n]


def train_full_pipeline(
    n_per_category: int = 50,
    *,
    seed: int = 42,
    extended: bool = True,
    n_estimators: int = 100,
) -> tuple[VMHandlerModel, TrainingResult, List[tuple[str, float]]]:
    """End-to-end: generate data, extract features, train, report.

    Returns ``(model, training_result, top_importances)``.
    """
    handlers = generate_synthetic_handlers(n_per_category=n_per_category, seed=seed)

    if extended:
        features, labels = prepare_extended_training_data(handlers, label_key="category")
        names = EXTENDED_FEATURE_NAMES
    else:
        features, labels = prepare_training_data(handlers, label_key="category")
        names = list(HANDLER_FEATURE_NAMES)

    model = VMHandlerModel()
    trainer = ModelTrainer(model)
    result = trainer.train(features, labels, n_estimators=n_estimators)

    imp = feature_importance(model, feature_names=names)
    return model, result, imp
