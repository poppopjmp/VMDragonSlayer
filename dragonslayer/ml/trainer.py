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
_HAS_GB = False
try:
    from sklearn.ensemble import RandomForestClassifier  # type: ignore[import-untyped]
    from sklearn.ensemble import GradientBoostingClassifier  # type: ignore[import-untyped]
    from sklearn.model_selection import cross_val_score  # type: ignore[import-untyped]
    from sklearn.metrics import classification_report as _sklearn_report  # type: ignore[import-untyped]
    import numpy as np  # type: ignore[import-untyped]
    _HAS_SKLEARN = True
    _HAS_GB = True
except ImportError:
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
    "vm_and": "bitwise",
    "vm_or": "bitwise",
    "vm_xor": "bitwise",
    "vm_not": "bitwise",
    "vm_shl": "bitwise",
    "vm_shr": "bitwise",
    "vm_sar": "bitwise",
    "vm_rol": "bitwise",
    "vm_ror": "bitwise",
    "vm_nand": "bitwise",
    "vm_nor": "bitwise",
    "vm_push": "stack",
    "vm_pop": "stack",
    "vm_load": "memory",
    "vm_store": "memory",
    "vm_mov": "memory",
    "vm_jmp": "control_flow",
    "vm_jcc": "control_flow",
    "vm_call": "control_flow",
    "vm_ret": "control_flow",
    # VM entry/exit (canonical: vm_control)
    "vm_enter": "vm_control",
    "vm_exit": "vm_control",
    # Context / dispatch (canonical: vm_control)
    "vm_ctx_save": "vm_control",
    "vm_ctx_restore": "vm_control",
    "vm_fetch_opcode": "vm_control",
    "vm_dispatch": "vm_control",
    # Crypto / anti-debug
    "vm_decrypt": "crypto",
    "vm_key_update": "crypto",
    "vm_cpuid": "crypto",
    "vm_rdtsc": "crypto",
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
        algorithm: str = "auto",
        **kwargs: Any,
    ) -> TrainingResult:
        """Train the model.

        Parameters
        ----------
        algorithm : str
            ``"auto"`` (GradientBoosting if available, else RandomForest),
            ``"rf"`` (RandomForest), ``"gb"`` (GradientBoosting).
        """
        # B67: Input validation — fail fast on mis-shaped data
        if len(features) != len(labels):
            raise ValueError(
                f"features/labels length mismatch: {len(features)} vs {len(labels)}"
            )
        if not features:
            raise ValueError("Cannot train on empty dataset")
        dim0 = features[0].dimension
        bad = [i for i, fv in enumerate(features) if fv.dimension != dim0]
        if bad:
            raise ValueError(
                f"Inconsistent feature dimensions: expected {dim0}, "
                f"got mismatches at indices {bad[:5]}"
            )

        if _HAS_SKLEARN:
            return self._train_sklearn(
                features, labels, n_estimators=n_estimators, algorithm=algorithm,
            )
        return self._validate_heuristic(features, labels)

    def _train_sklearn(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
        n_estimators: int = 100,
        algorithm: str = "auto",
    ) -> TrainingResult:
        X = np.array([fv.values for fv in features])
        y = np.array(list(labels))

        # Choose estimator
        use_gb = (algorithm == "gb") or (algorithm == "auto" and _HAS_GB)
        if use_gb and _HAS_GB:
            clf = GradientBoostingClassifier(
                n_estimators=n_estimators,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
            )
            algo_name = "GradientBoosting"
        else:
            clf = RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=42,
                n_jobs=-1,
            )
            algo_name = "RandomForest"

        clf.fit(X, y)

        # B67: Confidence calibration — raw predict_proba from RF/GB can be
        # poorly calibrated.  Wrap with isotonic calibration when we have
        # enough data for meaningful cross-validation.
        if len(y) >= 20:
            try:
                from sklearn.calibration import CalibratedClassifierCV
                from collections import Counter as _Counter
                min_class = min(_Counter(y).values(), default=0)
                cal_cv = min(3, min_class) if min_class >= 2 else 2
                if cal_cv >= 2:
                    cal_clf = CalibratedClassifierCV(clf, cv=cal_cv, method="isotonic")
                    cal_clf.fit(X, y)
                    clf = cal_clf
                    logger.info("Applied isotonic confidence calibration (cv=%d)", cal_cv)
            except (ValueError, TypeError, ImportError, AttributeError, RuntimeError) as exc:
                logger.debug("Calibration failed, using raw probabilities: %s", exc)

        # B67: Stratified cross-validation — preserves class distribution.
        accuracy = 0.0
        if len(y) >= 10:
            from collections import Counter as _Counter2
            from sklearn.model_selection import StratifiedKFold
            min_class_count = min(_Counter2(y).values(), default=0)
            n_splits = min(5, min_class_count) if min_class_count >= 2 else 2
            if n_splits >= 2:
                skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
                scores = cross_val_score(clf, X, y, cv=skf, scoring="accuracy")
            else:
                scores = cross_val_score(clf, X, y, cv=2, scoring="accuracy")
            accuracy = float(scores.mean())
        else:
            accuracy = float((clf.predict(X) == y).mean())

        # Per-class metrics
        per_class: Dict[str, Any] = {}
        try:
            y_pred = clf.predict(X)
            report = _sklearn_report(y, y_pred, output_dict=True, zero_division=0)
            for cls_name, cls_metrics in report.items():
                if isinstance(cls_metrics, dict):
                    per_class[cls_name] = {
                        k: round(v, 4) for k, v in cls_metrics.items()
                    }
        except (ValueError, TypeError, KeyError, AttributeError):
            pass

        # Attach to the model.
        if isinstance(self._model, VMHandlerModel):
            self._model._sklearn_model = clf

        logger.info("Trained %s with %d estimators, accuracy=%.3f", algo_name, n_estimators, accuracy)
        return TrainingResult(
            epochs=1,
            accuracy=round(accuracy, 4),
            metrics={
                "n_estimators": n_estimators,
                "n_samples": len(y),
                "algorithm": algo_name,
                "per_class": per_class,
            },
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

    # B75: Hyperparameter search -------------------------------------------

    def train_with_search(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
        *,
        param_grid: Dict[str, list] | None = None,
        cv: int = 3,
        n_iter: int = 10,
    ) -> TrainingResult:
        """Train with randomised hyperparameter search.

        Falls back to :meth:`train` if scikit-learn is unavailable or
        the dataset is too small for cross-validation.

        *param_grid* defaults to a sensible search space over
        ``n_estimators``, ``max_depth``, ``min_samples_leaf``.
        """
        if not _HAS_SKLEARN or len(features) < 10:
            return self.train(features, labels)

        from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold

        X = np.array([fv.values for fv in features])
        y = np.array(list(labels))

        if param_grid is None:
            param_grid = {
                "n_estimators": [50, 100, 200, 300],
                "max_depth": [3, 5, 7, 10, None],
                "min_samples_leaf": [1, 2, 4],
            }

        base_clf = RandomForestClassifier(random_state=42, n_jobs=-1)
        from collections import Counter as _Counter3
        min_class_count = min(_Counter3(y).values(), default=0)
        real_cv = min(cv, min_class_count) if min_class_count >= 2 else 2
        if real_cv < 2:
            return self.train(features, labels)

        skf = StratifiedKFold(n_splits=real_cv, shuffle=True, random_state=42)
        search = RandomizedSearchCV(
            base_clf, param_grid,
            n_iter=min(n_iter, _count_grid(param_grid)),
            cv=skf,
            scoring="accuracy",
            random_state=42,
            n_jobs=-1,
        )
        search.fit(X, y)

        clf = search.best_estimator_
        accuracy = float(search.best_score_)

        # Attach to the model
        if isinstance(self._model, VMHandlerModel):
            self._model._sklearn_model = clf

        best_params = search.best_params_
        logger.info(
            "Hyperparameter search: best_score=%.3f, best_params=%s",
            accuracy, best_params,
        )
        return TrainingResult(
            epochs=1,
            accuracy=round(accuracy, 4),
            metrics={
                "method": "randomized_search",
                "best_params": best_params,
                "n_iter": n_iter,
                "cv": real_cv,
                "n_samples": len(y),
            },
        )

    @property
    def feature_importances(self) -> List[tuple[str, float]]:
        """Return sorted feature importances from the trained model.

        Returns list of ``(feature_name, importance)`` descending.
        Empty list if no sklearn model is attached.
        """
        return feature_importance(self._model)


def _count_grid(grid: Dict[str, list]) -> int:
    """Count total combinations in a parameter grid."""
    n = 1
    for v in grid.values():
        n *= len(v)
    return n


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
    "bitwise": [
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
    "memory": [
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
    "control_flow": [
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
    # ── VM control (canonical: vm_control) ───────────────────────────────────
    "vm_control": [
        # VM entry: push all registers (x64 style)
        [
            ("push", "rax"),
            ("push", "rcx"),
            ("push", "rdx"),
            ("push", "rbx"),
            ("push", "rbp"),
            ("push", "rsi"),
            ("push", "rdi"),
            ("push", "r8"),
            ("push", "r9"),
            ("push", "r10"),
            ("push", "r11"),
            ("push", "r12"),
            ("push", "r13"),
            ("push", "r14"),
            ("push", "r15"),
            ("pushf", ""),
        ],
        # VM entry: individual stores to context area
        [
            ("mov", "[rdi], rax"),
            ("mov", "[rdi+0x8], rcx"),
            ("mov", "[rdi+0x10], rdx"),
            ("mov", "[rdi+0x18], rbx"),
            ("mov", "[rdi+0x20], rsp"),
            ("mov", "[rdi+0x28], rbp"),
            ("mov", "[rdi+0x30], rsi"),
        ],
        # VM exit: pop all (reverse order)
        [
            ("popf", ""),
            ("pop", "r15"),
            ("pop", "r14"),
            ("pop", "r13"),
            ("pop", "r12"),
            ("pop", "r11"),
            ("pop", "r10"),
            ("pop", "r9"),
            ("pop", "r8"),
            ("pop", "rdi"),
            ("pop", "rsi"),
            ("pop", "rbp"),
            ("pop", "rbx"),
            ("pop", "rdx"),
            ("pop", "rcx"),
            ("pop", "rax"),
            ("ret", ""),
        ],
        # VM exit: individual loads from context
        [
            ("mov", "rax, [rdi]"),
            ("mov", "rcx, [rdi+0x8]"),
            ("mov", "rdx, [rdi+0x10]"),
            ("mov", "rsp, [rdi+0x20]"),
            ("mov", "rbp, [rdi+0x28]"),
            ("ret", ""),
        ],
        # Fetch opcode: read byte from vIP, increment vIP
        [
            ("movzx", "eax, byte ptr [rsi]"),
            ("inc", "rsi"),
        ],
        # Fetch opcode with XOR decrypt
        [
            ("movzx", "eax, byte ptr [rsi]"),
            ("xor", "al, cl"),
            ("inc", "rsi"),
        ],
        # Dispatch: handler table lookup
        [
            ("movzx", "eax, byte ptr [rsi]"),
            ("lea", "rcx, [rip+handler_table]"),
            ("movsxd", "rax, dword ptr [rcx+rax*4]"),
            ("add", "rax, rcx"),
            ("jmp", "rax"),
        ],
        # Context save: save single register to VM context
        [
            ("mov", "rax, [rbp]"),
            ("mov", "[rdi+rcx*8], rax"),
            ("add", "rbp, 8"),
        ],
        # Context restore: load single register from VM context
        [
            ("sub", "rbp, 8"),
            ("mov", "rax, [rdi+rcx*8]"),
            ("mov", "[rbp], rax"),
        ],
    ],
    "comparison": [
        # CMP two virtual registers, save flags
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("cmp", "rax, rcx"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp+8], rax"),
        ],
        # TEST (bitwise AND without storing result)
        [
            ("mov", "rax, [rbp]"),
            ("mov", "rcx, [rbp+8]"),
            ("test", "rax, rcx"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp+8], rax"),
        ],
        # CMP with immediate zero (common in VM conditional branches)
        [
            ("mov", "rax, [rbp]"),
            ("cmp", "rax, 0"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp], rax"),
        ],
        # TEST self (zero-check idiom)
        [
            ("mov", "rax, [rbp]"),
            ("test", "rax, rax"),
            ("pushf", ""),
            ("pop", "rax"),
            ("mov", "[rbp], rax"),
        ],
    ],
    "crypto": [
        # XOR decrypt opcode
        [
            ("mov", "al, [rsi]"),
            ("xor", "al, cl"),
            ("ror", "cl, 3"),
            ("xor", "cl, al"),
        ],
        # ADD decrypt opcode
        [
            ("mov", "al, [rsi]"),
            ("add", "al, cl"),
            ("rol", "cl, 5"),
            ("sub", "cl, al"),
        ],
        # Rolling key update
        [
            ("xor", "cl, al"),
            ("rol", "cl, 3"),
            ("add", "cl, al"),
        ],
        # CPUID check
        [
            ("cpuid", ""),
            ("mov", "[rbp], eax"),
            ("mov", "[rbp+4], ebx"),
            ("mov", "[rbp+8], ecx"),
            ("mov", "[rbp+12], edx"),
        ],
        # RDTSC timing check
        [
            ("rdtsc", ""),
            ("shl", "rdx, 32"),
            ("or", "rax, rdx"),
            ("mov", "[rbp], rax"),
        ],
        # Flag-mixing multiply
        [
            ("imul", "rax, rcx"),
            ("imul", "rdx, rbx"),
            ("xor", "rax, rdx"),
            ("mov", "[rbp], rax"),
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

            # Map category to an operation name (B75: matches _HANDLER_TEMPLATES keys)
            _cat_to_op = {
                "arithmetic": "vm_add",
                "bitwise": "vm_xor",
                "stack": "vm_push",
                "memory": "vm_load",
                "control_flow": "vm_jmp",
                "vm_control": "vm_enter",
                "comparison": "vm_cmp",
                "crypto": "vm_decrypt",
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
    # B67: CalibratedClassifierCV wraps the real estimator.  Walk through
    # known wrappers to find the underlying model with feature_importances_.
    real_clf = clf
    if real_clf is not None and not hasattr(real_clf, "feature_importances_"):
        # sklearn.calibration.CalibratedClassifierCV stores underlying as
        # estimator (>=1.2) or base_estimator (legacy).
        for attr in ("estimator", "base_estimator"):
            inner = getattr(real_clf, attr, None)
            if inner is not None and hasattr(inner, "feature_importances_"):
                real_clf = inner
                break
    if real_clf is None or not hasattr(real_clf, "feature_importances_"):
        return []

    importances = real_clf.feature_importances_
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
    algorithm: str = "auto",
    save_path: str | None = None,
) -> tuple[VMHandlerModel, TrainingResult, List[tuple[str, float]]]:
    """End-to-end: generate data, extract features, train, report.

    Parameters
    ----------
    algorithm : str
        ``"auto"`` (GradientBoosting if available), ``"rf"``, ``"gb"``.

    If *save_path* is provided, the trained model is serialised there.

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
    result = trainer.train(features, labels, n_estimators=n_estimators, algorithm=algorithm)

    imp = feature_importance(model, feature_names=names)

    if save_path and model.is_trained:
        model.save(save_path)

    return model, result, imp


# ═══════════════════════════════════════════════════════════════════════════
# Themida / WinLicense handler templates
# ═══════════════════════════════════════════════════════════════════════════

# Themida VMs use EDI as the virtual context pointer with all virtual
# registers stored at [edi+offset].  ESI is the virtual IP.
# Handlers are shorter than VMProtect and use pushad/popad context save.

_THEMIDA_HANDLER_TEMPLATES: Dict[str, List[List[tuple[str, str]]]] = {
    "arithmetic": [
        # ADD two virtual registers via EDI context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("add", "eax, ecx"),
            ("mov", "[edi+0x00], eax"),
            ("pushfd", ""),
            ("pop", "dword ptr [edi+0x20]"),
        ],
        # SUB via EDI context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x08]"),
            ("sub", "eax, ecx"),
            ("mov", "[edi+0x00], eax"),
            ("pushfd", ""),
            ("pop", "dword ptr [edi+0x20]"),
        ],
        # NEG single register
        [
            ("mov", "eax, [edi+0x00]"),
            ("neg", "eax"),
            ("mov", "[edi+0x00], eax"),
            ("pushfd", ""),
            ("pop", "dword ptr [edi+0x20]"),
        ],
        # IMUL via context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("imul", "eax, ecx"),
            ("mov", "[edi+0x00], eax"),
        ],
    ],
    "bitwise": [
        # XOR via EDI context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("xor", "eax, ecx"),
            ("mov", "[edi+0x00], eax"),
            ("pushfd", ""),
            ("pop", "dword ptr [edi+0x20]"),
        ],
        # AND via EDI context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("and", "eax, ecx"),
            ("mov", "[edi+0x00], eax"),
        ],
        # NOT
        [
            ("mov", "eax, [edi+0x00]"),
            ("not", "eax"),
            ("mov", "[edi+0x00], eax"),
        ],
        # SHL via context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "cl, [edi+0x04]"),
            ("shl", "eax, cl"),
            ("mov", "[edi+0x00], eax"),
        ],
    ],
    "stack": [
        # PUSH to Themida virtual stack (ESP-like in EDI context)
        [
            ("mov", "eax, [edi+0x10]"),
            ("sub", "eax, 4"),
            ("mov", "ecx, [edi+0x00]"),
            ("mov", "[eax], ecx"),
            ("mov", "[edi+0x10], eax"),
        ],
        # POP from Themida virtual stack
        [
            ("mov", "eax, [edi+0x10]"),
            ("mov", "ecx, [eax]"),
            ("add", "eax, 4"),
            ("mov", "[edi+0x00], ecx"),
            ("mov", "[edi+0x10], eax"),
        ],
    ],
    "memory": [
        # Load dword via virtual address in context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [eax]"),
            ("mov", "[edi+0x00], ecx"),
        ],
        # Store dword
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("mov", "[eax], ecx"),
        ],
        # Load byte (movzx)
        [
            ("mov", "eax, [edi+0x00]"),
            ("movzx", "ecx, byte ptr [eax]"),
            ("mov", "[edi+0x00], ecx"),
        ],
    ],
    "control_flow": [
        # Unconditional jump: set ESI (vIP) from context
        [
            ("mov", "esi, [edi+0x00]"),
        ],
        # Conditional jump (Themida style: check flags + overwrite ESI)
        [
            ("push", "dword ptr [edi+0x20]"),
            ("popfd", ""),
            ("jz", "skip"),
            ("mov", "esi, [edi+0x00]"),
        ],
        # VM call: push return address then jump
        [
            ("mov", "eax, esi"),
            ("mov", "ecx, [edi+0x10]"),
            ("sub", "ecx, 4"),
            ("mov", "[ecx], eax"),
            ("mov", "[edi+0x10], ecx"),
            ("mov", "esi, [edi+0x00]"),
        ],
    ],
    "nop": [
        [("nop", "")],
        [("nop", ""), ("nop", "")],
    ],
    "vm_control": [
        # VM entry — Themida pushad-style context save
        [
            ("pushad", ""),
            ("mov", "edi, esp"),
            ("sub", "esp, 0x40"),
            ("mov", "esi, [esp+0x24]"),
        ],
        # VM exit — popad-style context restore
        [
            ("mov", "esp, edi"),
            ("popad", ""),
            ("ret", ""),
        ],
        # Opcode fetch from ESI (Themida style)
        [
            ("movzx", "eax, byte ptr [esi]"),
            ("inc", "esi"),
        ],
        # Dispatch via handler table
        [
            ("movzx", "eax, byte ptr [esi]"),
            ("inc", "esi"),
            ("mov", "edx, [ebx+eax*4]"),
            ("jmp", "edx"),
        ],
        # Context save — store single register from virtual context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "[edi+ecx*4], eax"),
        ],
    ],
    "comparison": [
        # CMP two virtual registers, store flags in EDI context
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("cmp", "eax, ecx"),
            ("pushfd", ""),
            ("pop", "dword ptr [edi+0x20]"),
        ],
        # TEST two virtual registers
        [
            ("mov", "eax, [edi+0x00]"),
            ("mov", "ecx, [edi+0x04]"),
            ("test", "eax, ecx"),
            ("pushfd", ""),
            ("pop", "dword ptr [edi+0x20]"),
        ],
    ],
    "crypto": [
        # Themida rolling-key XOR decrypt
        [
            ("movzx", "eax, byte ptr [esi]"),
            ("xor", "al, cl"),
            ("ror", "cl, 3"),
            ("xor", "cl, al"),
            ("inc", "esi"),
        ],
        # ADD-based key update
        [
            ("movzx", "eax, byte ptr [esi]"),
            ("add", "al, cl"),
            ("rol", "cl, 5"),
            ("sub", "cl, al"),
            ("inc", "esi"),
        ],
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# Code Virtualizer (Oreans) handler templates
# ═══════════════════════════════════════════════════════════════════════════

# Code Virtualizer (CV) VMs use LODSB for bytecode fetch, XLAT for
# bytecode decryption, and ESI as the virtual IP.  CV handlers are
# typically CISC-style with longer instruction sequences.

_CV_HANDLER_TEMPLATES: Dict[str, List[List[tuple[str, str]]]] = {
    "arithmetic": [
        # CV ADD: LODSB fetch + XLAT decrypt + context-based add
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("add", "[esp+eax*4], ecx"),
            ("pushfd", ""),
            ("pop", "dword ptr [esp+0x20]"),
        ],
        # CV SUB
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("sub", "[esp+eax*4], ecx"),
            ("pushfd", ""),
            ("pop", "dword ptr [esp+0x20]"),
        ],
        # CV NEG single register
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("neg", "dword ptr [esp+eax*4]"),
        ],
    ],
    "bitwise": [
        # CV XOR
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("xor", "[esp+eax*4], ecx"),
        ],
        # CV AND
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("and", "[esp+eax*4], ecx"),
        ],
        # CV SHL
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "cl, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("shl", "[esp+eax*4], cl"),
        ],
    ],
    "stack": [
        # CV PUSH via LODSB + XLAT
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("push", "dword ptr [esp+eax*4+4]"),
        ],
        # CV POP
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("pop", "dword ptr [esp+eax*4]"),
        ],
    ],
    "memory": [
        # CV LOAD dword
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("mov", "ecx, [ecx]"),
            ("mov", "[esp+eax*4], ecx"),
        ],
        # CV STORE dword
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "edx, [esp+eax*4]"),
            ("mov", "[ecx], edx"),
        ],
    ],
    "control_flow": [
        # CV unconditional jump (read dword offset from bytecode)
        [
            ("lodsd", ""),
            ("bswap", "eax"),
            ("add", "esi, eax"),
        ],
        # CV conditional jump (flags-based)
        [
            ("push", "dword ptr [esp+0x20]"),
            ("popfd", ""),
            ("lodsd", ""),
            ("bswap", "eax"),
            ("jnz", "do_jump"),
        ],
    ],
    "nop": [
        [("lodsb", ""), ("xlat", "")],
        [("nop", "")],
    ],
    "vm_control": [
        # CV VM entry — save all GPRs to stack + set up XLAT table
        [
            ("pushad", ""),
            ("mov", "ebx, [esp+0x24]"),
            ("mov", "esi, [esp+0x20]"),
            ("sub", "esp, 0x24"),
        ],
        # CV VM exit
        [
            ("add", "esp, 0x24"),
            ("popad", ""),
            ("ret", ""),
        ],
        # CV opcode fetch (LODSB + XLAT = fetch + decrypt in one step)
        [
            ("lodsb", ""),
            ("xlat", ""),
        ],
        # CV dispatch: XLAT decoded opcode → handler table
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("movzx", "eax, al"),
            ("jmp", "dword ptr [edx+eax*4]"),
        ],
    ],
    "comparison": [
        # CV CMP
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("cmp", "ecx, [esp+eax*4]"),
            ("pushfd", ""),
            ("pop", "dword ptr [esp+0x20]"),
        ],
        # CV TEST
        [
            ("lodsb", ""),
            ("xlat", ""),
            ("mov", "ecx, [esp+eax*4]"),
            ("lodsb", ""),
            ("xlat", ""),
            ("test", "ecx, [esp+eax*4]"),
            ("pushfd", ""),
            ("pop", "dword ptr [esp+0x20]"),
        ],
    ],
    "crypto": [
        # CV key update (ror+xor chain)
        [
            ("ror", "ebp, 7"),
            ("xor", "ebp, eax"),
            ("add", "ebp, ecx"),
        ],
        # CV bswap-based decrypt
        [
            ("lodsb", ""),
            ("bswap", "eax"),
            ("xor", "eax, ebp"),
            ("ror", "ebp, 3"),
        ],
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# Multi-protector synthetic data generation
# ═══════════════════════════════════════════════════════════════════════════

# Protector names used as metadata labels in synthetic data.
PROTECTOR_VMPROTECT = "vmprotect"
PROTECTOR_THEMIDA = "themida"
PROTECTOR_CV = "code_virtualizer"

_PROTECTOR_TEMPLATE_MAP: Dict[str, Dict[str, List[List[tuple[str, str]]]]] = {
    PROTECTOR_VMPROTECT: _HANDLER_TEMPLATES,
    PROTECTOR_THEMIDA: _THEMIDA_HANDLER_TEMPLATES,
    PROTECTOR_CV: _CV_HANDLER_TEMPLATES,
}


def _apply_jitter(
    body: List[tuple[str, str]],
    rng: _random.Random,
    *,
    nop_probability: float = 0.5,
    max_nops: int = 2,
    reg_rename: bool = True,
) -> List[tuple[str, str]]:
    """Apply realistic jitter transformations to a handler template.

    Jitter includes:
    - Random NOP insertion (0-*max_nops* instructions)
    - Register renaming (swap equivalent register names for diversity)
    - Dead-code insertion (push/pop pairs that cancel out)

    Returns a new list; does not mutate the original.
    """
    result = list(body)

    # NOP insertion
    if rng.random() < nop_probability:
        n_nops = rng.randint(0, max_nops)
        for _ in range(n_nops):
            pos = rng.randint(0, len(result))
            result.insert(pos, ("nop", ""))

    # Register renaming — swap register pairs that don't change semantics
    if reg_rename and rng.random() < 0.3:
        # Choose a rename pair for 64-bit or 32-bit contexts
        rename_pairs_64 = [
            ("rax", "rdx"), ("rcx", "r8"), ("r9", "r10"), ("r11", "r12"),
        ]
        rename_pairs_32 = [
            ("eax", "edx"), ("ecx", "ebx"),
        ]
        # Detect register width from body
        body_str = " ".join(ops for _, ops in result)
        if "rax" in body_str or "r8" in body_str:
            a, b = rng.choice(rename_pairs_64)
        else:
            a, b = rng.choice(rename_pairs_32)
        # Only rename if both registers appear (to create meaningful variation)
        if a in body_str and b not in body_str:
            result = [(m, ops.replace(a, b)) for m, ops in result]

    # Dead-code insertion (push/pop pair)
    if rng.random() < 0.15:
        dead_reg = rng.choice(["eax", "ecx", "edx", "ebx"])
        pos = rng.randint(0, max(len(result) - 1, 0))
        result.insert(pos, ("push", dead_reg))
        result.insert(pos + 1, ("pop", dead_reg))

    return result


def generate_multi_protector_data(
    n_per_category: int = 50,
    *,
    seed: int = 42,
    protectors: Sequence[str] | None = None,
    jitter: bool = True,
) -> List[Dict[str, Any]]:
    """Generate synthetic handler data for multiple protectors.

    Each generated handler dict includes a ``protector`` key indicating
    the source protector, in addition to the standard ``category``,
    ``instructions``, ``mnemonics`` keys.

    Parameters
    ----------
    n_per_category : int
        Number of handlers per category per protector.
    protectors : sequence of str or None
        Which protectors to generate data for.  Defaults to all three
        (VMProtect, Themida, Code Virtualizer).
    jitter : bool
        Apply realistic jitter (NOP insertion, register renaming,
        dead-code insertion).

    Returns
    -------
    list of dict
        Shuffled list of handler dicts ready for feature extraction.
    """
    rng = _random.Random(seed)
    if protectors is None:
        protectors = list(_PROTECTOR_TEMPLATE_MAP.keys())

    handlers: List[Dict[str, Any]] = []

    for protector in protectors:
        templates = _PROTECTOR_TEMPLATE_MAP.get(protector)
        if templates is None:
            logger.warning("Unknown protector %r, skipping", protector)
            continue

        for cat, cat_templates in templates.items():
            for _ in range(n_per_category):
                tmpl = rng.choice(cat_templates)
                body = list(tmpl)

                if jitter:
                    body = _apply_jitter(body, rng)
                else:
                    body = list(body)

                # Build instruction dicts
                instructions: List[Dict[str, str]] = []
                mnemonics: List[str] = []
                for mnem, ops in body:
                    instructions.append({"mnemonic": mnem, "operands": ops})
                    mnemonics.append(mnem.lower())

                _cat_to_op = {
                    "arithmetic": "vm_add",
                    "bitwise": "vm_xor",
                    "stack": "vm_push",
                    "memory": "vm_load",
                    "control_flow": "vm_jmp",
                    "vm_control": "vm_enter",
                    "comparison": "vm_cmp",
                    "crypto": "vm_decrypt",
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
                    "protector": protector,
                })

    rng.shuffle(handlers)
    return handlers


def train_and_save_model(
    output_path: str = "data/models/pretrained/handler_classifier.pkl",
    *,
    n_per_category: int = 80,
    seed: int = 42,
    algorithm: str = "auto",
    n_estimators: int = 200,
) -> tuple[VMHandlerModel, TrainingResult, List[tuple[str, float]]]:
    """End-to-end: generate multi-protector data, train, and save.

    Unlike :func:`train_full_pipeline`, this function generates data
    from all three protector families (VMProtect, Themida, Code
    Virtualizer) and saves both the model and a JSON training report.

    Parameters
    ----------
    output_path : str
        Where to save the trained model artifact.
    n_per_category : int
        Handlers per category per protector (total ≈ 3×9×n).
    algorithm : str
        ``"auto"``, ``"rf"``, or ``"gb"``.

    Returns
    -------
    tuple of (VMHandlerModel, TrainingResult, feature_importances)
    """
    import json as _json
    from pathlib import Path as _Path

    logger.info(
        "Generating multi-protector synthetic data (n_per_cat=%d, seed=%d)",
        n_per_category, seed,
    )
    handlers = generate_multi_protector_data(
        n_per_category=n_per_category, seed=seed, jitter=True,
    )
    logger.info("Generated %d synthetic handlers across 3 protectors", len(handlers))

    features, labels = prepare_extended_training_data(handlers, label_key="category")
    names = EXTENDED_FEATURE_NAMES

    model = VMHandlerModel()
    trainer = ModelTrainer(model)
    result = trainer.train(
        features, labels,
        n_estimators=n_estimators,
        algorithm=algorithm,
    )

    imp = feature_importance(model, feature_names=names, top_n=20)

    if model.is_trained:
        model.save(output_path, feature_names=list(names))
        logger.info("Saved trained model to %s", output_path)

        # Save training report alongside model
        report_path = str(_Path(output_path).with_suffix(".report.json"))
        report = {
            "model_path": output_path,
            "accuracy": result.accuracy,
            "n_samples": len(handlers),
            "n_features": len(names),
            "algorithm": result.metrics.get("algorithm", algorithm),
            "n_estimators": n_estimators,
            "protectors": list(_PROTECTOR_TEMPLATE_MAP.keys()),
            "categories": sorted(set(labels)),
            "top_features": [
                {"name": n, "importance": round(v, 4)} for n, v in imp
            ],
        }
        _Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as fh:
            _json.dump(report, fh, indent=2)
        logger.info("Saved training report to %s", report_path)

    return model, result, imp
