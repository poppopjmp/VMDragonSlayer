"""
Model Evaluation Utilities
===========================

Precision, recall, F1, and confusion-matrix evaluation for VM handler
classifiers against a ground-truth label set.

Usage::

    from dragonslayer.ml.evaluate import (
        evaluate_model, load_ground_truth, EvaluationReport,
    )

    gt = load_ground_truth()                     # loads default JSON
    report = evaluate_model(model, gt)
    print(report.summary())
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import BaseModel, PredictionResult
from .taxonomy import CANONICAL_CATEGORIES, canonicalize

logger = logging.getLogger(__name__)

# Default ground-truth file relative to the repository root.
_DEFAULT_GT_PATH = Path(__file__).resolve().parents[2] / "data" / "ground_truth" / "handler_labels.json"


# ---------------------------------------------------------------------------
# Ground-truth container
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthEntry:
    """One labelled handler sample."""

    id: str
    label: str
    handler_bytes_hex: str = ""
    symbolic_summary: dict[str, Any] | None = None
    description: str = ""

    def to_features(self) -> dict[str, Any]:
        """Build a feature dict suitable for :meth:`BaseModel.predict`."""
        features: dict[str, Any] = {}
        if self.symbolic_summary:
            features["symbolic_summary"] = self.symbolic_summary
        if self.handler_bytes_hex:
            features["handler_bytes_hex"] = self.handler_bytes_hex
        return features


def load_ground_truth(
    path: str | None = None,
) -> list[GroundTruthEntry]:
    """Load ground-truth entries from *path* (or the default JSON)."""
    p = Path(path) if path else _DEFAULT_GT_PATH
    if not p.exists():
        raise FileNotFoundError(f"Ground-truth file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    entries = []
    for item in data.get("handlers", []):
        entries.append(GroundTruthEntry(
            id=item["id"],
            label=canonicalize(item["label"]),
            handler_bytes_hex=item.get("handler_bytes_hex", ""),
            symbolic_summary=item.get("symbolic_summary"),
            description=item.get("description", ""),
        ))
    return entries


# ---------------------------------------------------------------------------
# Per-class & aggregate metrics
# ---------------------------------------------------------------------------

@dataclass
class ClassMetrics:
    """Precision / recall / F1 for a single class."""

    label: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def support(self) -> int:
        return self.tp + self.fn


@dataclass
class EvaluationReport:
    """Full evaluation report."""

    per_class: dict[str, ClassMetrics] = field(default_factory=dict)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    predictions: list[tuple[str, str, float]] = field(default_factory=list)
    total: int = 0
    correct: int = 0

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def macro_precision(self) -> float:
        vals = [m.precision for m in self.per_class.values() if m.support > 0]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def macro_recall(self) -> float:
        vals = [m.recall for m in self.per_class.values() if m.support > 0]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def macro_f1(self) -> float:
        vals = [m.f1 for m in self.per_class.values() if m.support > 0]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def weighted_f1(self) -> float:
        total_support = sum(m.support for m in self.per_class.values())
        if total_support == 0:
            return 0.0
        return sum(
            m.f1 * m.support for m in self.per_class.values()
        ) / total_support

    def summary(self) -> str:
        """Human-readable summary string."""
        lines = [
            f"Accuracy:       {self.accuracy:.4f}  ({self.correct}/{self.total})",
            f"Macro-F1:       {self.macro_f1:.4f}",
            f"Weighted-F1:    {self.weighted_f1:.4f}",
            "",
            f"{'Category':<16} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Sup':>5}",
            "-" * 45,
        ]
        for cat in CANONICAL_CATEGORIES:
            m = self.per_class.get(cat)
            if m and m.support > 0:
                lines.append(
                    f"{cat:<16} {m.precision:>6.2f} {m.recall:>6.2f} "
                    f"{m.f1:>6.2f} {m.support:>5d}"
                )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": round(self.accuracy, 4),
            "macro_precision": round(self.macro_precision, 4),
            "macro_recall": round(self.macro_recall, 4),
            "macro_f1": round(self.macro_f1, 4),
            "weighted_f1": round(self.weighted_f1, 4),
            "total": self.total,
            "correct": self.correct,
            "per_class": {
                k: {
                    "precision": round(v.precision, 4),
                    "recall": round(v.recall, 4),
                    "f1": round(v.f1, 4),
                    "support": v.support,
                }
                for k, v in self.per_class.items()
                if v.support > 0
            },
        }


# ---------------------------------------------------------------------------
# Evaluation driver
# ---------------------------------------------------------------------------

def evaluate_model(
    model: BaseModel,
    ground_truth: Sequence[GroundTruthEntry],
) -> EvaluationReport:
    """Run *model* against *ground_truth* and compute metrics.

    Returns an :class:`EvaluationReport` with per-class P/R/F1, accuracy,
    macro-averaged F1, and a confusion matrix.
    """
    # Initialise per-class metrics for every canonical category.
    per_class: dict[str, ClassMetrics] = {
        c: ClassMetrics(label=c) for c in CANONICAL_CATEGORIES
    }
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: Counter())  # type: ignore[arg-type]
    predictions: list[tuple[str, str, float]] = []
    correct = 0

    for entry in ground_truth:
        true_label = canonicalize(entry.label)
        features = entry.to_features()
        try:
            pred: PredictionResult = model.predict(features)
            pred_label = canonicalize(pred.label)
            conf = pred.confidence
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
            logger.debug("Model prediction failed for %s: %s", entry.id, exc)
            pred_label = "unknown"
            conf = 0.0

        predictions.append((true_label, pred_label, conf))
        confusion[true_label][pred_label] += 1

        if pred_label == true_label:
            correct += 1
            per_class[true_label].tp += 1
        else:
            per_class[true_label].fn += 1
            per_class[pred_label].fp += 1

    return EvaluationReport(
        per_class=per_class,
        confusion=dict(confusion),
        predictions=predictions,
        total=len(ground_truth),
        correct=correct,
    )
