#!/usr/bin/env python3
"""
Evaluate VMHandlerModel against ground-truth labels.
=====================================================

Reads labelled samples from ``data/ground_truth/handler_labels.json``
and computes per-category precision, recall, F1 plus global accuracy.

Usage::

    python -m tools.evaluate_model
    python tools/evaluate_model.py               # from repo root
    python tools/evaluate_model.py --gt data/ground_truth/handler_labels.json

Output is a Markdown-compatible table printed to stdout plus a JSON
``evaluation_results.json`` written to ``evidence/``.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure the repo root is importable when invoked directly
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from dragonslayer.ml.model import VMHandlerModel, PredictionResult  # noqa: E402

logger = logging.getLogger(__name__)


def load_ground_truth(path: Path) -> List[Dict[str, Any]]:
    """Load ground-truth JSON.

    Supports two formats:
    1. Top-level list of ``{"label": ..., "features": {...}}``
    2. Object with ``"samples"`` key containing the list.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("samples", "handlers"):
            if key in raw:
                return raw[key]
    raise ValueError(f"Unrecognised ground-truth format in {path}")


def evaluate(
    model: VMHandlerModel,
    samples: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Run model on every sample and compute metrics."""
    y_true: List[str] = []
    y_pred: List[str] = []
    confidences: List[float] = []

    for sample in samples:
        label = sample.get("label") or sample.get("category", "unknown")
        features = sample.get("features", {})
        pred: PredictionResult = model.predict(features)
        y_true.append(label)
        y_pred.append(pred.label)
        confidences.append(pred.confidence)

    # Per-category metrics
    labels = sorted(set(y_true) | set(y_pred))
    per_cat: Dict[str, Dict[str, Any]] = {}
    for cat in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cat and p == cat)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cat and p == cat)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cat and p != cat)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
               if (precision + recall) else 0.0)
        per_cat[cat] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "support": sum(1 for t in y_true if t == cat),
        }

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / len(y_true) if y_true else 0.0
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "total_samples": len(y_true),
        "correct": correct,
        "mean_confidence": round(avg_confidence, 4),
        "per_category": per_cat,
    }


def print_report(results: Dict[str, Any]) -> None:
    """Print a Markdown-friendly report to stdout."""
    print(f"\n## Model Evaluation Report")
    print(f"- **Accuracy**: {results['accuracy']:.1%}"
          f"  ({results['correct']}/{results['total_samples']})")
    print(f"- **Mean confidence**: {results['mean_confidence']:.3f}")
    print()
    print("| Category | Precision | Recall | F1 | Support |")
    print("|----------|-----------|--------|-----|---------|")
    for cat, m in sorted(results["per_category"].items()):
        print(f"| {cat:<12s} | {m['precision']:.3f}     "
              f"| {m['recall']:.3f}  | {m['f1']:.3f} | {m['support']}       |")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate VMHandlerModel")
    parser.add_argument(
        "--gt", type=Path,
        default=_REPO / "data" / "ground_truth" / "handler_labels.json",
        help="Path to ground-truth JSON",
    )
    parser.add_argument(
        "--output", type=Path,
        default=_REPO / "evidence" / "evaluation_results.json",
        help="Path for JSON output",
    )
    args = parser.parse_args()

    samples = load_ground_truth(args.gt)
    model = VMHandlerModel()
    results = evaluate(model, samples)
    print_report(results)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Saved results to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
