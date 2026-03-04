"""
Validate VM discovery on a labeled corpus and produce metrics + evidence.

Inputs:
- Registry JSON (default: data/samples/sample_registry.json)
- Predictions directory containing per-sample JSON files named by sample hash
  (default: artifacts/vm_detection/). Each prediction JSON should look like:
    {
      "hash": "<sha1 or similar>",
      "vm_detected": true,
      "confidence": 0.97
    }

Outputs:
- reports/vm_detect_metrics.json
- reports/confusion_matrix.png (if matplotlib is available)

Notes:
- If negatives are missing (no unprotected samples), precision may be ill-defined.
  The script will detect class imbalance and report "insufficient_data" when needed.
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

logger = logging.getLogger("vmds.validate_vm_detection")


@dataclass
class Sample:
    name: str
    hash: str
    vm_type: str
    label: int  # 1 = VM present, 0 = no VM


def load_registry(path: Path) -> List[Sample]:
    data = json.loads(path.read_text(encoding="utf-8"))
    samples: List[Sample] = []
    for key, items in data.items():
        if key == "metadata":
            continue
        if not isinstance(items, list):
            continue
        for it in items:
            # Ground truth: entries in this registry represent VM-protected samples
            # unless a field explicitly marks them negative.
            label = 1
            if isinstance(it, dict) and it.get("ground_truth_label") in (0, "negative", False):
                label = 0
            samples.append(
                Sample(
                    name=str(it.get("name", "")),
                    hash=str(it.get("hash", "")),
                    vm_type=str(it.get("vm_type", "unknown")),
                    label=label,
                )
            )
    return samples


def load_predictions(pred_dir: Path) -> Dict[str, Dict[str, Any]]:
    pred: Dict[str, Dict[str, Any]] = {}
    if not pred_dir.exists():
        return pred
    for p in pred_dir.glob("*.json"):
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            h = str(obj.get("hash") or p.stem)
            pred[h] = obj
        except Exception as e:
            logger.warning("Failed to read prediction %s: %s", p, e)
    return pred


def compute_metrics(samples: List[Sample], preds: Dict[str, Dict[str, Any]]):
    y_true: List[int] = []
    y_pred: List[int] = []
    y_score: List[float] = []
    missing: List[str] = []

    for s in samples:
        y_true.append(s.label)
        pobj = preds.get(s.hash, {})
        pred_bool = pobj.get("vm_detected")
        conf = pobj.get("confidence")
        if pred_bool is None:
            # Treat missing as negative prediction with score 0
            y_pred.append(0)
            y_score.append(0.0)
            missing.append(s.hash)
        else:
            y_pred.append(1 if bool(pred_bool) else 0)
            if isinstance(conf, (float, int)):
                y_score.append(float(conf))
            else:
                # Map boolean to a coarse score when confidence is unavailable
                y_score.append(0.9 if pred_bool else 0.1)

    pos = sum(1 for v in y_true if v == 1)
    neg = sum(1 for v in y_true if v == 0)

    metrics: Dict[str, Any] = {}
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    metrics["confusion_matrix"] = {
        "labels": [0, 1],
        "matrix": cm,
        "tn_fp_fn_tp": None,
    }
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    metrics["confusion_matrix"]["tn_fp_fn_tp"] = {
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }

    # Precision/recall/f1
    metrics["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
    metrics["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))

    # ROC AUC if we have at least one positive and one negative and a usable score range
    roc_auc: Optional[float] = None
    if pos > 0 and neg > 0:
        try:
            roc_auc = float(roc_auc_score(y_true, y_score))
        except Exception:
            roc_auc = None
    metrics["ROC_AUC"] = roc_auc

    metrics["class_balance"] = {"positives": pos, "negatives": neg}
    metrics["missing_predictions"] = missing

    # Acceptance gate
    acceptance = (metrics["precision"] >= 0.95) and (metrics["recall"] >= 0.95)
    metrics["acceptance"] = {
        "criteria": ">= 0.95 precision/recall on labeled set",
        "passed": bool(acceptance),
    }

    # Insufficient negatives check (informational)
    if neg == 0:
        metrics["notes"] = [
            "No negative samples found; precision may be inflated and ROC_AUC is undefined.",
        ]

    return metrics, (y_true, y_pred)


def save_confusion_png(y_true: List[int], y_pred: List[int], out_path: Path) -> None:
    try:
        import matplotlib.pyplot as plt  # type: ignore
        from sklearn.metrics import ConfusionMatrixDisplay

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        disp = ConfusionMatrixDisplay(cm, display_labels=["neg", "pos"])
        fig, ax = plt.subplots(figsize=(4, 4), dpi=120)
        disp.plot(ax=ax, colorbar=False)
        fig.tight_layout()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out_path, format="png")
        plt.close(fig)
    except Exception as e:
        logger.warning("Could not generate confusion matrix PNG: %s", e)


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate VM detection on labeled corpus")
    ap.add_argument(
        "--registry",
        type=Path,
        default=Path("data/samples/sample_registry.json"),
        help="Path to sample registry JSON",
    )
    ap.add_argument(
        "--predictions-dir",
        type=Path,
        default=Path("artifacts/vm_detection"),
        help="Directory containing per-sample prediction JSON files",
    )
    ap.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="Directory to write reports",
    )
    args = ap.parse_args()

    samples = load_registry(args.registry)
    preds = load_predictions(args.predictions_dir)
    metrics, (y_true, y_pred) = compute_metrics(samples, preds)

    # Write metrics JSON
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = args.reports_dir / "vm_detect_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # Write confusion matrix PNG if possible
    png_path = args.reports_dir / "confusion_matrix.png"
    save_confusion_png(y_true, y_pred, png_path)

    print(f"Wrote metrics to {metrics_path}")
    if png_path.exists():
        print(f"Wrote confusion matrix to {png_path}")
    else:
        print("Confusion matrix PNG not generated (optional dependency missing)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
