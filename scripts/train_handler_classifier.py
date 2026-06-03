#!/usr/bin/env python3
"""Train + evaluate the VM-handler ML classifier on synthetic data.

Generates a large, obfuscation-augmented synthetic corpus, trains a
RandomForest, reports held-out metrics, and demonstrates the
heuristic+ML **ensemble**.  Run::

    python scripts/train_handler_classifier.py [--n-per-category 200] [--save PATH]

Requires scikit-learn.
"""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-per-category", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--save", default="", help="pickle the trained RF to this path")
    args = ap.parse_args()

    try:
        import numpy as np
        from sklearn.model_selection import train_test_split
    except ImportError:
        print("scikit-learn is required: pip install scikit-learn", file=sys.stderr)
        return 2

    from dragonslayer.ml.model import VMHandlerModel
    from dragonslayer.ml.pipeline import EXTENDED_FEATURE_NAMES
    from dragonslayer.ml.synthetic import (
        PROTECTORS,
        featurize,
        generate_dataset,
        train_and_evaluate,
    )

    ds = generate_dataset(n_per_category=args.n_per_category, seed=args.seed)
    print(f"Synthetic corpus: {len(ds)} handlers ({args.n_per_category}/category "
          f"x 12 categories x {len(PROTECTORS)} protectors)")
    print(f"Protector flavours: {', '.join(PROTECTORS)}\n")

    m = train_and_evaluate(ds, extended=True, seed=args.seed)
    print(f"RandomForest (146-D features) — train={m['n_train']}  test={m['n_test']}")
    print(f"  accuracy = {m['accuracy']:.4f}    macro-F1 = {m['macro_f1']:.4f}\n")

    print("  per-category (precision / recall / f1 / support):")
    for lbl in m["labels"]:
        c = m["per_class"][lbl]
        print(f"    {lbl:14s}  {c['precision']:.2f} / {c['recall']:.2f} / "
              f"{c['f1']:.2f}   n={c['support']}")

    print("\n  top features:")
    for name, imp in m["top_features"]:
        print(f"    {name:22s} {imp:.4f}")

    # ---- Ensemble: RandomForest + rule-based heuristic --------------------
    X, y = featurize(ds, extended=True)
    X = np.asarray(X, dtype=float)
    X_tr, X_te, y_tr, y_te, d_tr, d_te = train_test_split(
        X, y, ds, test_size=0.25, random_state=args.seed, stratify=y,
    )
    from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier

    def acc(pred: list[str]) -> float:
        return sum(p == t for p, t in zip(pred, y_te, strict=False)) / len(y_te)

    # Weak rule-based baseline (same category space) — shows why ML is needed.
    heur_model = VMHandlerModel()
    heur_pred = [
        heur_model.predict(
            {"values": list(row), "names": list(EXTENDED_FEATURE_NAMES)}
        ).label
        for row in X_te
    ]

    # Soft-voting ensemble of three diverse learners (averaged probabilities).
    rf = m["model"]
    et = ExtraTreesClassifier(
        n_estimators=200, n_jobs=-1, random_state=args.seed,
    ).fit(X_tr, y_tr)
    gb = GradientBoostingClassifier(random_state=args.seed).fit(X_tr, y_tr)
    classes = list(rf.classes_)
    soft = rf.predict_proba(X_te) + et.predict_proba(X_te) + gb.predict_proba(X_te)
    rf_pred = [classes[i] for i in rf.predict_proba(X_te).argmax(axis=1)]
    ens_pred = [classes[i] for i in soft.argmax(axis=1)]

    print("\n  ensemble comparison (held-out accuracy):")
    print(f"    rule-based scorer only     : {acc(heur_pred):.4f}")
    print(f"    RandomForest only          : {acc(rf_pred):.4f}")
    print(f"    ExtraTrees only            : {et.score(X_te, y_te):.4f}")
    print(f"    GradientBoosting only      : {gb.score(X_te, y_te):.4f}")
    print(f"    soft-vote ensemble (3 ML)  : {acc(ens_pred):.4f}")
    print("\n  (cross-handler consistency voting is applied at devirt time via "
          "handler_clustering.refine_opcode_table)")

    if args.save:
        import pickle

        with open(args.save, "wb") as fh:
            pickle.dump(m["model"], fh)
        print(f"\nSaved RandomForest to {args.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
