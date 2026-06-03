"""Train + evaluate the ML handler classifier on synthetic data.

Proves the ML path actually learns: a RandomForest trained on the
obfuscation-augmented synthetic corpus must classify held-out handlers
across all 12 canonical categories and 4 protector flavours with high
accuracy.  Skipped automatically when scikit-learn is unavailable.
"""
from __future__ import annotations

import importlib.util

import pytest

from dragonslayer.ml.synthetic import PROTECTORS, generate_dataset

sklearn_only = pytest.mark.skipif(
    importlib.util.find_spec("sklearn") is None, reason="needs scikit-learn",
)


def test_synthetic_dataset_is_balanced_and_diverse():
    ds = generate_dataset(n_per_category=20)
    from collections import Counter

    cats = Counter(h["category"] for h in ds)
    prots = Counter(h["protector"] for h in ds)
    # 12 canonical categories present, evenly sized, across all protectors.
    assert len(cats) >= 11
    assert len(set(cats.values())) == 1  # balanced
    assert set(prots) == set(PROTECTORS)
    # Obfuscation produced variety (handlers of differing lengths).
    lengths = {len(h["mnemonics"]) for h in ds}
    assert len(lengths) > 5


@sklearn_only
def test_random_forest_learns_handler_categories():
    from dragonslayer.ml.synthetic import train_and_evaluate

    # ~3.8k samples keeps the test quick while staying representative.
    metrics = train_and_evaluate(n_per_category=80, extended=True, seed=7)
    assert metrics["n_train"] > 2000 and metrics["n_test"] > 700
    assert metrics["accuracy"] >= 0.88, f"accuracy too low: {metrics['accuracy']}"
    assert metrics["macro_f1"] >= 0.85, f"macro-F1 too low: {metrics['macro_f1']}"
    # Every category should be learned to at least a usable degree.
    worst = min(v["f1"] for v in metrics["per_class"].values())
    assert worst >= 0.6, f"a category collapsed: {metrics['per_class']}"


@sklearn_only
def test_extended_features_beat_compact_features():
    """The 146-D bigram features should out-perform the compact 17-D set on
    the obfuscated corpus (justifies the richer feature extractor)."""
    from dragonslayer.ml.synthetic import train_and_evaluate

    ds = generate_dataset(n_per_category=80, seed=7)
    compact = train_and_evaluate(ds, extended=False, seed=7)
    extended = train_and_evaluate(ds, extended=True, seed=7)
    assert extended["accuracy"] >= compact["accuracy"]
