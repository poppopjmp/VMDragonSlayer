"""
Active Learning — Uncertainty Sampling & Feedback Loop
======================================================

Infrastructure for identifying low-confidence ML predictions, queuing
them for human (analyst) review, and ingesting corrections back into
the training pipeline.

Key concepts
------------
* **UncertainSample** — a prediction that the model is unsure about.
* **FeedbackStore** — persistent store for analyst corrections.
* **select_uncertain_samples()** — top-k uncertain predictions using
  entropy, margin, or least-confidence strategies.
* **ingest_feedback()** — record a corrected label.
* **export_training_set()** — merge feedback into training data for
  incremental retraining.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class UncertaintyStrategy(str, Enum):
    """Strategy for selecting uncertain samples."""
    ENTROPY = "entropy"
    LEAST_CONFIDENCE = "least_confidence"
    MARGIN = "margin"


@dataclass
class UncertainSample:
    """A prediction the model is uncertain about.

    Attributes
    ----------
    sample_id : str
        Unique identifier (e.g. ``"handler_0x401000"``).
    features : dict
        Feature vector or summary used for prediction.
    predicted_label : str
        Model's predicted category.
    confidence : float
        Model's confidence score (0–1).
    entropy : float
        Shannon entropy of the prediction distribution.
    margin : float
        Difference between top-2 class probabilities.
    class_probabilities : dict
        Full class → probability mapping.
    metadata : dict
        Extra context (address, protector, source file, …).
    """
    sample_id: str = ""
    features: dict[str, Any] = field(default_factory=dict)
    predicted_label: str = ""
    confidence: float = 0.0
    entropy: float = 0.0
    margin: float = 0.0
    class_probabilities: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FeedbackEntry:
    """A single analyst correction.

    Attributes
    ----------
    sample_id : str
        Which sample was corrected.
    corrected_label : str
        The analyst's chosen ground-truth label.
    analyst_id : str
        Who provided the correction.
    timestamp : float
        Unix timestamp of the correction.
    original_label : str
        What the model originally predicted.
    notes : str
        Free-form analyst notes.
    """
    sample_id: str = ""
    corrected_label: str = ""
    analyst_id: str = ""
    timestamp: float = 0.0
    original_label: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Uncertainty computations
# ---------------------------------------------------------------------------


def compute_entropy(probabilities: Sequence[float]) -> float:
    """Shannon entropy of a probability distribution.

    Parameters
    ----------
    probabilities : sequence of float
        Class probabilities (should sum to ~1.0).

    Returns
    -------
    float
        Entropy in nats.  Higher = more uncertain.
    """
    total = 0.0
    for p in probabilities:
        if p > 0:
            total -= p * math.log(p)
    return total


def compute_margin(probabilities: Sequence[float]) -> float:
    """Margin between the two highest class probabilities.

    A small margin indicates high uncertainty (model can't decide).

    Returns
    -------
    float
        Margin (0–1).  Lower = more uncertain.
    """
    if len(probabilities) < 2:
        return 1.0
    sorted_probs = sorted(probabilities, reverse=True)
    return sorted_probs[0] - sorted_probs[1]


# ---------------------------------------------------------------------------
# Sample selection
# ---------------------------------------------------------------------------


def select_uncertain_samples(
    predictions: list[dict[str, Any]],
    *,
    strategy: UncertaintyStrategy | str = UncertaintyStrategy.ENTROPY,
    k: int = 10,
    confidence_threshold: float = 0.8,
) -> list[UncertainSample]:
    """Select the top-*k* most uncertain predictions.

    Parameters
    ----------
    predictions : list of dict
        Each dict must contain at minimum ``sample_id``, ``predicted_label``,
        ``confidence``.  Optionally ``class_probabilities`` (dict of
        class → prob) and ``features``.
    strategy : UncertaintyStrategy
        Ranking method: ``entropy`` (max entropy first),
        ``least_confidence`` (min confidence first), or
        ``margin`` (min margin between top-2 classes first).
    k : int
        Number of uncertain samples to return.
    confidence_threshold : float
        Only consider predictions below this confidence.

    Returns
    -------
    list of UncertainSample
        Up to *k* samples, ordered most-uncertain-first.
    """
    if isinstance(strategy, str):
        try:
            strategy = UncertaintyStrategy(strategy)
        except ValueError:
            valid = [s.value for s in UncertaintyStrategy]
            raise ValueError(
                f"Unknown uncertainty strategy: {strategy!r}. "
                f"Valid strategies: {valid}"
            ) from None

    candidates: list[UncertainSample] = []
    for pred in predictions:
        conf = pred.get("confidence", 1.0)
        if conf >= confidence_threshold:
            continue

        probs = pred.get("class_probabilities", {})
        prob_values = list(probs.values()) if probs else [conf, 1.0 - conf]

        entropy = compute_entropy(prob_values)
        margin = compute_margin(prob_values)

        sample = UncertainSample(
            sample_id=pred.get("sample_id", ""),
            features=pred.get("features", {}),
            predicted_label=pred.get("predicted_label", ""),
            confidence=conf,
            entropy=entropy,
            margin=margin,
            class_probabilities=probs,
            metadata=pred.get("metadata", {}),
        )
        candidates.append(sample)

    # Sort by strategy
    if strategy == UncertaintyStrategy.ENTROPY:
        candidates.sort(key=lambda s: s.entropy, reverse=True)
    elif strategy == UncertaintyStrategy.LEAST_CONFIDENCE:
        candidates.sort(key=lambda s: s.confidence)
    elif strategy == UncertaintyStrategy.MARGIN:
        candidates.sort(key=lambda s: s.margin)

    return candidates[:k]


# ---------------------------------------------------------------------------
# Feedback Store
# ---------------------------------------------------------------------------


class FeedbackStore:
    """Persistent store for analyst corrections.

    Supports JSON-file and in-memory backends.  The JSON backend
    writes atomically (write + rename) so partial writes are safe.

    Parameters
    ----------
    path : Path | str | None
        File path for JSON persistence.  ``None`` → in-memory only.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._entries: list[FeedbackEntry] = []
        if self._path and self._path.exists():
            self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        """Load entries from disk."""
        if self._path is None:
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self._entries = [FeedbackEntry(**e) for e in raw]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Could not load feedback store: %s", exc)
            self._entries = []

    def _save(self) -> None:
        """Persist entries to disk (atomic write)."""
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps([e.to_dict() for e in self._entries], indent=2),
            encoding="utf-8",
        )
        tmp.replace(self._path)

    # -- public API ----------------------------------------------------------

    def ingest(
        self,
        sample_id: str,
        corrected_label: str,
        *,
        analyst_id: str = "",
        original_label: str = "",
        notes: str = "",
    ) -> FeedbackEntry:
        """Record an analyst correction."""
        entry = FeedbackEntry(
            sample_id=sample_id,
            corrected_label=corrected_label,
            analyst_id=analyst_id,
            timestamp=time.time(),
            original_label=original_label,
            notes=notes,
        )
        self._entries.append(entry)
        self._save()
        return entry

    @property
    def entries(self) -> list[FeedbackEntry]:
        """All stored feedback entries."""
        return list(self._entries)

    def count(self) -> int:
        return len(self._entries)

    def get_corrections(self) -> dict[str, str]:
        """Return ``{sample_id: corrected_label}`` for the latest corrections.

        If a sample was corrected multiple times, the latest wins.
        """
        corrections: dict[str, str] = {}
        for entry in self._entries:
            corrections[entry.sample_id] = entry.corrected_label
        return corrections

    def clear(self) -> None:
        """Remove all entries."""
        self._entries.clear()
        self._save()


# ---------------------------------------------------------------------------
# Training-data merge
# ---------------------------------------------------------------------------


def export_training_set(
    feedback: FeedbackStore,
    existing_labels: dict[str, str],
) -> dict[str, str]:
    """Merge analyst corrections into an existing label set.

    Corrections from the feedback store **override** existing labels.

    Parameters
    ----------
    feedback : FeedbackStore
        Store containing analyst corrections.
    existing_labels : dict
        ``{sample_id: label}`` from currently known ground truth.

    Returns
    -------
    dict
        Merged ``{sample_id: label}`` with corrections applied.
    """
    merged = dict(existing_labels)
    merged.update(feedback.get_corrections())
    return merged
