"""
Ensemble Classifiers
====================

Combine predictions from multiple :class:`~dragonslayer.ml.model.BaseModel`
instances to improve classification accuracy.

Stub — real ensemble strategies require trained component models.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from .model import BaseModel, PredictionResult

logger = logging.getLogger(__name__)


class EnsembleClassifier:
    """Run multiple models and aggregate their predictions.

    By default uses majority vote.  For a weighted scheme see
    :class:`WeightedEnsemble`.
    """

    def __init__(self, models: Sequence[BaseModel] | None = None) -> None:
        self._models: List[BaseModel] = list(models) if models else []

    def add_model(self, model: BaseModel) -> None:
        self._models.append(model)

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        """Majority-vote prediction from all component models."""
        if not self._models:
            raise NotImplementedError(
                "EnsembleClassifier has no component models — "
                "add trained models via add_model()"
            )
        results = [m.predict(features) for m in self._models]
        # Majority vote
        from collections import Counter
        votes = Counter(r.label for r in results)
        winner, count = votes.most_common(1)[0]
        return PredictionResult(
            label=winner,
            confidence=count / len(results),
            metadata={"votes": dict(votes), "n_models": len(results)},
        )


class WeightedEnsemble(EnsembleClassifier):
    """Weighted combination of model predictions."""

    def __init__(
        self,
        models: Sequence[BaseModel] | None = None,
        weights: Sequence[float] | None = None,
    ) -> None:
        super().__init__(models)
        self._weights = list(weights) if weights else []

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        if not self._models:
            raise NotImplementedError(
                "WeightedEnsemble has no component models"
            )
        results = [m.predict(features) for m in self._models]
        weights = self._weights or [1.0] * len(results)
        if len(weights) != len(results):
            raise ValueError(
                f"Weight count ({len(weights)}) != model count ({len(results)})"
            )
        # Weighted vote
        from collections import defaultdict
        label_scores: Dict[str, float] = defaultdict(float)
        for r, w in zip(results, weights):
            label_scores[r.label] += r.confidence * w
        winner = max(label_scores, key=label_scores.get)  # type: ignore[arg-type]
        total_w = sum(weights)
        return PredictionResult(
            label=winner,
            confidence=label_scores[winner] / total_w if total_w else 0.0,
            metadata={"label_scores": dict(label_scores), "n_models": len(results)},
        )
