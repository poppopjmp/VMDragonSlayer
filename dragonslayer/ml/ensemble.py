"""
Ensemble Classifiers
====================

Combine predictions from multiple :class:`~dragonslayer.ml.model.BaseModel`
instances to improve classification accuracy.

Three strategies are provided:

* :class:`EnsembleClassifier` — majority vote.
* :class:`WeightedEnsemble` — weighted confidence aggregation.
* :class:`StackedEnsemble` — second-level meta-model trained on base
  model outputs (stacking / blending).
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Sequence

from .model import BaseModel, PredictionResult

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Majority-vote ensemble
# ═══════════════════════════════════════════════════════════════════════════════

class EnsembleClassifier:
    """Run multiple models and aggregate their predictions.

    By default uses majority vote.  For a weighted scheme see
    :class:`WeightedEnsemble`.
    """

    def __init__(self, models: Sequence[BaseModel] | None = None) -> None:
        self._models: List[BaseModel] = list(models) if models else []

    @property
    def n_models(self) -> int:
        return len(self._models)

    def add_model(self, model: BaseModel) -> None:
        self._models.append(model)

    # ── Fault-tolerant prediction (B59) ────────────────────────────────────

    def predict_safe(self, features: Dict[str, Any]) -> PredictionResult:
        """Like :meth:`predict` but tolerates individual model failures.

        Models that raise are logged and skipped.  If *all* models fail,
        returns a result with ``label="unknown"`` and ``confidence=0.0``.
        """
        if not self._models:
            return PredictionResult(
                label="unknown", confidence=0.0,
                metadata={"error": "no models"},
            )

        results: List[PredictionResult] = []
        responded_indices: List[int] = []
        failures: List[str] = []
        for idx, mdl in enumerate(self._models):
            try:
                results.append(mdl.predict(features))
                responded_indices.append(idx)
            except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
                failures.append(f"{getattr(mdl, 'name', type(mdl).__name__)}: {exc}")
                logger.debug("Ensemble model failed: %s", failures[-1])

        if not results:
            return PredictionResult(
                label="unknown", confidence=0.0,
                metadata={"failures": failures},
            )

        return self._aggregate(
            results,
            failures=failures,
            responded_indices=responded_indices,
        )

    # ── Standard prediction ────────────────────────────────────────────────

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        """Majority-vote prediction from all component models.

        Args:
            features: Feature dict passed to every component model.

        Returns:
            Aggregated :class:`PredictionResult` (majority vote).

        Raises:
            ValueError: If no component models have been added.
        """
        if not self._models:
            raise ValueError(
                "EnsembleClassifier has no component models — "
                "add trained models via add_model()"
            )
        results = [m.predict(features) for m in self._models]
        return self._aggregate(results)

    # ── Aggregation (overridable) ──────────────────────────────────────────

    def _aggregate(
        self,
        results: List[PredictionResult],
        *,
        failures: List[str] | None = None,
        responded_indices: List[int] | None = None,
    ) -> PredictionResult:
        """Aggregate results via majority vote (B59 refactor).

        Args:
            results: Predictions from component models.
            failures: Optional list of model names that failed.
            responded_indices: Original model indices for weight alignment.

        Returns:
            A single :class:`PredictionResult` with agreement metadata.
        """
        votes = Counter(r.label for r in results)
        winner, count = votes.most_common(1)[0]
        agreement = count / len(results) if results else 0.0
        meta: Dict[str, Any] = {
            "votes": dict(votes),
            "n_models": len(self._models),
            "n_responded": len(results),
            "agreement": agreement,
        }
        if failures:
            meta["failures"] = failures
        return PredictionResult(
            label=winner,
            confidence=agreement,
            metadata=meta,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Weighted-confidence ensemble
# ═══════════════════════════════════════════════════════════════════════════════

class WeightedEnsemble(EnsembleClassifier):
    """Weighted combination of model predictions."""

    def __init__(
        self,
        models: Sequence[BaseModel] | None = None,
        weights: Sequence[float] | None = None,
    ) -> None:
        super().__init__(models)
        self._weights = list(weights) if weights else []

    def _aggregate(
        self,
        results: List[PredictionResult],
        *,
        failures: List[str] | None = None,
        responded_indices: List[int] | None = None,
    ) -> PredictionResult:
        all_weights = self._weights or [1.0] * len(self._models)
        # Select weights for the models that actually responded, preserving
        # the original weight-to-model mapping.
        if responded_indices is not None:
            weights = [
                all_weights[i] if i < len(all_weights) else 1.0
                for i in responded_indices
            ]
        else:
            # Called from predict() where all models respond.
            weights = all_weights[:len(results)]
            if len(weights) < len(results):
                weights = weights + [1.0] * (len(results) - len(weights))
        label_scores: Dict[str, float] = defaultdict(float)
        for r, w in zip(results, weights):
            label_scores[r.label] += r.confidence * w
        winner = max(label_scores, key=label_scores.get)  # type: ignore[arg-type]
        total_w = sum(weights) or 1.0
        agreement = sum(1 for r in results if r.label == winner) / len(results) if results else 0.0
        meta: Dict[str, Any] = {
            "label_scores": dict(label_scores),
            "n_models": len(self._models),
            "n_responded": len(results),
            "agreement": agreement,
        }
        if failures:
            meta["failures"] = failures
        return PredictionResult(
            label=winner,
            confidence=min(1.0, max(0.0, label_scores[winner] / total_w)),
            metadata=meta,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Stacked ensemble (meta-model)  — B59
# ═══════════════════════════════════════════════════════════════════════════════

class StackedEnsemble(EnsembleClassifier):
    """Two-level stacking ensemble.

    Base models produce predictions; the *meta-model* then classifies
    the concatenated base-model outputs.  Training the meta-model is
    optional: if no meta-model is set, falls back to weighted voting.

    Usage::

        base = [model_a, model_b]
        stack = StackedEnsemble(models=base)
        stack.set_meta_model(meta_clf)
        result = stack.predict(features)
    """

    def __init__(
        self,
        models: Sequence[BaseModel] | None = None,
        meta_model: BaseModel | None = None,
    ) -> None:
        super().__init__(models)
        self._meta_model: Optional[BaseModel] = meta_model

    def set_meta_model(self, model: BaseModel) -> None:
        self._meta_model = model

    def _build_meta_features(
        self, results: List[PredictionResult]
    ) -> Dict[str, Any]:
        """Build a feature dict from base-model outputs for the meta-model.

        Extracts labels, confidences, per-class probabilities, and
        agreement ratio from the base-model results.

        Args:
            results: Predictions from the base component models.

        Returns:
            Dict of meta-features suitable for the stacking meta-model.
        """
        meta: Dict[str, Any] = {}
        for i, r in enumerate(results):
            meta[f"base_{i}_label"] = r.label
            meta[f"base_{i}_conf"] = r.confidence
            for lbl, prob in r.probabilities.items():
                meta[f"base_{i}_prob_{lbl}"] = prob
        # Agreement ratio
        labels = [r.label for r in results]
        if labels:
            most_common = Counter(labels).most_common(1)[0][1]
            meta["agreement_ratio"] = most_common / len(labels)
        return meta

    def _aggregate(
        self,
        results: List[PredictionResult],
        *,
        failures: List[str] | None = None,
        responded_indices: List[int] | None = None,
    ) -> PredictionResult:
        if self._meta_model is not None:
            try:
                meta_features = self._build_meta_features(results)
                meta_result = self._meta_model.predict(meta_features)
                meta_result.metadata["stacking"] = True
                meta_result.metadata["n_models"] = len(self._models)
                meta_result.metadata["n_responded"] = len(results)
                if failures:
                    meta_result.metadata["failures"] = failures
                return meta_result
            except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
                logger.debug("Meta-model failed, falling back to vote: %s", exc)
        # Fallback to majority vote
        return super()._aggregate(results, failures=failures, responded_indices=responded_indices)
