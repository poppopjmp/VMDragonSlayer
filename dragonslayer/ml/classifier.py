"""
ML Classifier
==============

High-level classification entry point that wraps the feature pipeline
and model inference into a single :meth:`classify` call.

When called with a handler dict (containing ``mnemonics`` or
``instructions``), uses :func:`extract_handler_features` to produce a
feature vector and the heuristic-based :class:`VMHandlerModel` to
classify the handler category (arithmetic, logic, stack, load_store,
branch, nop, unknown).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from .model import BaseModel, PredictionResult, VMHandlerModel
from .pipeline import FeatureExtractor, FeatureVector, extract_handler_features

logger = logging.getLogger(__name__)


class VMClassifier:
    """Classify binary artefacts using a trained ML model.

    Usage::

        clf = VMClassifier()
        result = clf.classify(handler_dict)
        print(result.label, result.confidence)
    """

    def __init__(
        self,
        model: BaseModel | None = None,
        extractor: FeatureExtractor | None = None,
    ) -> None:
        self.model = model or VMHandlerModel()
        self.extractor = extractor  # optional custom extractor

    def classify(self, analysis_data: Dict[str, Any]) -> PredictionResult:
        """Extract features and run model prediction.

        If a custom extractor was provided, uses it; otherwise
        delegates to :func:`extract_handler_features`.
        """
        if self.extractor is not None:
            features = self.extractor.extract(analysis_data)
        else:
            features = extract_handler_features(analysis_data)
        return self.model.predict(
            {"values": features.values, "names": features.feature_names}
        )

    def classify_batch(
        self,
        handlers: List[Dict[str, Any]],
    ) -> List[PredictionResult]:
        """Classify a list of handlers, tolerating individual failures.

        Returns one :class:`PredictionResult` per handler.  If an
        individual classification raises, a placeholder ``unknown``
        result is returned so the batch still produces output for
        every element.
        """
        results: List[PredictionResult] = []
        for i, h in enumerate(handlers):
            try:
                results.append(self.classify(h))
            except Exception as exc:
                logger.debug("classify_batch: item %d failed: %s", i, exc)
                results.append(PredictionResult(
                    label="unknown", confidence=0.0,
                    metadata={"error": str(exc), "batch_index": i},
                ))
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# B71 / B72 — Feature explainability
# ═══════════════════════════════════════════════════════════════════════════════

class FeatureExplainer:
    """Lightweight model-agnostic feature explainer.

    Provides two explanation modes:

    1. **Global importance** — permutation importance across a dataset.
    2. **Local explanation** — per-feature contribution for a single
       prediction (simplified LIME-style perturbation).

    The explainer operates at the *feature-vector* level: it first
    extracts features from every sample, then permutes / zeroes
    individual feature columns before feeding them to the underlying
    model.  This ensures perturbations are actually seen by the model.

    Usage::

        explainer = FeatureExplainer(classifier)
        global_imp = explainer.global_importance(dataset)
        local_exp  = explainer.local_explain(single_sample)
    """

    def __init__(self, classifier: VMClassifier, *, n_repeats: int = 5) -> None:
        self.classifier = classifier
        self.n_repeats = n_repeats

    # -- helper: classify from raw feature values ---------------------------

    def _predict_from_values(
        self,
        values: List[float],
        names: List[str],
    ) -> PredictionResult:
        """Run the model directly on a pre-built feature vector."""
        return self.classifier.model.predict({"values": values, "names": names})

    # -- Global permutation importance --------------------------------------

    def global_importance(
        self,
        dataset: List[Dict[str, Any]],
        labels: List[str] | None = None,
    ) -> List[tuple[str, float]]:
        """Compute permutation importance for each feature.

        For each feature column, shuffle its values across *dataset*
        and measure the accuracy / confidence drop.

        Returns ``[(feature_name, importance_score)]`` sorted descending.
        """
        if not dataset:
            return []

        # Extract all feature vectors up-front
        vectors = [extract_handler_features(d) for d in dataset]
        names = vectors[0].feature_names
        n = len(vectors)

        # Baseline score
        baseline = [self._predict_from_values(v.values, names) for v in vectors]
        if labels:
            base_score = sum(
                1 for p, l in zip(baseline, labels) if p.label == l
            ) / len(labels)
        else:
            base_score = sum(p.confidence for p in baseline) / n

        import random
        importances: Dict[str, float] = {}
        for fi, fname in enumerate(names):
            drops: list[float] = []
            original_col = [v.values[fi] for v in vectors]
            for _ in range(self.n_repeats):
                shuffled_col = list(original_col)
                random.shuffle(shuffled_col)
                perm_preds = []
                for si, vec in enumerate(vectors):
                    perturbed_vals = list(vec.values)
                    perturbed_vals[fi] = shuffled_col[si]
                    perm_preds.append(
                        self._predict_from_values(perturbed_vals, names)
                    )
                if labels:
                    perm_score = sum(
                        1 for p, l in zip(perm_preds, labels) if p.label == l
                    ) / len(labels)
                else:
                    perm_score = sum(p.confidence for p in perm_preds) / n
                drops.append(base_score - perm_score)
            importances[fname] = sum(drops) / len(drops) if drops else 0.0

        ranked = sorted(importances.items(), key=lambda x: x[1], reverse=True)
        return ranked

    # -- Local explanation (perturbation-based) -----------------------------

    def local_explain(
        self,
        sample: Dict[str, Any],
        *,
        n_perturbations: int = 20,
    ) -> Dict[str, float]:
        """Explain a single prediction by zeroing each feature.

        For each feature, set it to zero and measure the confidence
        change.  A large drop means the feature is important for
        this particular prediction.

        Returns ``{feature_name: contribution}`` where positive
        values mean the feature *supports* the prediction.
        """
        features = extract_handler_features(sample)
        base_pred = self._predict_from_values(features.values, features.feature_names)
        base_conf = base_pred.confidence
        base_label = base_pred.label

        contributions: Dict[str, float] = {}

        for fi, fname in enumerate(features.feature_names):
            perturbed_vals = list(features.values)
            perturbed_vals[fi] = 0.0  # zero the feature
            try:
                pert_pred = self._predict_from_values(perturbed_vals, features.feature_names)
                if pert_pred.label == base_label:
                    contributions[fname] = base_conf - pert_pred.confidence
                else:
                    contributions[fname] = base_conf  # label changed → full contribution
            except Exception:
                contributions[fname] = 0.0

        return contributions
