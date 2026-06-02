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
from typing import Any

from .model import BaseModel, PredictionResult, VMHandlerModel
from .pipeline import FeatureExtractor, extract_handler_features

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

    def classify(self, analysis_data: dict[str, Any]) -> PredictionResult:
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
        handlers: list[dict[str, Any]],
    ) -> list[PredictionResult]:
        """Classify a list of handlers, tolerating individual failures.

        Returns one :class:`PredictionResult` per handler.  If an
        individual classification raises, a placeholder ``unknown``
        result is returned so the batch still produces output for
        every element.
        """
        results: list[PredictionResult] = []
        for i, h in enumerate(handlers):
            try:
                results.append(self.classify(h))
            except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
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
        values: list[float],
        names: list[str],
    ) -> PredictionResult:
        """Run the model directly on a pre-built feature vector."""
        return self.classifier.model.predict({"values": values, "names": names})

    # -- Global permutation importance --------------------------------------

    def global_importance(
        self,
        dataset: list[dict[str, Any]],
        labels: list[str] | None = None,
        *,
        random_state: int | None = None,
    ) -> list[tuple[str, float]]:
        """Compute permutation importance for each feature.

        For each feature column, shuffle its values across *dataset*
        and measure the accuracy / confidence drop.

        Parameters
        ----------
        dataset : list of handler dicts
        labels : optional ground-truth labels for accuracy-based scoring
        random_state : optional seed for reproducibility

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
                1 for p, lbl in zip(baseline, labels, strict=False) if p.label == lbl
            ) / len(labels)
        else:
            base_score = sum(p.confidence for p in baseline) / n

        import random
        rng = random.Random(random_state)
        importances: dict[str, float] = {}
        for fi, fname in enumerate(names):
            drops: list[float] = []
            original_col = [v.values[fi] for v in vectors]
            for _ in range(self.n_repeats):
                shuffled_col = list(original_col)
                rng.shuffle(shuffled_col)
                perm_preds = []
                for si, vec in enumerate(vectors):
                    perturbed_vals = list(vec.values)
                    perturbed_vals[fi] = shuffled_col[si]
                    perm_preds.append(
                        self._predict_from_values(perturbed_vals, names)
                    )
                if labels:
                    perm_score = sum(
                        1 for p, lbl in zip(perm_preds, labels, strict=False) if p.label == lbl
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
        sample: dict[str, Any],
        *,
        n_perturbations: int = 20,
        random_state: int | None = None,
    ) -> dict[str, float]:
        """Explain a single prediction by perturbing each feature.

        For each feature, perform *n_perturbations* random perturbations
        (scaling the feature both up and down) and measure the average
        confidence change.  A large drop means the feature is important
        for this particular prediction.

        Returns ``{feature_name: contribution}`` where positive
        values mean the feature *supports* the prediction.
        """
        import random
        rng = random.Random(random_state)

        features = extract_handler_features(sample)
        base_pred = self._predict_from_values(features.values, features.feature_names)
        base_conf = base_pred.confidence
        base_label = base_pred.label

        contributions: dict[str, float] = {}

        for fi, fname in enumerate(features.feature_names):
            drops: list[float] = []
            original_val = features.values[fi]
            for pi in range(n_perturbations):
                perturbed_vals = list(features.values)
                # B78: Bidirectional perturbation — scale both down and up
                if pi == 0:
                    perturbed_vals[fi] = 0.0          # zero it out
                elif pi % 2 == 1:
                    # Scale down: [0.0, 0.8) of original
                    perturbed_vals[fi] = original_val * rng.uniform(0.0, 0.8)
                else:
                    # Scale up: (1.2, 2.0] of original
                    perturbed_vals[fi] = original_val * rng.uniform(1.2, 2.0)
                try:
                    pert_pred = self._predict_from_values(
                        perturbed_vals, features.feature_names
                    )
                    if pert_pred.label == base_label:
                        drops.append(base_conf - pert_pred.confidence)
                    else:
                        drops.append(base_conf)  # label changed → full contribution
                except (ValueError, TypeError, KeyError, AttributeError, IndexError):
                    drops.append(0.0)
            contributions[fname] = sum(drops) / len(drops) if drops else 0.0

        return contributions
