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
        """Classify a list of handlers."""
        return [self.classify(h) for h in handlers]
