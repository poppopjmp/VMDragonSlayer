"""
ML Classifier
==============

High-level classification entry point that wraps the feature pipeline
and model inference into a single :meth:`classify` call.

Stub — requires a trained model to be loaded.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from .model import BaseModel, PredictionResult, VMHandlerModel
from .pipeline import FeatureExtractor, FeatureVector

logger = logging.getLogger(__name__)


class VMClassifier:
    """Classify binary artefacts using a trained ML model.

    Usage::

        clf = VMClassifier(model=VMHandlerModel())
        clf.model.load("data/models/pretrained/vm_handler.pt")
        result = clf.classify(analysis_data)
    """

    def __init__(
        self,
        model: BaseModel | None = None,
        extractor: FeatureExtractor | None = None,
    ) -> None:
        self.model = model or VMHandlerModel()
        self.extractor = extractor or FeatureExtractor()

    def classify(self, analysis_data: Dict[str, Any]) -> PredictionResult:
        """Extract features and run model prediction."""
        features = self.extractor.extract(analysis_data)
        return self.model.predict(
            {"values": features.values, "names": features.feature_names}
        )
