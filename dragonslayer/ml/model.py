"""
ML Model Definitions
====================

Base model classes and prediction result container for the VM handler
classification pipeline.

These are **interface stubs** — concrete implementations require a
training backend (scikit-learn, PyTorch, etc.) to be installed and a
trained model artifact in ``data/models/pretrained/``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import logging

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """Container for a single model prediction."""

    label: str = ""
    confidence: float = 0.0
    probabilities: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseModel:
    """Abstract base for all ML models in VMDragonSlayer.

    Subclasses must override :meth:`predict` and :meth:`load`.
    """

    name: str = "base"

    def load(self, path: str) -> None:
        """Load model weights / parameters from *path*."""
        raise NotImplementedError(
            f"{type(self).__name__}.load() is not implemented — "
            "install a training backend and provide a trained model artifact"
        )

    def predict(self, features: Dict[str, Any]) -> PredictionResult:
        """Run inference on a single feature dict."""
        raise NotImplementedError(
            f"{type(self).__name__}.predict() is not implemented"
        )

    def predict_batch(self, batch: List[Dict[str, Any]]) -> List[PredictionResult]:
        """Run inference on a batch (default: sequential predict)."""
        return [self.predict(f) for f in batch]


class VMHandlerModel(BaseModel):
    """Specialised classifier for VM handler type detection.

    Expected to distinguish among handler families
    (arithmetic, load/store, branch, call, …) given an instruction-level
    feature vector.
    """

    name: str = "vm_handler"
