"""
ML Model Trainer
=================

Training infrastructure for the VM handler classification models.

These are **interface stubs** — concrete training loops require a
backend like scikit-learn or PyTorch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

import logging

from .model import BaseModel, PredictionResult
from .pipeline import FeatureVector

logger = logging.getLogger(__name__)


@dataclass
class TrainingResult:
    """Summary of a training run."""

    epochs: int = 0
    final_loss: float = 0.0
    accuracy: float = 0.0
    metrics: Dict[str, float] = field(default_factory=dict)
    model_path: str = ""


class ModelTrainer:
    """Train a :class:`BaseModel` on labelled feature vectors.

    Subclass and override :meth:`train` to plug in a real training loop.
    """

    def __init__(self, model: BaseModel | None = None) -> None:
        self._model = model

    def train(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
        *,
        epochs: int = 10,
        **kwargs: Any,
    ) -> TrainingResult:
        """Run training.  Raises :exc:`NotImplementedError` until a
        concrete trainer subclass is provided."""
        raise NotImplementedError(
            "ModelTrainer.train() is not implemented — "
            "provide a training backend (scikit-learn, PyTorch, …)"
        )

    def evaluate(
        self,
        features: Sequence[FeatureVector],
        labels: Sequence[str],
    ) -> Dict[str, float]:
        """Evaluate model accuracy on a held-out set."""
        raise NotImplementedError("ModelTrainer.evaluate() is not implemented")


def prepare_training_data(
    analysis_results: List[Dict[str, Any]],
    label_key: str = "handler_type",
) -> tuple[list[FeatureVector], list[str]]:
    """Convert raw analysis dicts into (features, labels) for training.

    Stub — raises :exc:`NotImplementedError` until domain-specific
    feature engineering is implemented.
    """
    raise NotImplementedError(
        "prepare_training_data() requires domain-specific feature engineering"
    )
