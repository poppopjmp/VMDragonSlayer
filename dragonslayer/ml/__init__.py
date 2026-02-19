"""
Machine Learning Module

All imports are guarded so the package can be imported even when
optional dependencies (scikit-learn, PyTorch, etc.) are missing.
"""

try:
    from .pipeline import FeatureExtractor, FeatureVector
except (ImportError, AttributeError):
    FeatureExtractor = None  # type: ignore[assignment,misc]
    FeatureVector = None  # type: ignore[assignment,misc]

try:
    from .trainer import ModelTrainer, TrainingResult, prepare_training_data
except (ImportError, AttributeError):
    ModelTrainer = None  # type: ignore[assignment,misc]
    TrainingResult = None  # type: ignore[assignment,misc]
    prepare_training_data = None  # type: ignore[assignment,misc]

try:
    from .model import BaseModel, VMHandlerModel, PredictionResult
except (ImportError, AttributeError):
    BaseModel = None  # type: ignore[assignment,misc]
    VMHandlerModel = None  # type: ignore[assignment,misc]
    PredictionResult = None  # type: ignore[assignment,misc]

try:
    from .ensemble import EnsembleClassifier, WeightedEnsemble
except (ImportError, AttributeError):
    EnsembleClassifier = None  # type: ignore[assignment,misc]
    WeightedEnsemble = None  # type: ignore[assignment,misc]

try:
    from .classifier import VMClassifier
except (ImportError, AttributeError):
    VMClassifier = None  # type: ignore[assignment,misc]

try:
    from .handler_classifier import (
        TrainedHandlerModel,
        classify_handlers,
        build_handler_classifier,
        HANDLER_CATEGORIES,
    )
except (ImportError, AttributeError):
    TrainedHandlerModel = None  # type: ignore[assignment,misc]
    classify_handlers = None  # type: ignore[assignment,misc]
    build_handler_classifier = None  # type: ignore[assignment,misc]
    HANDLER_CATEGORIES = None  # type: ignore[assignment,misc]

__all__ = [
    'FeatureExtractor',
    'FeatureVector',
    'ModelTrainer',
    'TrainingResult',
    'prepare_training_data',
    'BaseModel',
    'VMHandlerModel',
    'PredictionResult',
    'EnsembleClassifier',
    'WeightedEnsemble',
    'VMClassifier',
    'TrainedHandlerModel',
    'classify_handlers',
    'build_handler_classifier',
    'HANDLER_CATEGORIES',
]
