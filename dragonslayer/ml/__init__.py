"""
Machine Learning Module

"""

from .pipeline import FeatureExtractor, FeatureVector
from .trainer import ModelTrainer, TrainingResult, prepare_training_data
from .model import BaseModel, VMHandlerModel, PredictionResult
from .ensemble import EnsembleClassifier, WeightedEnsemble

__all__ = [
    # Feature extraction
    'FeatureExtractor',
    'FeatureVector',
    
    # Training
    'ModelTrainer',
    'TrainingResult',
    'prepare_training_data',
    
    # Models
    'BaseModel',
    'VMHandlerModel',
    'PredictionResult',
    
    # Ensemble
    'EnsembleClassifier',
    'WeightedEnsemble',

]
