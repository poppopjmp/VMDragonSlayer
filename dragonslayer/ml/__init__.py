"""
ML Module
=========

Machine learning components for VMDragonSlayer.

This module provides:
- Pattern classification for VM bytecode analysis
- Model training and evaluation
- Feature extraction and preprocessing
- Model lifecycle management
"""

from .classifier import PatternClassifier, ClassificationResult
from .trainer import ModelTrainer, TrainingConfig
from .model import MLModel, ModelType, ModelStatus
from .pipeline import MLPipeline, FeatureExtractor
from .ensemble import EnsemblePredictor, EnsembleConfig

__all__ = [
    'PatternClassifier',
    'ClassificationResult',
    'ModelTrainer', 
    'TrainingConfig',
    'MLModel',
    'ModelType',
    'ModelStatus',
    'MLPipeline',
    'FeatureExtractor',
    'EnsemblePredictor',
    'EnsembleConfig'
]
