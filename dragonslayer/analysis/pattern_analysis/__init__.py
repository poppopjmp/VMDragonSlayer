"""
Pattern Analysis Module

"""

from .database import (
    Pattern,
    PatternDatabase,
    Architecture,
    HandlerType
)

from .recognizer import (
    Match,
    PatternRecognizer,
    SequenceRecognizer
)

from .classifier import (
    PatternClassifier,
    ClassificationResult,
    ClassificationReport,
)

__all__ = [
    # Database
    'Pattern',
    'PatternDatabase',
    'Architecture',
    'HandlerType',
    
    # Recognition
    'Match',
    'PatternRecognizer',
    'SequenceRecognizer',

    # Classification
    'PatternClassifier',
    'ClassificationResult',
    'ClassificationReport',
]
