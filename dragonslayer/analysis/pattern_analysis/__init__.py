"""
Pattern Analysis Module
======================

Pattern recognition and analysis components for VMDragonSlayer.

This module provides:
- Pattern recognition for VM bytecode analysis
- Pattern database management
- Pattern classification and matching
"""

from .recognizer import PatternRecognizer, SemanticPattern, PatternMatch
from .database import PatternDatabase, PatternType, PatternSample
from .classifier import PatternClassifier, ClassificationResult

__all__ = [
    'PatternRecognizer',
    'SemanticPattern', 
    'PatternMatch',
    'PatternDatabase',
    'PatternType',
    'PatternSample',
    'PatternClassifier',
    'ClassificationResult'
]
