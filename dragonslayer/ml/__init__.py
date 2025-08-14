# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

from .classifier import ClassificationResult, PatternClassifier
from .ensemble import EnsembleConfig, EnsemblePredictor
from .model import MLModel, ModelStatus, ModelType
from .pipeline import FeatureExtractor, MLPipeline
from .trainer import ModelTrainer, TrainingConfig

__all__ = [
    "PatternClassifier",
    "ClassificationResult",
    "ModelTrainer",
    "TrainingConfig",
    "MLModel",
    "ModelType",
    "ModelStatus",
    "MLPipeline",
    "FeatureExtractor",
    "EnsemblePredictor",
    "EnsembleConfig",
]
