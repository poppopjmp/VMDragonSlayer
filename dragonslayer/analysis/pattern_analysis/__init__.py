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
Pattern Analysis Module
======================

Pattern recognition and analysis components for VMDragonSlayer.

This module provides:
- Pattern recognition for VM bytecode analysis
- Pattern database management
- Pattern classification and matching
"""

from .classifier import ClassificationResult, PatternClassifier
from .database import PatternDatabase, PatternSample, PatternType
from .recognizer import PatternMatch, PatternRecognizer, SemanticPattern

__all__ = [
    "PatternRecognizer",
    "SemanticPattern",
    "PatternMatch",
    "PatternDatabase",
    "PatternType",
    "PatternSample",
    "PatternClassifier",
    "ClassificationResult",
]
