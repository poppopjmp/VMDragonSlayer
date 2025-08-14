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
Analysis Module
==============

Analysis components for VMDragonSlayer.

This module provides various analysis engines for binary analysis including:
- VM discovery and structure analysis
- Pattern analysis and recognition
- Taint tracking (DTT)
- Symbolic execution
- Anti-analysis detection
"""

from .pattern_analysis import (
    ClassificationResult,
    PatternClassifier,
    PatternDatabase,
    PatternMatch,
    PatternRecognizer,
    PatternSample,
    PatternType,
    SemanticPattern,
)
from .symbolic_execution import (
    ConstraintSolver,
    ExecutionContext,
    HandlerLifter,
    Instruction,
    InstructionType,
    SymbolicExecutor,
    SymbolicValue,
)
from .taint_tracking import (
    EnhancedVMTaintTracker,
    OperationType,
    TaintInfo,
    TaintTracker,
    TaintType,
    VMTaintAnalyzer,
)
from .vm_discovery import HandlerType, VMDetector, VMHandler, VMStructure, VMType

# Anti-evasion components
try:
    from .anti_evasion import (
        AnalysisEnvironment,
        CountermeasureResult,
        CountermeasureType,
        DebuggerDetectionBypass,
        EnvironmentNormalizer,
        SandboxEvasionBypass,
        SelfModificationTracker,
        VMDetectionBypass,
    )

    ANTI_EVASION_AVAILABLE = True
except ImportError:
    ANTI_EVASION_AVAILABLE = False

__all__ = [
    # VM Discovery
    "VMDetector",
    "VMType",
    "HandlerType",
    "VMHandler",
    "VMStructure",
    # Pattern Analysis
    "PatternRecognizer",
    "PatternDatabase",
    "PatternClassifier",
    "SemanticPattern",
    "PatternSample",
    "PatternMatch",
    "ClassificationResult",
    "PatternType",
    # Symbolic Execution
    "SymbolicExecutor",
    "HandlerLifter",
    "ConstraintSolver",
    "ExecutionContext",
    "SymbolicValue",
    "Instruction",
    "InstructionType",
    # Taint Tracking
    "TaintTracker",
    "VMTaintAnalyzer",
    "TaintInfo",
    "TaintType",
    "OperationType",
    "EnhancedVMTaintTracker",
]

# Add anti-evasion components if available
if ANTI_EVASION_AVAILABLE:
    __all__.extend(
        [
            "EnvironmentNormalizer",
            "DebuggerDetectionBypass",
            "VMDetectionBypass",
            "SandboxEvasionBypass",
            "SelfModificationTracker",
            "AnalysisEnvironment",
            "CountermeasureType",
            "CountermeasureResult",
        ]
    )
