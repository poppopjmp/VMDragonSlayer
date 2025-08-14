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

from .vm_discovery import VMDetector, VMType, HandlerType, VMHandler, VMStructure
from .pattern_analysis import (
    PatternRecognizer,
    PatternDatabase,
    PatternClassifier,
    SemanticPattern,
    PatternSample,
    PatternMatch,
    ClassificationResult,
    PatternType
)
from .symbolic_execution import (
    SymbolicExecutor,
    HandlerLifter,
    ConstraintSolver,
    ExecutionContext,
    SymbolicValue,
    Instruction,
    InstructionType
)
from .taint_tracking import (
    TaintTracker,
    VMTaintAnalyzer,
    TaintInfo,
    TaintType,
    OperationType,
    EnhancedVMTaintTracker
)

# Anti-evasion components
try:
    from .anti_evasion import (
        EnvironmentNormalizer,
        DebuggerDetectionBypass,
        VMDetectionBypass,
        SandboxEvasionBypass,
        SelfModificationTracker,
        AnalysisEnvironment,
        CountermeasureType,
        CountermeasureResult
    )
    ANTI_EVASION_AVAILABLE = True
except ImportError:
    ANTI_EVASION_AVAILABLE = False

__all__ = [
    # VM Discovery
    'VMDetector',
    'VMType',
    'HandlerType', 
    'VMHandler',
    'VMStructure',
    # Pattern Analysis
    'PatternRecognizer',
    'PatternDatabase', 
    'PatternClassifier',
    'SemanticPattern',
    'PatternSample',
    'PatternMatch',
    'ClassificationResult',
    'PatternType',
    # Symbolic Execution
    'SymbolicExecutor',
    'HandlerLifter',
    'ConstraintSolver',
    'ExecutionContext',
    'SymbolicValue',
    'Instruction',
    'InstructionType',
    # Taint Tracking
    'TaintTracker',
    'VMTaintAnalyzer',
    'TaintInfo',
    'TaintType',
    'OperationType',
    'EnhancedVMTaintTracker'
]

# Add anti-evasion components if available
if ANTI_EVASION_AVAILABLE:
    __all__.extend([
        'EnvironmentNormalizer',
        'DebuggerDetectionBypass', 
        'VMDetectionBypass',
        'SandboxEvasionBypass',
        'SelfModificationTracker',
        'AnalysisEnvironment',
        'CountermeasureType',
        'CountermeasureResult'
    ])
