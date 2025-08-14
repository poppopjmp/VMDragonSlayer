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
VMDragonSlayer Library
=====================

A comprehensive library for virtual machine analysis and pattern detection.

This library provides:
- VM structure detection and analysis
- Pattern recognition and classification
- Machine learning-based classification
- REST API for remote access
- Symbolic execution and taint tracking
- Anti-analysis detection

Usage:
    from vmdragonslayer import analyze_file, get_api

    # Simple file analysis
    result = analyze_file("sample.exe")

    # Get full API
    api = get_api()
    result = api.analyze_file("sample.exe", analysis_type="vm_discovery")

Architecture:
    - core: Core orchestration, configuration, and API
    - analysis: Analysis engines (VM discovery, pattern analysis, etc.)
    - ml: Machine learning components
    - api: REST API server and client
    - utils: Utility functions
    - workflows: Analysis workflows and pipelines
"""

# Core functionality - most commonly used
from .analysis.pattern_analysis import (
    ClassificationResult,
    PatternClassifier,
    PatternDatabase,
    PatternRecognizer,
    PatternType,
)
from .analysis.symbolic_execution import (
    ConstraintSolver,
    ExecutionContext,
    HandlerLifter,
    Instruction,
    InstructionType,
    SymbolicExecutor,
    SymbolicValue,
)
from .analysis.taint_tracking import (
    EnhancedVMTaintTracker,
    OperationType,
    TaintInfo,
    TaintTracker,
    TaintType,
    VMTaintAnalyzer,
)

# Analysis components
from .analysis.vm_discovery import HandlerType, VMDetector, VMType
from .core import (
    AnalysisError,
    AnalysisType,
    Orchestrator,
    VMDragonSlayerAPI,
    VMDragonSlayerConfig,
    VMDragonSlayerError,
    WorkflowStrategy,
    analyze_binary_data,
    analyze_file,
    configure,
    get_api,
    get_config,
    get_status,
)

# ML components (optional, may require heavy deps)
try:
    from .ml import EnsemblePredictor

    ML_AVAILABLE = True
except Exception:  # Broad except to handle runtime errors in optional deps
    ML_AVAILABLE = False

# API components (optional)
try:
    from .api import APIClient, APIServer, create_app, create_client

    API_AVAILABLE = True
except Exception:
    API_AVAILABLE = False

# GPU acceleration components
try:
    from .gpu import GPUEngine, GPUProfiler, KernelOptimizer, MemoryManager

    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# Analytics components
try:
    from .analytics import (
        AnalyticsDashboard,
        MetricsCollector,
        ReportGenerator,
        ThreatIntelligenceProcessor,
    )

    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False

# Anti-evasion components
try:
    from .analysis.anti_evasion import (
        AnalysisEnvironment,
        CountermeasureType,
        DebuggerDetectionBypass,
        EnvironmentNormalizer,
        SandboxEvasionBypass,
        VMDetectionBypass,
    )

    ANTI_EVASION_AVAILABLE = True
except ImportError:
    ANTI_EVASION_AVAILABLE = False

# Enterprise components
try:
    from .enterprise import (
        ComplianceManager,
        EnterpriseArchitecture,
        IntegrationAPISystem,
        LoadBalancer,
        ServiceMesh,
        WebhookManager,
    )

    ENTERPRISE_AVAILABLE = True
except ImportError:
    ENTERPRISE_AVAILABLE = False

# Version and metadata
__version__ = "1.0.0"
__author__ = "van1sh"
__description__ = "Virtual Machine Analysis and Pattern Detection Library"
__url__ = "https://github.com/poppopjmp/vmdragonslayer"

# Main public API - most commonly used functions
__all__ = [
    # Core API functions
    "analyze_file",
    "analyze_binary_data",
    "get_api",
    "get_status",
    "configure",
    # Main classes
    "VMDragonSlayerAPI",
    "Orchestrator",
    "VMDetector",
    "PatternRecognizer",
    "PatternDatabase",
    "PatternClassifier",
    "SymbolicExecutor",
    "HandlerLifter",
    "ConstraintSolver",
    "TaintTracker",
    "VMTaintAnalyzer",
    # API symbols added below if available
    # 'EnsemblePredictor' added below if available
    # Configuration
    "VMDragonSlayerConfig",
    "get_config",
    # Enums
    "AnalysisType",
    "WorkflowStrategy",
    "VMType",
    "HandlerType",
    "PatternType",
    "InstructionType",
    "TaintType",
    "OperationType",
    # Exceptions
    "VMDragonSlayerError",
    "AnalysisError",
    # Utilities
    # API utility functions added below if available
    "ClassificationResult",
    "ExecutionContext",
    "SymbolicValue",
    "Instruction",
    "TaintInfo",
    "EnhancedVMTaintTracker",
    # Metadata
    "__version__",
    "__author__",
    "__description__",
]

# Add conditional exports based on availability
if GPU_AVAILABLE:
    __all__.extend(["GPUEngine", "GPUProfiler", "MemoryManager", "KernelOptimizer"])

if ML_AVAILABLE:
    __all__.extend(["EnsemblePredictor"])

if API_AVAILABLE:
    __all__.extend(["APIServer", "APIClient", "create_app", "create_client"])

if ANALYTICS_AVAILABLE:
    __all__.extend(
        [
            "ReportGenerator",
            "AnalyticsDashboard",
            "ThreatIntelligenceProcessor",
            "MetricsCollector",
        ]
    )

if ANTI_EVASION_AVAILABLE:
    __all__.extend(
        [
            "EnvironmentNormalizer",
            "DebuggerDetectionBypass",
            "VMDetectionBypass",
            "SandboxEvasionBypass",
            "AnalysisEnvironment",
            "CountermeasureType",
        ]
    )

if ENTERPRISE_AVAILABLE:
    __all__.extend(
        [
            "IntegrationAPISystem",
            "ComplianceManager",
            "EnterpriseArchitecture",
            "WebhookManager",
            "LoadBalancer",
            "ServiceMesh",
        ]
    )

# Convenience aliases for backward compatibility
VMDragonSlayerOrchestrator = Orchestrator
VMAnalysisAPI = VMDragonSlayerAPI
