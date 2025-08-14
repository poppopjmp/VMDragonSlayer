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
from .core import (
    VMDragonSlayerAPI, get_api, analyze_file, analyze_binary_data, get_status,
    Orchestrator, AnalysisType, WorkflowStrategy,
    VMDragonSlayerConfig, get_config, configure,
    VMDragonSlayerError, AnalysisError
)

# Analysis components
from .analysis.vm_discovery import VMDetector, VMType, HandlerType
from .analysis.pattern_analysis import (
    PatternRecognizer, PatternDatabase, PatternClassifier,
    PatternType, ClassificationResult
)
from .analysis.symbolic_execution import (
    SymbolicExecutor, HandlerLifter, ConstraintSolver,
    ExecutionContext, SymbolicValue, Instruction, InstructionType
)
from .analysis.taint_tracking import (
    TaintTracker, VMTaintAnalyzer, TaintInfo, TaintType, 
    OperationType, EnhancedVMTaintTracker
)

# ML components
from .ml import EnsemblePredictor

# API components
from .api import APIServer, APIClient, create_app, create_client

# GPU acceleration components
try:
    from .gpu import GPUEngine, GPUProfiler, MemoryManager, KernelOptimizer
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# Analytics components
try:
    from .analytics import (
        ReportGenerator, AnalyticsDashboard, ThreatIntelligenceProcessor, 
        MetricsCollector
    )
    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False

# Anti-evasion components
try:
    from .analysis.anti_evasion import (
        EnvironmentNormalizer, DebuggerDetectionBypass, VMDetectionBypass,
        SandboxEvasionBypass, AnalysisEnvironment, CountermeasureType
    )
    ANTI_EVASION_AVAILABLE = True
except ImportError:
    ANTI_EVASION_AVAILABLE = False

# Enterprise components
try:
    from .enterprise import (
        IntegrationAPISystem, ComplianceManager, EnterpriseArchitecture,
        WebhookManager, LoadBalancer, ServiceMesh
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
    'analyze_file',
    'analyze_binary_data', 
    'get_api',
    'get_status',
    'configure',
    
    # Main classes
    'VMDragonSlayerAPI',
    'Orchestrator',
    'VMDetector',
    'PatternRecognizer',
    'PatternDatabase', 
    'PatternClassifier',
    'SymbolicExecutor',
    'HandlerLifter',
    'ConstraintSolver',
    'TaintTracker',
    'VMTaintAnalyzer',
    'APIServer',
    'APIClient',
    'EnsemblePredictor',
    
    # Configuration
    'VMDragonSlayerConfig',
    'get_config',
    
    # Enums
    'AnalysisType',
    'WorkflowStrategy',
    'VMType',
    'HandlerType',
    'PatternType',
    'InstructionType',
    'TaintType',
    'OperationType',
    
    # Exceptions
    'VMDragonSlayerError',
    'AnalysisError',
    
    # Utilities
    'create_app',
    'create_client',
    'ClassificationResult',
    'ExecutionContext',
    'SymbolicValue',
    'Instruction',
    'TaintInfo',
    'EnhancedVMTaintTracker',
    
    # Metadata
    '__version__',
    '__author__',
    '__description__',
]

# Add conditional exports based on availability
if GPU_AVAILABLE:
    __all__.extend([
        'GPUEngine', 'GPUProfiler', 'MemoryManager', 'KernelOptimizer'
    ])

if ANALYTICS_AVAILABLE:
    __all__.extend([
        'ReportGenerator', 'AnalyticsDashboard', 'ThreatIntelligenceProcessor', 
        'MetricsCollector'
    ])

if ANTI_EVASION_AVAILABLE:
    __all__.extend([
        'EnvironmentNormalizer', 'DebuggerDetectionBypass', 'VMDetectionBypass',
        'SandboxEvasionBypass', 'AnalysisEnvironment', 'CountermeasureType'
    ])

if ENTERPRISE_AVAILABLE:
    __all__.extend([
        'IntegrationAPISystem', 'ComplianceManager', 'EnterpriseArchitecture',
        'WebhookManager', 'LoadBalancer', 'ServiceMesh'
    ])

# Convenience aliases for backward compatibility
VMDragonSlayerOrchestrator = Orchestrator
VMAnalysisAPI = VMDragonSlayerAPI
