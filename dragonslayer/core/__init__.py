"""
VMDragonSlayer Core Module
=========================

Core functionality for the VMDragonSlayer library.

This module provides the foundational components for VM analysis,
including orchestration, configuration, and error handling.
"""

from .api import VMDragonSlayerAPI, get_api, analyze_file, analyze_binary_data, get_status
from .orchestrator import Orchestrator, AnalysisRequest, AnalysisResult, AnalysisType, WorkflowStrategy
from .config import (
    VMDragonSlayerConfig, ConfigManager, get_config, get_config_manager,
    get_ml_config, get_api_config, get_analysis_config, get_infrastructure_config,
    configure
)
from .exceptions import (
    VMDragonSlayerError, AnalysisError, BinaryAnalysisError, VMDetectionError,
    PatternAnalysisError, TaintTrackingError, SymbolicExecutionError,
    MLError, ModelLoadError, ModelTrainingError, ClassificationError,
    APIError, AuthenticationError, ValidationError,
    ConfigurationError, InvalidConfigurationError, ConfigurationNotFoundError,
    DataError, InvalidDataError, DataNotFoundError,
    ResourceError, MemoryError, DiskSpaceError, TimeoutError,
    NetworkError, ConnectionError,
    ComponentError, ComponentNotFoundError, ComponentInitializationError,
    WorkflowError, WorkflowExecutionError, WorkflowTimeoutError,
    handle_exception, create_error_response
)

__version__ = "1.0.0"
__author__ = "van1sh"
__description__ = "Core functionality for VM analysis and pattern detection"

# Public API
__all__ = [
    # Main API
    'VMDragonSlayerAPI',
    'get_api',
    'analyze_file',
    'analyze_binary_data',
    'get_status',
    
    # Orchestration
    'Orchestrator',
    'AnalysisRequest',
    'AnalysisResult',
    'AnalysisType',
    'WorkflowStrategy',
    
    # Configuration
    'VMDragonSlayerConfig',
    'ConfigManager',
    'get_config',
    'get_config_manager',
    'get_ml_config',
    'get_api_config', 
    'get_analysis_config',
    'get_infrastructure_config',
    'configure',
    
    # Exceptions
    'VMDragonSlayerError',
    'AnalysisError',
    'BinaryAnalysisError',
    'VMDetectionError',
    'PatternAnalysisError',
    'TaintTrackingError',
    'SymbolicExecutionError',
    'MLError',
    'ModelLoadError',
    'ModelTrainingError',
    'ClassificationError',
    'APIError',
    'AuthenticationError',
    'ValidationError',
    'ConfigurationError',
    'InvalidConfigurationError',
    'ConfigurationNotFoundError',
    'DataError',
    'InvalidDataError',
    'DataNotFoundError',
    'ResourceError',
    'MemoryError',
    'DiskSpaceError',
    'TimeoutError',
    'NetworkError',
    'ConnectionError',
    'ComponentError',
    'ComponentNotFoundError',
    'ComponentInitializationError',
    'WorkflowError',
    'WorkflowExecutionError',
    'WorkflowTimeoutError',
    'handle_exception',
    'create_error_response',
]
