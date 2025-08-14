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
VMDragonSlayer Core Module
=========================

Core functionality for the VMDragonSlayer library.

This module provides the foundational components for VM analysis,
including orchestration, configuration, and error handling.
"""

from .api import (
    VMDragonSlayerAPI,
    analyze_binary_data,
    analyze_file,
    get_api,
    get_status,
)
from .config import (
    ConfigManager,
    VMDragonSlayerConfig,
    configure,
    get_analysis_config,
    get_api_config,
    get_config,
    get_config_manager,
    get_infrastructure_config,
    get_ml_config,
)
from .exceptions import (
    AnalysisError,
    APIError,
    AuthenticationError,
    BinaryAnalysisError,
    ClassificationError,
    ComponentError,
    ComponentInitializationError,
    ComponentNotFoundError,
    ConfigurationError,
    ConfigurationNotFoundError,
    ConnectionError,
    DataError,
    DataNotFoundError,
    DiskSpaceError,
    InvalidConfigurationError,
    InvalidDataError,
    MemoryError,
    MLError,
    ModelLoadError,
    ModelTrainingError,
    NetworkError,
    PatternAnalysisError,
    ResourceError,
    SymbolicExecutionError,
    TaintTrackingError,
    TimeoutError,
    ValidationError,
    VMDetectionError,
    VMDragonSlayerError,
    WorkflowError,
    WorkflowExecutionError,
    WorkflowTimeoutError,
    create_error_response,
    handle_exception,
)
from .orchestrator import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisType,
    Orchestrator,
    WorkflowStrategy,
)

__version__ = "1.0.0"
__author__ = "van1sh"
__description__ = "Core functionality for VM analysis and pattern detection"

# Public API
__all__ = [
    # Main API
    "VMDragonSlayerAPI",
    "get_api",
    "analyze_file",
    "analyze_binary_data",
    "get_status",
    # Orchestration
    "Orchestrator",
    "AnalysisRequest",
    "AnalysisResult",
    "AnalysisType",
    "WorkflowStrategy",
    # Configuration
    "VMDragonSlayerConfig",
    "ConfigManager",
    "get_config",
    "get_config_manager",
    "get_ml_config",
    "get_api_config",
    "get_analysis_config",
    "get_infrastructure_config",
    "configure",
    # Exceptions
    "VMDragonSlayerError",
    "AnalysisError",
    "BinaryAnalysisError",
    "VMDetectionError",
    "PatternAnalysisError",
    "TaintTrackingError",
    "SymbolicExecutionError",
    "MLError",
    "ModelLoadError",
    "ModelTrainingError",
    "ClassificationError",
    "APIError",
    "AuthenticationError",
    "ValidationError",
    "ConfigurationError",
    "InvalidConfigurationError",
    "ConfigurationNotFoundError",
    "DataError",
    "InvalidDataError",
    "DataNotFoundError",
    "ResourceError",
    "MemoryError",
    "DiskSpaceError",
    "TimeoutError",
    "NetworkError",
    "ConnectionError",
    "ComponentError",
    "ComponentNotFoundError",
    "ComponentInitializationError",
    "WorkflowError",
    "WorkflowExecutionError",
    "WorkflowTimeoutError",
    "handle_exception",
    "create_error_response",
]
