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
VMDragonSlayer Core Exceptions
=============================

Centralized exception handling for the VMDragonSlayer system.
Provides a hierarchy of specific exceptions for different error categories.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VMDragonSlayerError(Exception):
    """
    Base exception for VMDragonSlayer system.

    All VMDragonSlayer exceptions inherit from this base class,
    providing consistent error handling and logging.
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        """
        Initialize VMDragonSlayer error.

        Args:
            message: Human-readable error message
            error_code: Optional error code for programmatic handling
            details: Optional dictionary with additional error details
            cause: Optional underlying exception that caused this error
        """
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.cause = cause

        super().__init__(self.message)

        # Log the error
        logger.error(
            f"{self.__class__.__name__}: {message} "
            f"(code: {error_code}, details: {self.details})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for serialization"""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
            "cause": str(self.cause) if self.cause else None,
        }


class AnalysisError(VMDragonSlayerError):
    """Errors related to VM analysis operations"""

    pass


class BinaryAnalysisError(AnalysisError):
    """Errors specific to binary file analysis"""

    pass


class VMDetectionError(AnalysisError):
    """Errors related to virtual machine detection"""

    pass


class PatternAnalysisError(AnalysisError):
    """Errors related to pattern detection and analysis"""

    pass


class TaintTrackingError(AnalysisError):
    """Errors related to dynamic taint tracking"""

    pass


class SymbolicExecutionError(AnalysisError):
    """Errors related to symbolic execution"""

    pass


class MLError(VMDragonSlayerError):
    """Errors related to machine learning operations"""

    pass


class ModelLoadError(MLError):
    """Errors when loading ML models"""

    pass


class ModelTrainingError(MLError):
    """Errors during ML model training"""

    pass


class ClassificationError(MLError):
    """Errors during pattern classification"""

    pass


class APIError(VMDragonSlayerError):
    """Errors related to API operations"""

    pass


class AuthenticationError(APIError):
    """Authentication and authorization errors"""

    pass


class ValidationError(APIError):
    """Request validation errors"""

    pass


class ConfigurationError(VMDragonSlayerError):
    """Errors related to system configuration"""

    pass


class InvalidConfigurationError(ConfigurationError):
    """Invalid configuration values"""

    pass


class ConfigurationNotFoundError(ConfigurationError):
    """Configuration file not found"""

    pass


class DataError(VMDragonSlayerError):
    """Errors related to data processing and validation"""

    pass


class InvalidDataError(DataError):
    """Invalid or corrupted data"""

    pass


class DataNotFoundError(DataError):
    """Required data not found"""

    pass


class ResourceError(VMDragonSlayerError):
    """Errors related to system resources"""

    pass


class MemoryError(ResourceError):
    """Memory-related errors"""

    pass


class DiskSpaceError(ResourceError):
    """Disk space related errors"""

    pass


class TimeoutError(ResourceError):
    """Operation timeout errors"""

    pass


class NetworkError(VMDragonSlayerError):
    """Errors related to network operations"""

    pass


class ConnectionError(NetworkError):
    """Network connection errors"""

    pass


class ComponentError(VMDragonSlayerError):
    """Errors related to component lifecycle and management"""

    pass


class ComponentNotFoundError(ComponentError):
    """Component not found or not available"""

    pass


class UIError(VMDragonSlayerError):
    """Errors related to user interface components"""

    pass


class ComponentInitializationError(ComponentError):
    """Component initialization failed"""

    pass


class WorkflowError(VMDragonSlayerError):
    """Errors related to workflow execution"""

    pass


class WorkflowExecutionError(WorkflowError):
    """Workflow execution failed"""

    pass


class WorkflowTimeoutError(WorkflowError):
    """Workflow execution timed out"""

    pass


def handle_exception(func):
    """
    Decorator for consistent exception handling.

    Wraps functions to catch and convert generic exceptions
    to VMDragonSlayer-specific exceptions.
    """

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except VMDragonSlayerError:
            # Re-raise VMDragonSlayer exceptions as-is
            raise
        except Exception as e:
            # Convert generic exceptions to VMDragonSlayerError
            raise VMDragonSlayerError(
                f"Unexpected error in {func.__name__}: {str(e)}",
                error_code="UNEXPECTED_ERROR",
                cause=e,
            ) from e

    return wrapper


def create_error_response(error: Exception) -> Dict[str, Any]:
    """
    Create standardized error response dictionary.

    Args:
        error: Exception to convert to response

    Returns:
        Dictionary suitable for API error responses
    """
    if isinstance(error, VMDragonSlayerError):
        return {"success": False, "error": error.to_dict()}
    else:
        return {
            "success": False,
            "error": {
                "error_type": "UnexpectedError",
                "message": str(error),
                "error_code": "UNEXPECTED_ERROR",
            },
        }


def validate_not_none(value: Any, name: str) -> None:
    """Validate that a value is not None"""
    if value is None:
        raise InvalidDataError(f"{name} cannot be None")


def validate_not_empty(value: str, name: str) -> None:
    """Validate that a string is not empty"""
    if not value or not value.strip():
        raise InvalidDataError(f"{name} cannot be empty")


def validate_type(value: Any, expected_type: type, name: str) -> None:
    """Validate that a value is of expected type"""
    if not isinstance(value, expected_type):
        raise InvalidDataError(
            f"{name} must be of type {expected_type.__name__}, "
            f"got {type(value).__name__}"
        )


def validate_range(value: float, min_val: float, max_val: float, name: str) -> None:
    """Validate that a numeric value is within range"""
    if not min_val <= value <= max_val:
        raise InvalidDataError(
            f"{name} must be between {min_val} and {max_val}, got {value}"
        )


def validate_choices(value: Any, choices: List[Any], name: str) -> None:
    """Validate that a value is one of allowed choices"""
    if value not in choices:
        raise InvalidDataError(f"{name} must be one of {choices}, got {value}")


# Legacy compatibility aliases for backward compatibility
class VMAnalysisError(AnalysisError):
    """Legacy alias for AnalysisError"""

    pass


class MLModelError(MLError):
    """Legacy alias for MLError"""

    pass


class PatternError(PatternAnalysisError):
    """Legacy alias for PatternAnalysisError"""

    pass


class ModelError(MLError):
    """Legacy alias for MLError"""

    pass
