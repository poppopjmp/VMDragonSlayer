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
VMDragonSlayer Core API
======================

Core API interface that provides a unified, clean interface to all
VMDragonSlayer functionality without development artifacts.
"""

import asyncio
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import get_config
from .exceptions import (
    AnalysisError,
    InvalidDataError,
    VMDragonSlayerError,
    validate_not_none,
    validate_type,
)
from .orchestrator import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisType,
    Orchestrator,
    WorkflowStrategy,
)

logger = logging.getLogger(__name__)


class VMDragonSlayerAPI:
    """
    Unified API for VMDragonSlayer functionality.

    This class provides a clean, production-ready interface to all
    VMDragonSlayer capabilities without development artifacts or
    phase-related naming conventions.

    Features:
    - Binary analysis coordination
    - Multiple analysis types (VM discovery, pattern analysis, etc.)
    - Workflow management
    - Configuration management
    - Status monitoring
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize VMDragonSlayer API.

        Args:
            config_path: Optional path to configuration file
        """
        self.config = get_config(config_path)
        self.logger = logging.getLogger(f"{__name__}.API")
        self.orchestrator = Orchestrator(config_path)
        self._initialized = True

        self.logger.info("VMDragonSlayer API initialized")

    def analyze_file(
        self, file_path: str, analysis_type: str = "hybrid", **options
    ) -> Dict[str, Any]:
        """
        Analyze a binary file.

        Args:
            file_path: Path to the binary file to analyze
            analysis_type: Type of analysis to perform
            **options: Additional analysis options

        Returns:
            Dictionary containing analysis results

        Raises:
            AnalysisError: If analysis fails
            InvalidDataError: If file path is invalid
        """
        validate_not_none(file_path, "file_path")
        validate_type(file_path, str, "file_path")

        file_path = Path(file_path)
        if not file_path.exists():
            raise InvalidDataError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise InvalidDataError(f"Path is not a file: {file_path}")

        try:
            result = self.orchestrator.analyze_binary(
                str(file_path), analysis_type=analysis_type, **options
            )

            self.logger.info(
                f"File analysis completed: {file_path} "
                f"(success: {result.get('success', False)})"
            )

            return result

        except Exception as e:
            self.logger.error(f"File analysis failed: {file_path}: {e}")
            raise AnalysisError(
                f"Failed to analyze file: {file_path}",
                error_code="FILE_ANALYSIS_FAILED",
                cause=e,
            ) from e

    def analyze_binary_data(
        self,
        binary_data: bytes,
        analysis_type: str = "hybrid",
        metadata: Optional[Dict[str, Any]] = None,
        **options,
    ) -> Dict[str, Any]:
        """
        Analyze binary data directly.

        Args:
            binary_data: Binary data to analyze
            analysis_type: Type of analysis to perform
            metadata: Optional metadata about the binary
            **options: Additional analysis options

        Returns:
            Dictionary containing analysis results

        Raises:
            AnalysisError: If analysis fails
            InvalidDataError: If binary data is invalid
        """
        validate_not_none(binary_data, "binary_data")
        validate_type(binary_data, (bytes, bytearray), "binary_data")

        if len(binary_data) == 0:
            raise InvalidDataError("Binary data cannot be empty")

        try:
            # Create analysis request
            request = AnalysisRequest(
                binary_data=binary_data,
                analysis_type=AnalysisType(analysis_type),
                metadata=metadata or {},
                options=options,
            )

            # Execute analysis
            result = asyncio.run(self.orchestrator.execute_analysis(request))

            # Convert to dictionary
            result_dict = {
                "request_id": result.request_id,
                "success": result.success,
                "results": result.results,
                "errors": result.errors,
                "warnings": result.warnings,
                "execution_time": result.execution_time,
                "metadata": result.metadata,
            }

            self.logger.info(
                f"Binary analysis completed: {request.request_id} "
                f"(success: {result.success})"
            )

            return result_dict

        except Exception as e:
            self.logger.error(f"Binary analysis failed: {e}")
            raise AnalysisError(
                "Failed to analyze binary data",
                error_code="BINARY_ANALYSIS_FAILED",
                cause=e,
            ) from e

    async def analyze_binary_data_async(
        self,
        binary_data: bytes,
        analysis_type: str = "hybrid",
        metadata: Optional[Dict[str, Any]] = None,
        **options,
    ) -> AnalysisResult:
        """
        Analyze binary data asynchronously.

        Args:
            binary_data: Binary data to analyze
            analysis_type: Type of analysis to perform
            metadata: Optional metadata about the binary
            **options: Additional analysis options

        Returns:
            AnalysisResult object

        Raises:
            AnalysisError: If analysis fails
            InvalidDataError: If binary data is invalid
        """
        validate_not_none(binary_data, "binary_data")
        validate_type(binary_data, (bytes, bytearray), "binary_data")

        if len(binary_data) == 0:
            raise InvalidDataError("Binary data cannot be empty")

        try:
            request = AnalysisRequest(
                binary_data=binary_data,
                analysis_type=AnalysisType(analysis_type),
                metadata=metadata or {},
                options=options,
            )

            result = await self.orchestrator.execute_analysis(request)

            self.logger.info(
                f"Async binary analysis completed: {request.request_id} "
                f"(success: {result.success})"
            )

            return result

        except Exception as e:
            self.logger.error(f"Async binary analysis failed: {e}")
            raise AnalysisError(
                "Failed to analyze binary data asynchronously",
                error_code="ASYNC_BINARY_ANALYSIS_FAILED",
                cause=e,
            ) from e

    def detect_vm_structures(self, file_path: str) -> Dict[str, Any]:
        """
        Detect virtual machine structures in a binary file.

        Args:
            file_path: Path to the binary file

        Returns:
            Dictionary containing VM detection results
        """
        return self.analyze_file(file_path, analysis_type="vm_discovery")

    def analyze_patterns(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze patterns in a binary file.

        Args:
            file_path: Path to the binary file

        Returns:
            Dictionary containing pattern analysis results
        """
        return self.analyze_file(file_path, analysis_type="pattern_analysis")

    def track_taint(self, file_path: str, **options) -> Dict[str, Any]:
        """
        Perform taint tracking analysis on a binary file.

        Args:
            file_path: Path to the binary file
            **options: Taint tracking options

        Returns:
            Dictionary containing taint tracking results
        """
        return self.analyze_file(file_path, analysis_type="taint_tracking", **options)

    def execute_symbolically(self, file_path: str, **options) -> Dict[str, Any]:
        """
        Perform symbolic execution on a binary file.

        Args:
            file_path: Path to the binary file
            **options: Symbolic execution options

        Returns:
            Dictionary containing symbolic execution results
        """
        return self.analyze_file(
            file_path, analysis_type="symbolic_execution", **options
        )

    def get_status(self) -> Dict[str, Any]:
        """
        Get current API and orchestrator status.

        Returns:
            Dictionary containing status information
        """
        try:
            orchestrator_status = self.orchestrator.get_status()

            return {
                "api_status": "active",
                "initialized": self._initialized,
                "version": self.config.version,
                "orchestrator": orchestrator_status,
                "configuration": {
                    "analysis": asdict(self.config.analysis),
                    "ml": asdict(self.config.ml),
                    "infrastructure": asdict(self.config.infrastructure),
                },
            }

        except Exception as e:
            self.logger.error(f"Failed to get status: {e}")
            return {
                "api_status": "error",
                "initialized": self._initialized,
                "error": str(e),
            }

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics.

        Returns:
            Dictionary containing performance metrics
        """
        try:
            status = self.orchestrator.get_status()
            return status.get("metrics", {})

        except Exception as e:
            self.logger.error(f"Failed to get metrics: {e}")
            return {"error": str(e)}

    def configure(self, **kwargs) -> None:
        """
        Update API configuration.

        Args:
            **kwargs: Configuration updates
        """
        try:
            self.orchestrator.configure(**kwargs)
            self.logger.info(f"Configuration updated: {kwargs}")

        except Exception as e:
            self.logger.error(f"Configuration update failed: {e}")
            raise VMDragonSlayerError(
                f"Failed to update configuration: {e}",
                error_code="CONFIG_UPDATE_FAILED",
                cause=e,
            ) from e

    def get_supported_analysis_types(self) -> List[str]:
        """
        Get list of supported analysis types.

        Returns:
            List of supported analysis type strings
        """
        return [analysis_type.value for analysis_type in AnalysisType]

    def get_supported_workflow_strategies(self) -> List[str]:
        """
        Get list of supported workflow strategies.

        Returns:
            List of supported workflow strategy strings
        """
        return [strategy.value for strategy in WorkflowStrategy]

    def validate_binary(self, file_path: str) -> Dict[str, Any]:
        """
        Validate that a file is a valid binary for analysis.

        Args:
            file_path: Path to the file to validate

        Returns:
            Dictionary containing validation results
        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                return {
                    "valid": False,
                    "reason": "File does not exist",
                    "path": str(file_path),
                }

            if not file_path.is_file():
                return {
                    "valid": False,
                    "reason": "Path is not a file",
                    "path": str(file_path),
                }

            # Check file size
            file_size = file_path.stat().st_size
            max_size = self.config.api.max_file_size_mb * 1024 * 1024

            if file_size > max_size:
                return {
                    "valid": False,
                    "reason": f"File too large ({file_size} bytes, max: {max_size})",
                    "path": str(file_path),
                    "size": file_size,
                }

            if file_size == 0:
                return {
                    "valid": False,
                    "reason": "File is empty",
                    "path": str(file_path),
                    "size": file_size,
                }

            return {"valid": True, "path": str(file_path), "size": file_size}

        except Exception as e:
            return {
                "valid": False,
                "reason": f"Validation error: {e}",
                "path": str(file_path) if "file_path" in locals() else "unknown",
            }

    async def shutdown(self) -> None:
        """Shutdown API and cleanup resources"""
        try:
            self.logger.info("Shutting down VMDragonSlayer API...")
            await self.orchestrator.shutdown()
            self._initialized = False
            self.logger.info("VMDragonSlayer API shutdown complete")

        except Exception as e:
            self.logger.error(f"Error during API shutdown: {e}")
            raise VMDragonSlayerError(
                f"Failed to shutdown API: {e}", error_code="SHUTDOWN_FAILED", cause=e
            ) from e

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        asyncio.run(self.shutdown())

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.shutdown()


# Global API instance for convenience
_api_instance = None


def get_api(config_path: Optional[str] = None) -> VMDragonSlayerAPI:
    """Get global API instance"""
    global _api_instance
    if _api_instance is None:
        _api_instance = VMDragonSlayerAPI(config_path)
    return _api_instance


def analyze_file(file_path: str, **kwargs) -> Dict[str, Any]:
    """Convenience function for file analysis"""
    return get_api().analyze_file(file_path, **kwargs)


def analyze_binary_data(binary_data: bytes, **kwargs) -> Dict[str, Any]:
    """Convenience function for binary data analysis"""
    return get_api().analyze_binary_data(binary_data, **kwargs)


def get_status() -> Dict[str, Any]:
    """Convenience function to get status"""
    return get_api().get_status()
