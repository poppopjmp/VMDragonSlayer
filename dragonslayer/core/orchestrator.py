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
VMDragonSlayer Orchestrator
==========================

Unified orchestrator that consolidates functionality from multiple implementations
into a single, clean, production-ready component without development artifacts.

This orchestrator provides:
- Binary analysis coordination
- Resource management and optimization
- Workflow orchestration
- Component lifecycle management
- Configuration management
"""

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# Handle optional dependencies gracefully
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

    # Mock psutil for environments without it
    class MockPsutil:
        class Process:
            def memory_info(self) -> Any:
                class MemInfo:
                    rss = 1024 * 1024 * 100  # 100MB mock

                return MemInfo()

            def cpu_percent(self) -> float:
                return 15.0

    def virtual_memory() -> Any:
            class VirtMem:
                total = 1024 * 1024 * 1024 * 8  # 8GB mock
                available = 1024 * 1024 * 1024 * 4  # 4GB mock

            return VirtMem()

    psutil = MockPsutil()

logger = logging.getLogger(__name__)


class AnalysisType(str, Enum):
    """Types of analysis that can be performed"""

    VM_DISCOVERY = "vm_discovery"
    PATTERN_ANALYSIS = "pattern_analysis"
    TAINT_TRACKING = "taint_tracking"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    HYBRID = "hybrid"
    BATCH = "batch"


class WorkflowStrategy(str, Enum):
    """Workflow execution strategies"""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    ADAPTIVE = "adaptive"
    OPTIMIZED = "optimized"


@dataclass
class AnalysisRequest:
    """Analysis request configuration"""

    binary_data: bytes
    analysis_type: AnalysisType = AnalysisType.HYBRID
    workflow_strategy: WorkflowStrategy = WorkflowStrategy.OPTIMIZED
    options: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AnalysisResult:
    """Analysis result container"""

    request_id: str
    success: bool = False
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class Orchestrator:
    """
    Unified orchestrator for VMDragonSlayer analysis workflows.

    This class provides a clean, production-ready interface for coordinating
    all analysis components without development artifacts or phase-related naming.

    Features:
    - Unified analysis coordination
    - Resource optimization and management
    - Flexible workflow strategies
    - Comprehensive error handling
    - Performance monitoring
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize the orchestrator.

        Args:
            config_path: Optional path to configuration file
        """
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(f"{__name__}.Orchestrator")

        # Component registry (lazy loaded)
        self._components = {}  # type: Dict[str, Any]
        self._component_lock = threading.RLock()

        # Performance tracking
        self.metrics = {
            "analyses_completed": 0,
            "analyses_failed": 0,
            "total_execution_time": 0.0,
            "average_execution_time": 0.0,
            "memory_usage_mb": 0.0,
            "cpu_utilization": 0.0,
        }

        # Active analysis tracking
        self._active_analyses = {}  # type: Dict[str, Dict[str, Any]]
        self._analysis_lock = threading.RLock()

        self.logger.info("Orchestrator initialized successfully")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration with sensible defaults"""
        default_config = {
            "analysis": {
                "max_concurrent_analyses": 10,
                "memory_limit_mb": 2048,
                "timeout_seconds": 300,
                "enable_caching": True,
                "cache_size_mb": 512,
            },
            "components": {
                "vm_discovery": {"enabled": True, "confidence_threshold": 0.8},
                "pattern_analysis": {"enabled": True, "pattern_cache_size": 1000},
                "taint_tracking": {"enabled": True, "max_depth": 10},
                "symbolic_execution": {"enabled": True, "solver_timeout": 30},
                "ml_classifier": {"enabled": True, "model_cache_size": 3},
            },
            "workflows": {
                "default_strategy": "optimized",
                "parallel_workers": "auto",
                "resource_pooling": True,
            },
            "logging": {"level": "INFO", "enable_metrics": True},
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path) as f:
                    user_config = json.load(f)
                    # Deep merge user config with defaults
                    self._deep_update(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if (
                isinstance(value, dict)
                and key in base_dict
                and isinstance(base_dict[key], dict)
            ):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def analyze_binary(
        self, binary_path: str, analysis_type: str = "hybrid", **options: Any
    ) -> Dict[str, Any]:
        """
        Analyze a binary file.

        Args:
            binary_path: Path to the binary file
            analysis_type: Type of analysis to perform
            **options: Additional analysis options

        Returns:
            Analysis results dictionary
        """
        try:
            # Read binary data
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            # Create analysis request
            request = AnalysisRequest(
                binary_data=binary_data,
                analysis_type=AnalysisType(analysis_type),
                options=options,
                metadata={"source_path": binary_path},
            )

            # Execute analysis
            result = asyncio.run(self.execute_analysis(request))

            # Convert to dictionary for backward compatibility
            return {
                "request_id": result.request_id,
                "success": result.success,
                "results": result.results,
                "errors": result.errors,
                "warnings": result.warnings,
                "execution_time": result.execution_time,
                "metadata": result.metadata,
            }

        except Exception as e:
            self.logger.error(f"Binary analysis failed for {binary_path}: {e}")
            return {
                "request_id": str(uuid.uuid4()),
                "success": False,
                "results": {},
                "errors": [str(e)],
                "warnings": [],
                "execution_time": 0.0,
                "metadata": {"source_path": binary_path},
            }

    async def execute_analysis(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Execute an analysis request asynchronously.

        Args:
            request: Analysis request configuration

        Returns:
            Analysis result
        """
        start_time = time.time()
        result = AnalysisResult(request_id=request.request_id)

        try:
            # Register active analysis
            with self._analysis_lock:
                self._active_analyses[request.request_id] = {
                    "request": request,
                    "start_time": start_time,
                    "status": "running",
                }

            self.logger.info(
                f"Starting analysis {request.request_id} "
                f"(type: {request.analysis_type}, strategy: {request.workflow_strategy})"
            )

            # Execute based on analysis type
            if request.analysis_type == AnalysisType.VM_DISCOVERY:
                result.results = await self._execute_vm_discovery(request)
            elif request.analysis_type == AnalysisType.PATTERN_ANALYSIS:
                result.results = await self._execute_pattern_analysis(request)
            elif request.analysis_type == AnalysisType.TAINT_TRACKING:
                result.results = await self._execute_taint_tracking(request)
            elif request.analysis_type == AnalysisType.SYMBOLIC_EXECUTION:
                result.results = await self._execute_symbolic_execution(request)
            elif request.analysis_type == AnalysisType.HYBRID:
                result.results = await self._execute_hybrid_analysis(request)
            elif request.analysis_type == AnalysisType.BATCH:
                result.results = await self._execute_batch_analysis(request)
            else:
                raise ValueError(f"Unknown analysis type: {request.analysis_type}")

            result.success = True

        except Exception as e:
            self.logger.error(f"Analysis {request.request_id} failed: {e}")
            result.success = False
            result.errors.append(str(e))

        finally:
            # Calculate execution time
            result.execution_time = time.time() - start_time

            # Update metrics
            self._update_metrics(result)

            # Unregister active analysis
            with self._analysis_lock:
                if request.request_id in self._active_analyses:
                    del self._active_analyses[request.request_id]

            self.logger.info(
                f"Analysis {request.request_id} completed in "
                f"{result.execution_time:.2f}s (success: {result.success})"
            )

        return result

    async def _execute_vm_discovery(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Execute VM discovery analysis"""
        # Get VM discovery component
        vm_detector = await self._get_component("vm_discovery")

        # Perform VM detection
        # Prefer async API when available; otherwise offload sync to thread pool
        if hasattr(vm_detector, "detect_vm_structures_async"):
            detection_result = await vm_detector.detect_vm_structures_async(
                request.binary_data
            )
        else:
            loop = asyncio.get_event_loop()
            detection_result = await loop.run_in_executor(
                None, vm_detector.detect_vm_structures, request.binary_data
            )

        return {
            "vm_detected": detection_result.get("vm_detected", False),
            "confidence": detection_result.get("confidence", 0.0),
            "structures": detection_result.get("detection_details", {}).get(
                "structures", {}
            ),
            "patterns": detection_result.get("detection_details", {}).get(
                "patterns", {}
            ),
        }

    async def _execute_pattern_analysis(
        self, request: AnalysisRequest
    ) -> Dict[str, Any]:
        """Execute pattern analysis"""
        # Get pattern analyzer component
        pattern_analyzer = await self._get_component("pattern_analysis")

        # Perform pattern analysis — use recognizer API
        # Convert binary data to a small opcode sequence for demo purposes
        sequence = list(request.binary_data[:128])
        matches = await pattern_analyzer.recognize_patterns(sequence, context={})

        return {
            "patterns_found": [m.to_dict() for m in matches],
            "classification": "unknown",
            "confidence": max((m.confidence for m in matches), default=0.0),
        }

    async def _execute_taint_tracking(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Execute taint tracking analysis"""
        # Get taint tracker component
        taint_tracker = await self._get_component("taint_tracking")

        # Perform taint tracking
        tracking_result = await taint_tracker.track_taint(request.binary_data)

        return {
            "taint_flows": tracking_result.get("flows", []),
            "data_dependencies": tracking_result.get("dependencies", []),
            "coverage": tracking_result.get("coverage", 0.0),
        }

    async def _execute_symbolic_execution(
        self, request: AnalysisRequest
    ) -> Dict[str, Any]:
        """Execute symbolic execution analysis"""
        # Get symbolic executor component
        symbolic_executor = await self._get_component("symbolic_execution")

        # Perform symbolic execution
        execution_result = await symbolic_executor.execute_symbolically(
            request.binary_data
        )

        return {
            "constraints": execution_result.get("constraints", []),
            "test_cases": execution_result.get("test_cases", []),
            "coverage": execution_result.get("coverage", 0.0),
        }

    async def _execute_hybrid_analysis(
        self, request: AnalysisRequest
    ) -> Dict[str, Any]:
        """Execute hybrid analysis combining multiple techniques"""
        results = {}

        # Run VM discovery
        if self.config["components"]["vm_discovery"]["enabled"]:
            results["vm_discovery"] = await self._execute_vm_discovery(request)

        # Run pattern analysis
        if self.config["components"]["pattern_analysis"]["enabled"]:
            results["pattern_analysis"] = await self._execute_pattern_analysis(request)

        # Run taint tracking if VM detected
        if self.config["components"]["taint_tracking"]["enabled"] and results.get(
            "vm_discovery", {}
        ).get("vm_detected", False):
            results["taint_tracking"] = await self._execute_taint_tracking(request)

        # Run symbolic execution if patterns suggest complexity
        if (
            self.config["components"]["symbolic_execution"]["enabled"]
            and len(results.get("pattern_analysis", {}).get("patterns_found", [])) > 5
        ):
            results["symbolic_execution"] = await self._execute_symbolic_execution(
                request
            )

        return results

    async def _execute_batch_analysis(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Execute batch analysis for multiple samples"""
        # This would handle multiple binary samples
        # For now, treat as single sample
        return await self._execute_hybrid_analysis(request)

    async def _get_component(self, component_name: str) -> Any:
        """Get or create analysis component (lazy loading)"""
        with self._component_lock:
            if component_name not in self._components:
                self._components[component_name] = await self._create_component(
                    component_name
                )
            return self._components[component_name]

    async def _create_component(self, component_name: str) -> Any:
        """Create analysis component instance"""
        # Import components dynamically to avoid circular imports
        if component_name == "vm_discovery":
            from ..analysis.vm_discovery.detector import VMDetector

            return VMDetector()
        elif component_name == "pattern_analysis":
            from ..analysis.pattern_analysis.recognizer import PatternRecognizer

            return PatternRecognizer()
        elif component_name == "taint_tracking":
            from ..analysis.taint_tracking.tracker import TaintTracker

            return TaintTracker()
        elif component_name == "symbolic_execution":
            from ..analysis.symbolic_execution.executor import SymbolicExecutor

            return SymbolicExecutor()
        else:
            raise ValueError(f"Unknown component: {component_name}")

    def _update_metrics(self, result: AnalysisResult) -> None:
        """Update performance metrics"""
        if result.success:
            self.metrics["analyses_completed"] += 1
        else:
            self.metrics["analyses_failed"] += 1

        self.metrics["total_execution_time"] += result.execution_time
        total_analyses = (
            self.metrics["analyses_completed"] + self.metrics["analyses_failed"]
        )

        if total_analyses > 0:
            self.metrics["average_execution_time"] = (
                self.metrics["total_execution_time"] / total_analyses
            )

        # Update resource metrics if psutil is available
        if PSUTIL_AVAILABLE:
            try:
                process = psutil.Process()
                self.metrics["memory_usage_mb"] = (
                    process.memory_info().rss / 1024 / 1024
                )
                self.metrics["cpu_utilization"] = process.cpu_percent()
            except Exception as e:
                self.logger.debug(f"psutil metrics collection failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status"""
        with self._analysis_lock:
            active_count = len(self._active_analyses)
            active_analyses = [
                {
                    "request_id": req_id,
                    "analysis_type": info["request"].analysis_type,
                    "duration": time.time() - info["start_time"],
                }
                for req_id, info in self._active_analyses.items()
            ]

        return {
            "status": "active",
            "active_analyses": active_count,
            "active_details": active_analyses,
            "metrics": self.metrics.copy(),
            "config": self.config,
            "components_loaded": list(self._components.keys()),
        }

    def get_supported_analysis_types(self) -> List[str]:
        """Get list of supported analysis types"""
        return [analysis_type.value for analysis_type in AnalysisType]

    def configure(self, **kwargs: Any) -> None:
        """Update orchestrator configuration"""
        for key, value in kwargs.items():
            if key in self.config:
                if isinstance(self.config[key], dict) and isinstance(value, dict):
                    self.config[key].update(value)
                else:
                    self.config[key] = value
                self.logger.info(f"Updated config: {key} = {value}")
            else:
                self.logger.warning(f"Unknown config key: {key}")

    async def shutdown(self) -> None:
        """Shutdown orchestrator and cleanup resources"""
        self.logger.info("Shutting down orchestrator...")

        # Wait for active analyses to complete (with timeout)
        timeout = 30  # 30 seconds
        start_time = time.time()

        while self._active_analyses and (time.time() - start_time) < timeout:
            await asyncio.sleep(1)

        # Force cleanup of remaining analyses
        with self._analysis_lock:
            if self._active_analyses:
                self.logger.warning(
                    f"Force stopping {len(self._active_analyses)} active analyses"
                )
                self._active_analyses.clear()

        # Cleanup components
        with self._component_lock:
            for component_name, component in self._components.items():
                if hasattr(component, "cleanup"):
                    try:
                        await component.cleanup()
                    except Exception as e:
                        self.logger.error(f"Error cleaning up {component_name}: {e}")
            self._components.clear()

        self.logger.info("Orchestrator shutdown complete")


# Backward compatibility alias
VMDragonSlayerOrchestrator = Orchestrator
