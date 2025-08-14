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
Utilities Module
===============

Common utilities for VMDragonSlayer.
Consolidates utility functions from infrastructure and lib modules.
"""

from .memory import (
    MemoryManager,
    clear_memory_caches,
    get_memory_usage,
    memory_monitor,
    optimize_memory,
)
from .performance import (
    PerformanceMonitor,
    benchmark_function,
    get_system_metrics,
    measure_performance,
    profile_execution,
)
from .platform import (
    PlatformInfo,
    detect_vm_environment,
    get_cpu_features,
    get_platform_info,
    get_system_info,
)
from .validation import (
    ValidationResult,
    check_dependencies,
    validate_analysis_result,
    validate_binary_file,
    validate_config,
    validate_file_hash,
)

__all__ = [
    # Platform utilities
    "PlatformInfo",
    "get_platform_info",
    "detect_vm_environment",
    "get_cpu_features",
    "get_system_info",
    # Memory utilities
    "MemoryManager",
    "get_memory_usage",
    "optimize_memory",
    "memory_monitor",
    "clear_memory_caches",
    # Performance utilities
    "PerformanceMonitor",
    "measure_performance",
    "profile_execution",
    "benchmark_function",
    "get_system_metrics",
    # Validation utilities
    "ValidationResult",
    "validate_binary_file",
    "validate_analysis_result",
    "validate_config",
    "check_dependencies",
    "validate_file_hash",
]
