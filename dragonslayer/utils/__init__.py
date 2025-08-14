"""
Utilities Module
===============

Common utilities for VMDragonSlayer.
Consolidates utility functions from infrastructure and lib modules.
"""

from .platform import (
    PlatformInfo,
    get_platform_info,
    detect_vm_environment,
    get_cpu_features,
    get_system_info
)

from .memory import (
    MemoryManager,
    get_memory_usage,
    optimize_memory,
    memory_monitor,
    clear_memory_caches
)

from .performance import (
    PerformanceMonitor,
    measure_performance,
    profile_execution,
    benchmark_function,
    get_system_metrics
)

from .validation import (
    ValidationResult,
    validate_binary_file,
    validate_analysis_result,
    validate_config,
    check_dependencies,
    validate_file_hash
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
    "validate_file_hash"
]
