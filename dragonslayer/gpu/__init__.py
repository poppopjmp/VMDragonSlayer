"""
GPU Acceleration Module
========================

Provides GPU-accelerated pattern matching, symbolic execution, and
feature extraction for VMDragonSlayer.

All classes are **interface stubs** until a CUDA / OpenCL backend is
integrated.  Importing this module always succeeds — GPU availability
is checked at runtime via :func:`gpu_available`.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_HAS_CUDA = False
try:
    import cupy  # type: ignore[import-untyped]
    _HAS_CUDA = True
except Exception:
    pass


def gpu_available() -> bool:
    """Return *True* if a usable GPU backend is detected."""
    return _HAS_CUDA


# Guarded imports from submodules
try:
    from .engine import GPUEngine
except (ImportError, AttributeError):
    GPUEngine = None  # type: ignore[assignment,misc]

try:
    from .memory import GPUMemoryManager
except (ImportError, AttributeError):
    GPUMemoryManager = None  # type: ignore[assignment,misc]

try:
    from .optimizer import GPUOptimizer
except (ImportError, AttributeError):
    GPUOptimizer = None  # type: ignore[assignment,misc]

try:
    from .profiler import GPUProfiler
except (ImportError, AttributeError):
    GPUProfiler = None  # type: ignore[assignment,misc]


__all__ = [
    "gpu_available",
    "GPUEngine",
    "GPUMemoryManager",
    "GPUOptimizer",
    "GPUProfiler",
]
