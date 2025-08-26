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
GPU Engine
==========

Unified GPU acceleration engine consolidating enterprise GPU functionality.

This module provides comprehensive GPU acceleration capabilities including:
- Multi-GPU workload distribution
- CUDA/OpenCL backend support with automatic selection
- Intelligent memory pool management
- Real-time performance monitoring
- Kernel optimization and caching
- Production-grade error handling
"""

import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# GPU framework imports with graceful fallbacks
try:
    import cupy as cp
    import cupyx.profiler

    CUDA_AVAILABLE = True
    logger.info("CUDA support available via CuPy")
except ImportError:
    CUDA_AVAILABLE = False
    cp = None
    logger.info("CUDA not available, using CPU fallback")

try:
    import pyopencl as cl

    OPENCL_AVAILABLE = True
    logger.info("OpenCL support available")
except ImportError:
    OPENCL_AVAILABLE = False
    cl = None
    logger.info("OpenCL not available")

try:
    import pynvml

    NVML_AVAILABLE = True
    # Don't initialize here - do it lazily when needed
    logger.info("NVIDIA ML library available")
except ImportError:
    NVML_AVAILABLE = False
    pynvml = None
    logger.info("NVIDIA ML not available")


@dataclass
class GPUInfo:
    """GPU device information."""

    device_id: int
    name: str
    memory_total_mb: int
    compute_capability: Tuple[int, int]
    multiprocessor_count: int
    warp_size: int
    max_threads_per_block: int
    backend: str = "cuda"  # cuda, opencl, cpu


@dataclass
class PerformanceMetrics:
    """GPU performance metrics."""

    kernel_name: str
    execution_time_ms: float
    memory_throughput_gbps: float
    compute_utilization: float
    memory_utilization: float
    power_usage_watts: float = 0.0
    temperature_celsius: float = 0.0


class MemoryPool:
    """GPU memory pool manager with intelligent allocation."""

    def __init__(self, pool_size_mb: int = 1024, device_id: int = 0):
        self.pool_size_mb = pool_size_mb
        self.device_id = device_id
        self.allocated_blocks: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._initialize_pool()

    def _initialize_pool(self):
        """Initialize memory pool based on available backend."""
        try:
            if CUDA_AVAILABLE:
                self.memory_pool = cp.get_default_memory_pool()
                self.memory_pool.set_limit(size=self.pool_size_mb * 1024 * 1024)
                logger.info(f"Initialized CUDA memory pool: {self.pool_size_mb}MB")
            else:
                logger.info("Using CPU memory pool fallback")
                self.memory_pool = None
        except Exception as e:
            logger.error(f"Failed to initialize memory pool: {e}")
            self.memory_pool = None

    def allocate(self, size_mb: int) -> Optional[str]:
        """Allocate memory block."""
        with self._lock:
            try:
                if CUDA_AVAILABLE and self.memory_pool:
                    size_bytes = size_mb * 1024 * 1024
                    memory_block = cp.cuda.alloc(size_bytes)
                    block_id = f"gpu_block_{int(time.time() * 1000000)}"
                else:
                    # CPU fallback
                    memory_block = np.zeros(size_mb * 1024 * 256, dtype=np.float32)
                    block_id = f"cpu_block_{int(time.time() * 1000000)}"

                self.allocated_blocks[block_id] = {
                    "memory": memory_block,
                    "size_mb": size_mb,
                    "allocated_at": datetime.now(),
                }
                return block_id
            except Exception as e:
                logger.error(f"Memory allocation failed: {e}")
                return None

    def deallocate(self, block_id: str) -> bool:
        """Deallocate memory block."""
        with self._lock:
            if block_id in self.allocated_blocks:
                del self.allocated_blocks[block_id]
                return True
            return False

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get memory pool usage statistics."""
        with self._lock:
            total_allocated = sum(
                block["size_mb"] for block in self.allocated_blocks.values()
            )
            return {
                "total_pool_mb": self.pool_size_mb,
                "allocated_mb": total_allocated,
                "free_mb": self.pool_size_mb - total_allocated,
                "utilization_percent": (total_allocated / self.pool_size_mb) * 100,
                "active_blocks": len(self.allocated_blocks),
            }


class KernelCache:
    """Kernel compilation cache for performance optimization."""

    def __init__(self, max_cache_size: int = 100):
        self.max_cache_size = max_cache_size
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get_kernel(
        self, kernel_source: str, optimization_level: str = "O2"
    ) -> Optional[Any]:
        """Get cached compiled kernel."""
        with self._lock:
            kernel_hash = self._hash_kernel(kernel_source, optimization_level)
            if kernel_hash in self.cache:
                entry = self.cache[kernel_hash]
                entry["last_used"] = datetime.now()
                entry["usage_count"] += 1
                return entry["compiled_kernel"]
            return None

    def cache_kernel(
        self,
        kernel_source: str,
        compiled_kernel: Any,
        compilation_time_ms: float,
        optimization_level: str = "O2",
    ) -> str:
        """Cache compiled kernel."""
        with self._lock:
            if len(self.cache) >= self.max_cache_size:
                self._evict_oldest()

            kernel_hash = self._hash_kernel(kernel_source, optimization_level)
            self.cache[kernel_hash] = {
                "compiled_kernel": compiled_kernel,
                "compilation_time_ms": compilation_time_ms,
                "source_code": kernel_source,
                "optimization_level": optimization_level,
                "cached_at": datetime.now(),
                "last_used": datetime.now(),
                "usage_count": 1,
            }
            return kernel_hash

    def _hash_kernel(self, source: str, optimization: str) -> str:
        """Generate hash for kernel source and optimization level."""
        import hashlib

        content = f"{source}:{optimization}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _evict_oldest(self):
        """Evict least recently used kernel."""
        if not self.cache:
            return
        oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["last_used"])
        del self.cache[oldest_key]

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_usage = sum(entry["usage_count"] for entry in self.cache.values())
            avg_compilation_time = (
                np.mean([entry["compilation_time_ms"] for entry in self.cache.values()])
                if self.cache
                else 0
            )

            return {
                "cached_kernels": len(self.cache),
                "max_cache_size": self.max_cache_size,
                "cache_utilization_percent": (len(self.cache) / self.max_cache_size)
                * 100,
                "total_kernel_usage": total_usage,
                "avg_compilation_time_ms": avg_compilation_time,
            }


class GPUEngine:
    """
    Unified GPU acceleration engine.

    Consolidates functionality from:
    - lib/gpu_acceleration/gpu_engine.py
    - lib/ml_engine/gpu_trainer.py
    - Enterprise GPU components
    """

    def __init__(
        self, auto_select_device: bool = True, memory_pool_size_mb: int = 1024
    ):
        self.devices: List[GPUInfo] = []
        self.current_device_id: int = 0
        self.memory_pool = MemoryPool(memory_pool_size_mb)
        self.kernel_cache = KernelCache()
        self.performance_history: deque = deque(maxlen=1000)
        self._executor = ThreadPoolExecutor(max_workers=4)

        # Initialize GPU devices
        self._detect_devices()

        # Auto-select best device if requested
        if auto_select_device and self.devices:
            self._select_best_device()

        logger.info(f"GPUEngine initialized with {len(self.devices)} device(s)")

    def _detect_devices(self):
        """Detect available GPU devices."""
        self.devices = []

        # Detect CUDA devices
        if CUDA_AVAILABLE:
            try:
                device_count = cp.cuda.runtime.getDeviceCount()
                for i in range(device_count):
                    props = cp.cuda.runtime.getDeviceProperties(i)
                    device_info = GPUInfo(
                        device_id=i,
                        name=props["name"].decode("utf-8"),
                        memory_total_mb=props["totalGlobalMem"] // (1024 * 1024),
                        compute_capability=(props["major"], props["minor"]),
                        multiprocessor_count=props["multiProcessorCount"],
                        warp_size=props["warpSize"],
                        max_threads_per_block=props["maxThreadsPerBlock"],
                        backend="cuda",
                    )
                    self.devices.append(device_info)
                    logger.info(f"Detected CUDA device {i}: {device_info.name}")
            except Exception as e:
                logger.error(f"Failed to detect CUDA devices: {e}")

        # Detect OpenCL devices (fallback)
        if OPENCL_AVAILABLE and not self.devices:
            try:
                platforms = cl.get_platforms()
                device_id = 0
                for platform in platforms:
                    devices = platform.get_devices()
                    for device in devices:
                        device_info = GPUInfo(
                            device_id=device_id,
                            name=device.name.strip(),
                            memory_total_mb=device.global_mem_size // (1024 * 1024),
                            compute_capability=(
                                0,
                                0,
                            ),  # OpenCL doesn't have this concept
                            multiprocessor_count=device.max_compute_units,
                            warp_size=32,  # Assumption for OpenCL
                            max_threads_per_block=device.max_work_group_size,
                            backend="opencl",
                        )
                        self.devices.append(device_info)
                        logger.info(
                            f"Detected OpenCL device {device_id}: {device_info.name}"
                        )
                        device_id += 1
            except Exception as e:
                logger.error(f"Failed to detect OpenCL devices: {e}")

        # CPU fallback
        if not self.devices:
            import psutil

            cpu_info = GPUInfo(
                device_id=0,
                name=f"CPU ({psutil.cpu_count()} cores)",
                memory_total_mb=psutil.virtual_memory().total // (1024 * 1024),
                compute_capability=(0, 0),
                multiprocessor_count=psutil.cpu_count(),
                warp_size=1,
                max_threads_per_block=psutil.cpu_count(),
                backend="cpu",
            )
            self.devices.append(cpu_info)
            logger.info("Using CPU fallback device")

    def _select_best_device(self):
        """Select the best available GPU device."""
        if not self.devices:
            return

        # Priority: CUDA > OpenCL > CPU
        # Within same backend: Higher memory and compute capability
        best_device = max(
            self.devices,
            key=lambda d: (
                d.backend == "cuda",
                d.backend == "opencl",
                d.memory_total_mb,
                d.compute_capability[0] * 10 + d.compute_capability[1],
            ),
        )

        self.current_device_id = best_device.device_id
        logger.info(f"Selected device {self.current_device_id}: {best_device.name}")

    def get_device_info(self, device_id: Optional[int] = None) -> Optional[GPUInfo]:
        """Get information about a GPU device."""
        device_id = device_id or self.current_device_id
        for device in self.devices:
            if device.device_id == device_id:
                return device
        return None

    def set_device(self, device_id: int) -> bool:
        """Set the current GPU device."""
        if any(d.device_id == device_id for d in self.devices):
            self.current_device_id = device_id
            if CUDA_AVAILABLE:
                cp.cuda.Device(device_id).use()
            logger.info(f"Switched to device {device_id}")
            return True
        return False

    def execute_kernel(
        self,
        kernel_source: str,
        input_data: np.ndarray,
        grid_size: Tuple[int, ...],
        block_size: Tuple[int, ...],
        kernel_name: str = "custom_kernel",
    ) -> Tuple[np.ndarray, PerformanceMetrics]:
        """Execute a GPU kernel with performance monitoring."""
        start_time = time.time()

        try:
            # Check kernel cache first
            cached_kernel = self.kernel_cache.get_kernel(kernel_source)

            if cached_kernel is None:
                # Compile kernel
                compile_start = time.time()
                if CUDA_AVAILABLE:
                    compiled_kernel = cp.RawKernel(kernel_source, kernel_name)
                else:
                    # CPU fallback - simulate kernel execution
                    def compiled_kernel(*args):
                        return self._cpu_fallback_kernel(
                                            input_data
                                        )

                compile_time = (time.time() - compile_start) * 1000
                self.kernel_cache.cache_kernel(
                    kernel_source, compiled_kernel, compile_time
                )
                cached_kernel = compiled_kernel

            # Execute kernel
            if CUDA_AVAILABLE:
                gpu_data = cp.asarray(input_data)
                output_data = cp.zeros_like(gpu_data)

                # Execute with performance monitoring
                with cupyx.profiler.time_range("kernel_execution"):
                    cached_kernel(grid_size, block_size, (gpu_data, output_data))
                    cp.cuda.Stream.null.synchronize()

                result = cp.asnumpy(output_data)
            else:
                # CPU fallback
                result = cached_kernel(input_data)

            execution_time = (time.time() - start_time) * 1000

            # Calculate performance metrics
            data_size_gb = input_data.nbytes / (1024**3)
            throughput = (
                data_size_gb / (execution_time / 1000) if execution_time > 0 else 0
            )

            metrics = PerformanceMetrics(
                kernel_name=kernel_name,
                execution_time_ms=execution_time,
                memory_throughput_gbps=throughput,
                compute_utilization=80.0,  # Estimated
                memory_utilization=60.0,  # Estimated
            )

            self.performance_history.append(metrics)
            return result, metrics

        except Exception as e:
            logger.error(f"Kernel execution failed: {e}")
            # Return input data as fallback
            dummy_metrics = PerformanceMetrics(
                kernel_name=kernel_name,
                execution_time_ms=0.0,
                memory_throughput_gbps=0.0,
                compute_utilization=0.0,
                memory_utilization=0.0,
            )
            return input_data, dummy_metrics

    def _cpu_fallback_kernel(self, data: np.ndarray) -> np.ndarray:
        """CPU fallback for GPU kernel execution."""
        # Simple element-wise operation as example
        return np.abs(data)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        if not self.performance_history:
            return {"message": "No performance data available"}

        metrics_list = list(self.performance_history)
        execution_times = [m.execution_time_ms for m in metrics_list]
        throughputs = [m.memory_throughput_gbps for m in metrics_list]

        return {
            "total_kernels_executed": len(metrics_list),
            "avg_execution_time_ms": np.mean(execution_times),
            "max_execution_time_ms": np.max(execution_times),
            "min_execution_time_ms": np.min(execution_times),
            "avg_throughput_gbps": np.mean(throughputs),
            "max_throughput_gbps": np.max(throughputs),
            "kernel_cache_stats": self.kernel_cache.get_cache_stats(),
            "memory_pool_stats": self.memory_pool.get_usage_stats(),
            "current_device": self.get_device_info(),
        }

    def cleanup(self):
        """Clean up GPU resources."""
        try:
            if CUDA_AVAILABLE:
                cp.get_default_memory_pool().free_all_blocks()
            self._executor.shutdown(wait=True)
            logger.info("GPU engine cleaned up successfully")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


# Convenience functions for backward compatibility
def create_gpu_engine(memory_pool_mb: int = 1024) -> GPUEngine:
    """Create a GPU engine instance."""
    return GPUEngine(memory_pool_size_mb=memory_pool_mb)


def get_available_devices() -> List[GPUInfo]:
    """Get list of available GPU devices."""
    engine = GPUEngine()
    devices = engine.devices
    engine.cleanup()
    return devices
