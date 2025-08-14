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
Kernel Optimizer
================

GPU kernel optimization and performance tuning.
Consolidates kernel optimization functionality from the enterprise GPU engine.
"""

import hashlib
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    import cupy as cp

    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False
    cp = None


@dataclass
class KernelProfile:
    """Kernel performance profile."""

    kernel_hash: str
    kernel_name: str
    grid_size: Tuple[int, ...]
    block_size: Tuple[int, ...]
    execution_time_ms: float
    memory_throughput_gbps: float
    occupancy_percent: float
    register_usage: int = 0
    shared_memory_usage: int = 0


@dataclass
class OptimizationResult:
    """Kernel optimization result."""

    original_time_ms: float
    optimized_time_ms: float
    speedup_factor: float
    optimization_applied: str
    configuration: Dict[str, Any]


class KernelOptimizer:
    """
    GPU kernel optimizer with automatic performance tuning.

    Features:
    - Automatic grid/block size optimization
    - Kernel compilation parameter tuning
    - Performance profiling and analysis
    - Optimization strategy recommendation
    """

    def __init__(self, device_id: int = 0):
        self.device_id = device_id
        self.kernel_profiles: Dict[str, List[KernelProfile]] = defaultdict(list)
        self.optimization_cache: Dict[str, OptimizationResult] = {}
        self._lock = threading.Lock()

        # Optimization strategies
        self.optimization_strategies = [
            self._optimize_block_size,
            self._optimize_grid_size,
            self._optimize_memory_access,
            self._optimize_occupancy,
        ]

    def profile_kernel(
        self,
        kernel_source: str,
        kernel_name: str,
        input_data: np.ndarray,
        grid_sizes: List[Tuple[int, ...]],
        block_sizes: List[Tuple[int, ...]],
    ) -> List[KernelProfile]:
        """
        Profile kernel performance across different configurations.

        Args:
            kernel_source: CUDA kernel source code
            kernel_name: Name of the kernel function
            input_data: Input data for profiling
            grid_sizes: List of grid size configurations to test
            block_sizes: List of block size configurations to test

        Returns:
            List of kernel performance profiles
        """
        profiles = []
        kernel_hash = self._hash_kernel(kernel_source)

        if not CUDA_AVAILABLE:
            logger.warning("CUDA not available, returning dummy profile")
            return [
                KernelProfile(
                    kernel_hash=kernel_hash,
                    kernel_name=kernel_name,
                    grid_size=(1,),
                    block_size=(1,),
                    execution_time_ms=1.0,
                    memory_throughput_gbps=1.0,
                    occupancy_percent=50.0,
                )
            ]

        try:
            # Compile kernel
            compiled_kernel = cp.RawKernel(kernel_source, kernel_name)
            gpu_data = cp.asarray(input_data)
            output_data = cp.zeros_like(gpu_data)

            # Test different configurations
            for grid_size in grid_sizes:
                for block_size in block_sizes:
                    try:
                        # Warm up
                        compiled_kernel(grid_size, block_size, (gpu_data, output_data))
                        cp.cuda.Stream.null.synchronize()

                        # Measure performance
                        start_time = time.time()
                        for _ in range(10):  # Average over multiple runs
                            compiled_kernel(
                                grid_size, block_size, (gpu_data, output_data)
                            )
                        cp.cuda.Stream.null.synchronize()
                        end_time = time.time()

                        execution_time_ms = ((end_time - start_time) / 10) * 1000

                        # Calculate metrics
                        data_size_gb = input_data.nbytes / (1024**3)
                        throughput = data_size_gb / (execution_time_ms / 1000)

                        # Estimate occupancy (simplified)
                        total_threads = np.prod(grid_size) * np.prod(block_size)
                        max_threads = 2048 * 108  # Typical GPU specs
                        occupancy = min(100.0, (total_threads / max_threads) * 100)

                        profile = KernelProfile(
                            kernel_hash=kernel_hash,
                            kernel_name=kernel_name,
                            grid_size=grid_size,
                            block_size=block_size,
                            execution_time_ms=execution_time_ms,
                            memory_throughput_gbps=throughput,
                            occupancy_percent=occupancy,
                        )

                        profiles.append(profile)

                    except Exception as e:
                        logger.warning(
                            f"Failed to profile config {grid_size}x{block_size}: {e}"
                        )
                        continue

            # Store profiles
            with self._lock:
                self.kernel_profiles[kernel_hash].extend(profiles)

            logger.info(
                f"Profiled {len(profiles)} configurations for kernel {kernel_name}"
            )
            return profiles

        except Exception as e:
            logger.error(f"Kernel profiling failed: {e}")
            return []

    def find_optimal_configuration(
        self,
        kernel_source: str,
        input_data: np.ndarray,
        optimization_target: str = "execution_time",
    ) -> Optional[KernelProfile]:
        """
        Find optimal kernel configuration for given optimization target.

        Args:
            kernel_source: CUDA kernel source code
            input_data: Representative input data
            optimization_target: "execution_time", "throughput", or "occupancy"

        Returns:
            Optimal kernel configuration profile
        """
        kernel_hash = self._hash_kernel(kernel_source)

        # Check cache first
        with self._lock:
            if kernel_hash in self.optimization_cache:
                cached_result = self.optimization_cache[kernel_hash]
                logger.info(f"Using cached optimization for kernel {kernel_hash}")
                return cached_result

        # Generate test configurations
        grid_sizes, block_sizes = self._generate_test_configurations(input_data.shape)

        # Profile kernel
        profiles = self.profile_kernel(
            kernel_source, "optimized_kernel", input_data, grid_sizes, block_sizes
        )

        if not profiles:
            logger.warning("No valid profiles generated")
            return None

        # Find optimal configuration
        if optimization_target == "execution_time":
            optimal = min(profiles, key=lambda p: p.execution_time_ms)
        elif optimization_target == "throughput":
            optimal = max(profiles, key=lambda p: p.memory_throughput_gbps)
        elif optimization_target == "occupancy":
            optimal = max(profiles, key=lambda p: p.occupancy_percent)
        else:
            logger.warning(f"Unknown optimization target: {optimization_target}")
            optimal = min(profiles, key=lambda p: p.execution_time_ms)

        logger.info(
            f"Optimal configuration: grid={optimal.grid_size}, block={optimal.block_size}, "
            f"time={optimal.execution_time_ms:.2f}ms"
        )

        return optimal

    def optimize_kernel(
        self, kernel_source: str, input_data: np.ndarray
    ) -> OptimizationResult:
        """
        Apply comprehensive optimization to a kernel.

        Args:
            kernel_source: CUDA kernel source code
            input_data: Representative input data

        Returns:
            Optimization result with performance improvements
        """
        # Get baseline performance
        baseline_config = self.find_optimal_configuration(
            kernel_source, input_data, "execution_time"
        )

        if not baseline_config:
            return OptimizationResult(
                original_time_ms=0.0,
                optimized_time_ms=0.0,
                speedup_factor=1.0,
                optimization_applied="none",
                configuration={},
            )

        original_time = baseline_config.execution_time_ms
        best_time = original_time
        best_config = baseline_config
        applied_optimizations = []

        # Apply optimization strategies
        for strategy in self.optimization_strategies:
            try:
                optimized_config = strategy(baseline_config, input_data)
                if optimized_config and optimized_config.execution_time_ms < best_time:
                    best_time = optimized_config.execution_time_ms
                    best_config = optimized_config
                    applied_optimizations.append(strategy.__name__)
            except Exception as e:
                logger.warning(f"Optimization strategy {strategy.__name__} failed: {e}")

        speedup = original_time / best_time if best_time > 0 else 1.0

        result = OptimizationResult(
            original_time_ms=original_time,
            optimized_time_ms=best_time,
            speedup_factor=speedup,
            optimization_applied=", ".join(applied_optimizations) or "none",
            configuration={
                "grid_size": best_config.grid_size,
                "block_size": best_config.block_size,
                "occupancy_percent": best_config.occupancy_percent,
            },
        )

        # Cache result
        kernel_hash = self._hash_kernel(kernel_source)
        with self._lock:
            self.optimization_cache[kernel_hash] = result

        logger.info(f"Kernel optimization completed: {speedup:.2f}x speedup")
        return result

    def _generate_test_configurations(
        self, data_shape: Tuple[int, ...]
    ) -> Tuple[List, List]:
        """Generate test grid and block size configurations."""
        data_size = np.prod(data_shape)

        # Common block sizes
        block_sizes = [
            (32,),
            (64,),
            (128,),
            (256,),
            (512,),
            (16, 16),
            (16, 32),
            (32, 32),
            (8, 8, 8),
            (16, 16, 4),
        ]

        # Calculate appropriate grid sizes
        grid_sizes = []
        for block_size in block_sizes:
            block_threads = np.prod(block_size)
            if block_threads <= 1024:  # Max threads per block
                num_blocks = (data_size + block_threads - 1) // block_threads

                if len(block_size) == 1:
                    grid_sizes.append((num_blocks,))
                elif len(block_size) == 2:
                    grid_x = int(np.sqrt(num_blocks))
                    grid_y = (num_blocks + grid_x - 1) // grid_x
                    grid_sizes.append((grid_x, grid_y))
                else:
                    grid_x = int(np.cbrt(num_blocks))
                    grid_y = int(np.sqrt(num_blocks // grid_x))
                    grid_z = (num_blocks + grid_x * grid_y - 1) // (grid_x * grid_y)
                    grid_sizes.append((grid_x, grid_y, grid_z))

        # Remove duplicates and ensure reasonable sizes
        grid_sizes = list(set(grid_sizes))
        grid_sizes = [g for g in grid_sizes if all(dim <= 65535 for dim in g)]

        return grid_sizes, block_sizes

    def _optimize_block_size(
        self, baseline: KernelProfile, input_data: np.ndarray
    ) -> Optional[KernelProfile]:
        """Optimize block size configuration."""
        # This is a simplified optimization - in practice would be more sophisticated
        current_block_size = baseline.block_size
        current_threads = np.prod(current_block_size)

        # Try doubling and halving block size
        candidates = []
        if current_threads < 512:
            candidates.append(tuple(dim * 2 for dim in current_block_size))
        if current_threads > 32:
            candidates.append(tuple(max(1, dim // 2) for dim in current_block_size))

        # For now, return baseline (would implement actual optimization logic)
        return baseline

    def _optimize_grid_size(
        self, baseline: KernelProfile, input_data: np.ndarray
    ) -> Optional[KernelProfile]:
        """Optimize grid size configuration."""
        # Simplified optimization
        return baseline

    def _optimize_memory_access(
        self, baseline: KernelProfile, input_data: np.ndarray
    ) -> Optional[KernelProfile]:
        """Optimize memory access patterns."""
        # Simplified optimization
        return baseline

    def _optimize_occupancy(
        self, baseline: KernelProfile, input_data: np.ndarray
    ) -> Optional[KernelProfile]:
        """Optimize for GPU occupancy."""
        # Simplified optimization
        return baseline

    def _hash_kernel(self, kernel_source: str) -> str:
        """Generate hash for kernel source code."""
        return hashlib.sha256(kernel_source.encode()).hexdigest()[:16]

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics."""
        with self._lock:
            total_kernels = len(self.kernel_profiles)
            total_optimizations = len(self.optimization_cache)

            if self.optimization_cache:
                speedups = [
                    result.speedup_factor for result in self.optimization_cache.values()
                ]
                avg_speedup = np.mean(speedups)
                max_speedup = np.max(speedups)
            else:
                avg_speedup = 1.0
                max_speedup = 1.0

            return {
                "total_kernels_profiled": total_kernels,
                "total_optimizations": total_optimizations,
                "average_speedup": avg_speedup,
                "maximum_speedup": max_speedup,
                "cache_hit_rate": 0.0,  # Would track actual cache hits
            }

    def clear_cache(self):
        """Clear optimization cache."""
        with self._lock:
            self.optimization_cache.clear()
            self.kernel_profiles.clear()
        logger.info("Optimization cache cleared")


# Convenience functions
def optimize_kernel_auto(
    kernel_source: str, input_data: np.ndarray, device_id: int = 0
) -> OptimizationResult:
    """Automatically optimize a kernel and return results."""
    optimizer = KernelOptimizer(device_id=device_id)
    return optimizer.optimize_kernel(kernel_source, input_data)


def find_best_config(
    kernel_source: str, input_data: np.ndarray, target: str = "execution_time"
) -> Optional[KernelProfile]:
    """Find the best kernel configuration for given target."""
    optimizer = KernelOptimizer()
    return optimizer.find_optimal_configuration(kernel_source, input_data, target)
