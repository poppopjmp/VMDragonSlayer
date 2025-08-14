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
Memory Management Utilities
===========================

Memory optimization and management utilities for VMDragonSlayer.
Consolidates memory-related functionality from optimization_engine and memory modules.
"""

import gc
import logging
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, ContextManager, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class MemoryUsage:
    """Memory usage information"""

    rss_mb: float  # Resident Set Size
    vms_mb: float  # Virtual Memory Size
    percent: float  # Memory percentage
    available_mb: float  # Available memory
    total_mb: float  # Total system memory


class MemoryManager:
    """
    Advanced memory management for large binary analysis.
    Consolidates memory optimization techniques from across the codebase.
    """

    def __init__(self, gc_threshold_mb: int = 700, enable_monitoring: bool = True):
        """
        Initialize memory manager.

        Args:
            gc_threshold_mb: Memory usage threshold for triggering garbage collection
            enable_monitoring: Whether to enable memory monitoring
        """
        self.gc_threshold_mb = gc_threshold_mb
        self.enable_monitoring = enable_monitoring
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()

        if self.enable_monitoring:
            self.start_monitoring()

    def get_memory_usage(self) -> MemoryUsage:
        """
        Get current memory usage information.

        Returns:
            MemoryUsage object with current memory statistics
        """
        try:
            import psutil

            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()

            return MemoryUsage(
                rss_mb=memory_info.rss / (1024 * 1024),
                vms_mb=memory_info.vms / (1024 * 1024),
                percent=process.memory_percent(),
                available_mb=system_memory.available / (1024 * 1024),
                total_mb=system_memory.total / (1024 * 1024),
            )
        except ImportError:
            # Fallback without psutil
            import resource

            usage = resource.getrusage(resource.RUSAGE_SELF)
            # Note: ru_maxrss is in KB on Linux, bytes on macOS
            if sys.platform == "darwin":
                rss_mb = usage.ru_maxrss / (1024 * 1024)
            else:
                rss_mb = usage.ru_maxrss / 1024

            return MemoryUsage(
                rss_mb=rss_mb,
                vms_mb=0.0,  # Not available
                percent=0.0,  # Not available
                available_mb=0.0,  # Not available
                total_mb=0.0,  # Not available
            )

    def optimize_memory(self) -> None:
        """
        Perform memory optimization.
        Triggers garbage collection and cleans up caches.
        """
        logger.debug("Starting memory optimization")

        # Force garbage collection
        collected = gc.collect()
        logger.debug(f"Garbage collection freed {collected} objects")

        # Clear Python caches if available
        try:
            sys.intern.__dict__.clear()
        except AttributeError:
            pass

        # Clear import cache
        if hasattr(sys.modules, "clear"):
            # Don't actually clear sys.modules as it would break imports
            pass

        logger.debug("Memory optimization completed")

    def cleanup_memory(self) -> None:
        """
        Aggressive memory cleanup.
        Use with caution as it may affect performance.
        """
        logger.debug("Starting aggressive memory cleanup")

        # Multiple GC passes
        for i in range(3):
            collected = gc.collect()
            logger.debug(f"GC pass {i+1}: freed {collected} objects")

        # Clear all possible caches
        try:
            import functools

            functools.lru_cache.__wrapped__.__dict__.clear()
        except (AttributeError, ImportError):
            pass

        logger.debug("Aggressive memory cleanup completed")

    def start_monitoring(self) -> None:
        """Start memory monitoring thread"""
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_monitoring.clear()
            self._monitoring_thread = threading.Thread(
                target=self._memory_monitor, daemon=True
            )
            self._monitoring_thread.start()
            logger.debug("Memory monitoring started")

    def stop_monitoring(self) -> None:
        """Stop memory monitoring thread"""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=5)
            logger.debug("Memory monitoring stopped")

    def _memory_monitor(self) -> None:
        """Internal memory monitoring loop"""
        while not self._stop_monitoring.wait(30):  # Check every 30 seconds
            try:
                usage = self.get_memory_usage()

                if usage.rss_mb > self.gc_threshold_mb:
                    logger.warning(
                        f"Memory usage ({usage.rss_mb:.1f} MB) exceeds threshold "
                        f"({self.gc_threshold_mb} MB), triggering optimization"
                    )
                    self.optimize_memory()

            except Exception as e:
                logger.error(f"Error in memory monitoring: {e}")

    @contextmanager
    def memory_limit(self, limit_mb: int) -> ContextManager:
        """
        Context manager to enforce memory limits.

        Args:
            limit_mb: Memory limit in MB

        Yields:
            Context with memory monitoring
        """
        initial_usage = self.get_memory_usage()
        logger.debug(
            f"Starting with memory limit: {limit_mb} MB "
            f"(current: {initial_usage.rss_mb:.1f} MB)"
        )

        try:
            yield
        finally:
            final_usage = self.get_memory_usage()
            if final_usage.rss_mb > limit_mb:
                logger.warning(
                    f"Memory limit exceeded: {final_usage.rss_mb:.1f} MB > {limit_mb} MB"
                )
                self.optimize_memory()

    def __del__(self):
        """Cleanup when manager is destroyed"""
        self.stop_monitoring()


# Global memory manager instance
_memory_manager = None


def get_memory_manager() -> MemoryManager:
    """Get global memory manager instance"""
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = MemoryManager()
    return _memory_manager


def get_memory_usage() -> MemoryUsage:
    """Get current memory usage"""
    return get_memory_manager().get_memory_usage()


def optimize_memory() -> None:
    """Trigger memory optimization"""
    get_memory_manager().optimize_memory()


def cleanup_memory() -> None:
    """Trigger aggressive memory cleanup"""
    get_memory_manager().cleanup_memory()


@contextmanager
def memory_monitor(limit_mb: Optional[int] = None) -> ContextManager:
    """
    Context manager for memory monitoring.

    Args:
        limit_mb: Optional memory limit in MB

    Example:
        with memory_monitor(limit_mb=1000):
            # Memory-intensive operation
            analyze_large_binary()
    """
    manager = get_memory_manager()

    if limit_mb:
        with manager.memory_limit(limit_mb):
            yield
    else:
        initial = manager.get_memory_usage()
        try:
            yield
        finally:
            final = manager.get_memory_usage()
            logger.debug(
                f"Memory usage: {initial.rss_mb:.1f} MB → {final.rss_mb:.1f} MB "
                f"(Δ {final.rss_mb - initial.rss_mb:.1f} MB)"
            )


def set_memory_limits(soft_limit_mb: int, hard_limit_mb: int) -> None:
    """
    Set system memory limits using resource module.

    Args:
        soft_limit_mb: Soft memory limit in MB
        hard_limit_mb: Hard memory limit in MB
    """
    try:
        import resource

        soft_bytes = soft_limit_mb * 1024 * 1024
        hard_bytes = hard_limit_mb * 1024 * 1024

        resource.setrlimit(resource.RLIMIT_AS, (soft_bytes, hard_bytes))
        logger.info(
            f"Set memory limits: soft={soft_limit_mb}MB, hard={hard_limit_mb}MB"
        )

    except (ImportError, OSError) as e:
        logger.warning(f"Failed to set memory limits: {e}")


def get_memory_info() -> Dict[str, Any]:
    """
    Get comprehensive memory information.

    Returns:
        Dictionary with detailed memory statistics
    """
    usage = get_memory_usage()
    gc_stats = gc.get_stats()

    return {
        "current_usage_mb": usage.rss_mb,
        "virtual_memory_mb": usage.vms_mb,
        "memory_percent": usage.percent,
        "available_mb": usage.available_mb,
        "total_system_mb": usage.total_mb,
        "gc_collections": sum(stat["collections"] for stat in gc_stats),
        "gc_collected": sum(stat["collected"] for stat in gc_stats),
        "gc_uncollectable": sum(stat["uncollectable"] for stat in gc_stats),
    }
