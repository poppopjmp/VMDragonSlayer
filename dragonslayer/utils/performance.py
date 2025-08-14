"""
Performance Monitoring Utilities
===============================

Performance monitoring, profiling, and metrics collection for VMDragonSlayer.
Consolidates performance-related functionality from optimization_engine and infrastructure.
"""

import time
import logging
import threading
import functools
from typing import Dict, List, Optional, Any, Callable, ContextManager
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis operations"""
    execution_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    cache_hit_rate: float = 0.0
    throughput_samples_per_minute: float = 0.0
    peak_memory_mb: float = 0.0
    gc_collections: int = 0
    operation_count: int = 0
    error_count: int = 0
    timestamps: List[float] = field(default_factory=list)


@dataclass
class TimingResult:
    """Result of timing measurement"""
    duration: float
    start_time: float
    end_time: float
    operation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class PerformanceMonitor:
    """
    Comprehensive performance monitoring system.
    Tracks execution times, memory usage, and system metrics.
    """
    
    def __init__(self, history_size: int = 1000):
        """
        Initialize performance monitor.
        
        Args:
            history_size: Number of measurements to keep in history
        """
        self.history_size = history_size
        self._measurements = defaultdict(lambda: deque(maxlen=history_size))
        self._counters = defaultdict(int)
        self._lock = threading.RLock()
        self._start_time = time.time()
    
    def start_timer(self, operation: str) -> str:
        """
        Start timing an operation.
        
        Args:
            operation: Name of the operation
            
        Returns:
            Timer ID for later stopping
        """
        timer_id = f"{operation}_{int(time.time() * 1000000)}"
        with self._lock:
            self._measurements[f"{timer_id}_start"] = deque([time.time()], maxlen=1)
        return timer_id
    
    def stop_timer(self, timer_id: str, metadata: Optional[Dict[str, Any]] = None) -> TimingResult:
        """
        Stop timing an operation.
        
        Args:
            timer_id: Timer ID from start_timer
            metadata: Optional metadata about the operation
            
        Returns:
            TimingResult with timing information
        """
        end_time = time.time()
        
        with self._lock:
            start_times = self._measurements.get(f"{timer_id}_start")
            if not start_times:
                raise ValueError(f"Timer {timer_id} not found")
            
            start_time = start_times[0]
            duration = end_time - start_time
            
            # Extract operation name from timer_id
            operation = timer_id.rsplit('_', 1)[0]
            
            # Store timing result
            result = TimingResult(
                duration=duration,
                start_time=start_time,
                end_time=end_time,
                operation=operation,
                metadata=metadata or {}
            )
            
            self._measurements[f"{operation}_timings"].append(result)
            self._counters[f"{operation}_count"] += 1
            
            # Cleanup start time
            del self._measurements[f"{timer_id}_start"]
            
            return result
    
    def record_metric(self, metric_name: str, value: float, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Record a performance metric.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            metadata: Optional metadata
        """
        with self._lock:
            timestamp = time.time()
            metric_data = {
                'value': value,
                'timestamp': timestamp,
                'metadata': metadata or {}
            }
            self._measurements[metric_name].append(metric_data)
    
    def increment_counter(self, counter_name: str, delta: int = 1) -> None:
        """
        Increment a counter.
        
        Args:
            counter_name: Name of the counter
            delta: Amount to increment by
        """
        with self._lock:
            self._counters[counter_name] += delta
    
    def get_metrics(self, operation: Optional[str] = None) -> PerformanceMetrics:
        """
        Get performance metrics.
        
        Args:
            operation: Optional operation name to filter by
            
        Returns:
            PerformanceMetrics object
        """
        with self._lock:
            if operation:
                timings_key = f"{operation}_timings"
                timings = self._measurements.get(timings_key, [])
                count_key = f"{operation}_count"
                count = self._counters.get(count_key, 0)
            else:
                # Aggregate across all operations
                timings = []
                count = 0
                for key, measurements in self._measurements.items():
                    if key.endswith('_timings'):
                        timings.extend(measurements)
                for key, counter_val in self._counters.items():
                    if key.endswith('_count'):
                        count += counter_val
            
            if timings:
                durations = [t.duration for t in timings]
                avg_duration = sum(durations) / len(durations)
                timestamps = [t.start_time for t in timings]
            else:
                avg_duration = 0.0
                timestamps = []
            
            # Get memory metrics if available
            memory_usage = 0.0
            try:
                from .memory import get_memory_usage
                mem_info = get_memory_usage()
                memory_usage = mem_info.rss_mb
            except ImportError:
                pass
            
            return PerformanceMetrics(
                execution_time=avg_duration,
                memory_usage_mb=memory_usage,
                operation_count=count,
                timestamps=timestamps
            )
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get performance summary.
        
        Returns:
            Dictionary with performance summary
        """
        with self._lock:
            uptime = time.time() - self._start_time
            
            # Collect operation summaries
            operations = {}
            for key in self._measurements:
                if key.endswith('_timings'):
                    operation = key[:-8]  # Remove '_timings'
                    timings = self._measurements[key]
                    if timings:
                        durations = [t.duration for t in timings]
                        operations[operation] = {
                            'count': len(timings),
                            'avg_duration': sum(durations) / len(durations),
                            'min_duration': min(durations),
                            'max_duration': max(durations),
                            'total_duration': sum(durations)
                        }
            
            return {
                'uptime_seconds': uptime,
                'operations': operations,
                'counters': dict(self._counters),
                'total_measurements': sum(len(m) for m in self._measurements.values())
            }
    
    def reset(self) -> None:
        """Reset all measurements and counters"""
        with self._lock:
            self._measurements.clear()
            self._counters.clear()
            self._start_time = time.time()
    
    @contextmanager
    def measure(self, operation: str, metadata: Optional[Dict[str, Any]] = None) -> ContextManager[TimingResult]:
        """
        Context manager for measuring operation performance.
        
        Args:
            operation: Name of the operation
            metadata: Optional metadata
            
        Yields:
            TimingResult object (populated after completion)
        """
        timer_id = self.start_timer(operation)
        result = TimingResult(0, 0, 0, operation)
        
        try:
            yield result
        finally:
            completed_result = self.stop_timer(timer_id, metadata)
            # Update the yielded result
            result.duration = completed_result.duration
            result.start_time = completed_result.start_time
            result.end_time = completed_result.end_time
            result.metadata = completed_result.metadata


# Global performance monitor
_performance_monitor = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def measure_performance(operation: str, metadata: Optional[Dict[str, Any]] = None) -> ContextManager[TimingResult]:
    """
    Context manager for measuring performance.
    
    Args:
        operation: Name of the operation
        metadata: Optional metadata
        
    Example:
        with measure_performance("binary_analysis"):
            analyze_binary(data)
    """
    return get_performance_monitor().measure(operation, metadata)


def profile_execution(func: Callable) -> Callable:
    """
    Decorator for profiling function execution.
    
    Args:
        func: Function to profile
        
    Returns:
        Wrapped function with profiling
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        monitor = get_performance_monitor()
        operation_name = f"{func.__module__}.{func.__name__}"
        
        with monitor.measure(operation_name):
            return func(*args, **kwargs)
    
    return wrapper


def get_system_metrics() -> Dict[str, Any]:
    """
    Get system-wide performance metrics.
    
    Returns:
        Dictionary with system metrics
    """
    metrics = {}
    
    try:
        import psutil
        
        # CPU metrics
        metrics['cpu_percent'] = psutil.cpu_percent(interval=1)
        metrics['cpu_count'] = psutil.cpu_count()
        metrics['load_average'] = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        
        # Memory metrics
        memory = psutil.virtual_memory()
        metrics['memory_total_gb'] = memory.total / (1024**3)
        metrics['memory_available_gb'] = memory.available / (1024**3)
        metrics['memory_percent'] = memory.percent
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        metrics['disk_total_gb'] = disk.total / (1024**3)
        metrics['disk_free_gb'] = disk.free / (1024**3)
        metrics['disk_percent'] = (disk.used / disk.total) * 100
        
        # Network metrics (basic)
        network = psutil.net_io_counters()
        metrics['network_bytes_sent'] = network.bytes_sent
        metrics['network_bytes_recv'] = network.bytes_recv
        
    except ImportError:
        logger.warning("psutil not available, limited system metrics")
        metrics['cpu_count'] = None
        metrics['memory_available'] = 'unknown'
    
    return metrics


class PerformanceProfiler:
    """
    Advanced performance profiler with detailed analysis.
    """
    
    def __init__(self):
        self.monitor = get_performance_monitor()
        self._profiles = {}
    
    def start_profile(self, profile_name: str) -> None:
        """Start a performance profile"""
        self._profiles[profile_name] = {
            'start_time': time.time(),
            'operations': [],
            'memory_snapshots': []
        }
    
    def end_profile(self, profile_name: str) -> Dict[str, Any]:
        """End a performance profile and return results"""
        if profile_name not in self._profiles:
            raise ValueError(f"Profile {profile_name} not found")
        
        profile = self._profiles[profile_name]
        end_time = time.time()
        
        return {
            'profile_name': profile_name,
            'total_duration': end_time - profile['start_time'],
            'operations': profile['operations'],
            'memory_snapshots': profile['memory_snapshots']
        }
    
    @contextmanager
    def profile(self, profile_name: str) -> ContextManager:
        """Context manager for profiling"""
        self.start_profile(profile_name)
        try:
            yield
        finally:
            return self.end_profile(profile_name)
