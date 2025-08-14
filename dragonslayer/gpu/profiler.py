"""
GPU Profiler
============

Performance profiling and monitoring for GPU operations.
Consolidates profiling functionality from the enterprise GPU engine.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
import numpy as np

logger = logging.getLogger(__name__)

try:
    import pynvml
    NVML_AVAILABLE = True
    pynvml.nvmlInit()
except ImportError:
    NVML_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class ProfilingData:
    """GPU profiling data point."""
    timestamp: datetime
    gpu_utilization: float
    memory_utilization: float
    temperature: float
    power_usage: float
    memory_used_mb: int
    memory_total_mb: int
    compute_processes: int


class GPUProfiler:
    """
    GPU performance profiler with real-time monitoring.
    
    Provides comprehensive GPU monitoring including:
    - GPU utilization tracking
    - Memory usage monitoring
    - Temperature and power monitoring
    - Performance bottleneck detection
    """
    
    def __init__(self, device_id: int = 0, sampling_interval: float = 1.0):
        self.device_id = device_id
        self.sampling_interval = sampling_interval
        self.profiling_data: deque = deque(maxlen=1000)
        self.is_profiling = False
        self._profiling_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Initialize GPU monitoring
        self._initialize_monitoring()
    
    def _initialize_monitoring(self):
        """Initialize GPU monitoring capabilities."""
        self.nvml_handle = None
        
        if NVML_AVAILABLE:
            try:
                device_count = pynvml.nvmlDeviceGetCount()
                if self.device_id < device_count:
                    self.nvml_handle = pynvml.nvmlDeviceGetHandleByIndex(self.device_id)
                    logger.info(f"NVML monitoring initialized for GPU {self.device_id}")
                else:
                    logger.warning(f"GPU {self.device_id} not found, max devices: {device_count}")
            except Exception as e:
                logger.error(f"Failed to initialize NVML: {e}")
                self.nvml_handle = None
        
        if not self.nvml_handle:
            logger.info("Using fallback monitoring without NVML")
    
    def start_profiling(self):
        """Start continuous GPU profiling."""
        if self.is_profiling:
            logger.warning("Profiling already active")
            return
        
        self.is_profiling = True
        self._profiling_thread = threading.Thread(target=self._profiling_loop, daemon=True)
        self._profiling_thread.start()
        logger.info(f"Started GPU profiling with {self.sampling_interval}s interval")
    
    def stop_profiling(self):
        """Stop GPU profiling."""
        self.is_profiling = False
        if self._profiling_thread:
            self._profiling_thread.join(timeout=5.0)
        logger.info("Stopped GPU profiling")
    
    def _profiling_loop(self):
        """Main profiling loop."""
        while self.is_profiling:
            try:
                data_point = self._collect_gpu_metrics()
                with self._lock:
                    self.profiling_data.append(data_point)
                time.sleep(self.sampling_interval)
            except Exception as e:
                logger.error(f"Profiling error: {e}")
                time.sleep(self.sampling_interval)
    
    def _collect_gpu_metrics(self) -> ProfilingData:
        """Collect current GPU metrics."""
        timestamp = datetime.now()
        
        if self.nvml_handle:
            # Use NVML for accurate GPU metrics
            try:
                # GPU utilization
                util = pynvml.nvmlDeviceGetUtilizationRates(self.nvml_handle)
                gpu_util = util.gpu
                memory_util = util.memory
                
                # Memory info
                mem_info = pynvml.nvmlDeviceGetMemoryInfo(self.nvml_handle)
                memory_used_mb = mem_info.used // (1024 * 1024)
                memory_total_mb = mem_info.total // (1024 * 1024)
                
                # Temperature
                try:
                    temperature = pynvml.nvmlDeviceGetTemperature(self.nvml_handle, pynvml.NVML_TEMPERATURE_GPU)
                except:
                    temperature = 0.0
                
                # Power usage
                try:
                    power_usage = pynvml.nvmlDeviceGetPowerUsage(self.nvml_handle) / 1000.0  # Convert to watts
                except:
                    power_usage = 0.0
                
                # Process count
                try:
                    processes = pynvml.nvmlDeviceGetComputeRunningProcesses(self.nvml_handle)
                    compute_processes = len(processes)
                except:
                    compute_processes = 0
                
            except Exception as e:
                logger.error(f"NVML data collection failed: {e}")
                return self._get_fallback_metrics(timestamp)
        else:
            return self._get_fallback_metrics(timestamp)
        
        return ProfilingData(
            timestamp=timestamp,
            gpu_utilization=gpu_util,
            memory_utilization=memory_util,
            temperature=temperature,
            power_usage=power_usage,
            memory_used_mb=memory_used_mb,
            memory_total_mb=memory_total_mb,
            compute_processes=compute_processes
        )
    
    def _get_fallback_metrics(self, timestamp: datetime) -> ProfilingData:
        """Get fallback metrics when NVML is unavailable."""
        if PSUTIL_AVAILABLE:
            # Use system metrics as approximation
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            return ProfilingData(
                timestamp=timestamp,
                gpu_utilization=min(cpu_percent, 100.0),  # Approximate
                memory_utilization=memory.percent,
                temperature=50.0,  # Default temperature
                power_usage=100.0,  # Estimated power usage
                memory_used_mb=memory.used // (1024 * 1024),
                memory_total_mb=memory.total // (1024 * 1024),
                compute_processes=len([p for p in psutil.process_iter() if p.name().startswith('python')])
            )
        else:
            # Minimal fallback
            return ProfilingData(
                timestamp=timestamp,
                gpu_utilization=50.0,
                memory_utilization=50.0,
                temperature=50.0,
                power_usage=100.0,
                memory_used_mb=1024,
                memory_total_mb=8192,
                compute_processes=1
            )
    
    def get_current_metrics(self) -> Optional[ProfilingData]:
        """Get the most recent GPU metrics."""
        if not self.is_profiling:
            return self._collect_gpu_metrics()
        
        with self._lock:
            return list(self.profiling_data)[-1] if self.profiling_data else None
    
    def get_metrics_history(self, minutes: int = 10) -> List[ProfilingData]:
        """Get GPU metrics history for the specified time period."""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        with self._lock:
            return [data for data in self.profiling_data if data.timestamp >= cutoff_time]
    
    def get_performance_summary(self, minutes: int = 10) -> Dict[str, Any]:
        """Get performance summary for the specified time period."""
        history = self.get_metrics_history(minutes)
        
        if not history:
            return {'error': 'No performance data available'}
        
        gpu_utils = [d.gpu_utilization for d in history]
        memory_utils = [d.memory_utilization for d in history]
        temperatures = [d.temperature for d in history]
        power_usages = [d.power_usage for d in history]
        
        return {
            'time_period_minutes': minutes,
            'data_points': len(history),
            'gpu_utilization': {
                'avg': np.mean(gpu_utils),
                'max': np.max(gpu_utils),
                'min': np.min(gpu_utils),
                'std': np.std(gpu_utils)
            },
            'memory_utilization': {
                'avg': np.mean(memory_utils),
                'max': np.max(memory_utils),
                'min': np.min(memory_utils),
                'std': np.std(memory_utils)
            },
            'temperature': {
                'avg': np.mean(temperatures),
                'max': np.max(temperatures),
                'min': np.min(temperatures)
            },
            'power_usage': {
                'avg': np.mean(power_usages),
                'max': np.max(power_usages),
                'min': np.min(power_usages)
            },
            'current_memory_mb': history[-1].memory_used_mb,
            'total_memory_mb': history[-1].memory_total_mb,
            'active_processes': history[-1].compute_processes
        }
    
    def detect_bottlenecks(self) -> Dict[str, Any]:
        """Detect performance bottlenecks based on current metrics."""
        current = self.get_current_metrics()
        if not current:
            return {'error': 'No current metrics available'}
        
        bottlenecks = []
        recommendations = []
        
        # High GPU utilization
        if current.gpu_utilization > 95:
            bottlenecks.append("GPU compute fully utilized")
            recommendations.append("Consider increasing batch size or optimizing kernels")
        
        # High memory utilization
        if current.memory_utilization > 90:
            bottlenecks.append("GPU memory near capacity")
            recommendations.append("Reduce batch size or enable gradient checkpointing")
        
        # High temperature
        if current.temperature > 80:
            bottlenecks.append("High GPU temperature")
            recommendations.append("Check cooling system and reduce workload if necessary")
        
        # Low utilization
        if current.gpu_utilization < 30:
            bottlenecks.append("Low GPU utilization")
            recommendations.append("Increase batch size or parallelize workload")
        
        return {
            'timestamp': current.timestamp.isoformat(),
            'bottlenecks': bottlenecks,
            'recommendations': recommendations,
            'current_metrics': {
                'gpu_utilization': current.gpu_utilization,
                'memory_utilization': current.memory_utilization,
                'temperature': current.temperature,
                'power_usage': current.power_usage
            }
        }
    
    def export_metrics(self, filepath: str, format: str = 'csv'):
        """Export profiling data to file."""
        with self._lock:
            data = list(self.profiling_data)
        
        if not data:
            logger.warning("No data to export")
            return
        
        if format.lower() == 'csv':
            import csv
            with open(filepath, 'w', newline='') as csvfile:
                fieldnames = ['timestamp', 'gpu_utilization', 'memory_utilization', 
                             'temperature', 'power_usage', 'memory_used_mb', 
                             'memory_total_mb', 'compute_processes']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for point in data:
                    writer.writerow({
                        'timestamp': point.timestamp.isoformat(),
                        'gpu_utilization': point.gpu_utilization,
                        'memory_utilization': point.memory_utilization,
                        'temperature': point.temperature,
                        'power_usage': point.power_usage,
                        'memory_used_mb': point.memory_used_mb,
                        'memory_total_mb': point.memory_total_mb,
                        'compute_processes': point.compute_processes
                    })
            logger.info(f"Exported {len(data)} data points to {filepath}")
        
        elif format.lower() == 'json':
            import json
            export_data = []
            for point in data:
                export_data.append({
                    'timestamp': point.timestamp.isoformat(),
                    'gpu_utilization': point.gpu_utilization,
                    'memory_utilization': point.memory_utilization,
                    'temperature': point.temperature,
                    'power_usage': point.power_usage,
                    'memory_used_mb': point.memory_used_mb,
                    'memory_total_mb': point.memory_total_mb,
                    'compute_processes': point.compute_processes
                })
            
            with open(filepath, 'w') as jsonfile:
                json.dump(export_data, jsonfile, indent=2)
            logger.info(f"Exported {len(data)} data points to {filepath}")
        
        else:
            logger.error(f"Unsupported export format: {format}")
    
    def __enter__(self):
        self.start_profiling()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_profiling()


# Convenience functions
def profile_gpu(device_id: int = 0, duration_seconds: int = 60) -> Dict[str, Any]:
    """Profile GPU for a specified duration and return summary."""
    profiler = GPUProfiler(device_id=device_id, sampling_interval=1.0)
    
    profiler.start_profiling()
    time.sleep(duration_seconds)
    profiler.stop_profiling()
    
    summary = profiler.get_performance_summary(minutes=duration_seconds // 60 + 1)
    return summary


def get_gpu_status(device_id: int = 0) -> Dict[str, Any]:
    """Get current GPU status."""
    profiler = GPUProfiler(device_id=device_id)
    current_metrics = profiler.get_current_metrics()
    bottlenecks = profiler.detect_bottlenecks()
    
    if current_metrics:
        return {
            'device_id': device_id,
            'current_metrics': {
                'gpu_utilization': current_metrics.gpu_utilization,
                'memory_utilization': current_metrics.memory_utilization,
                'temperature': current_metrics.temperature,
                'power_usage': current_metrics.power_usage,
                'memory_used_mb': current_metrics.memory_used_mb,
                'memory_total_mb': current_metrics.memory_total_mb
            },
            'bottlenecks': bottlenecks
        }
    else:
        return {'error': 'Failed to get GPU metrics'}
