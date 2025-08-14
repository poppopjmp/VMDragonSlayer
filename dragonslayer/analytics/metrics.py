"""
Metrics Collector
=================

Comprehensive metrics collection and aggregation system.
Consolidates metrics functionality from enterprise monitoring systems.
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import statistics

logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """Individual metric data point."""
    metric_name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricSeries:
    """Time series of metric data points."""
    metric_name: str
    data_points: List[MetricPoint] = field(default_factory=list)
    retention_hours: int = 24
    
    def add_point(self, value: float, tags: Dict[str, str] = None, 
                 metadata: Dict[str, Any] = None):
        """Add a new data point to the series."""
        point = MetricPoint(
            metric_name=self.metric_name,
            value=value,
            timestamp=datetime.now(),
            tags=tags or {},
            metadata=metadata or {}
        )
        
        self.data_points.append(point)
        self._cleanup_old_points()
    
    def _cleanup_old_points(self):
        """Remove data points older than retention period."""
        cutoff = datetime.now() - timedelta(hours=self.retention_hours)
        self.data_points = [
            point for point in self.data_points 
            if point.timestamp > cutoff
        ]
    
    def get_latest_value(self) -> Optional[float]:
        """Get the most recent metric value."""
        if self.data_points:
            return self.data_points[-1].value
        return None
    
    def get_average(self, hours: int = 1) -> Optional[float]:
        """Get average value over specified time period."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_points = [
            point.value for point in self.data_points 
            if point.timestamp > cutoff
        ]
        
        if recent_points:
            return statistics.mean(recent_points)
        return None
    
    def get_min_max(self, hours: int = 1) -> tuple[Optional[float], Optional[float]]:
        """Get min and max values over specified time period."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_points = [
            point.value for point in self.data_points 
            if point.timestamp > cutoff
        ]
        
        if recent_points:
            return min(recent_points), max(recent_points)
        return None, None


class MetricsCollector:
    """
    Comprehensive metrics collection and aggregation system.
    
    Features:
    - Real-time metric collection
    - Time series data storage
    - Metric aggregation and analysis
    - Alert threshold monitoring
    - Metric export and reporting
    """
    
    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self.metrics: Dict[str, MetricSeries] = {}
        self.alert_thresholds: Dict[str, Dict[str, float]] = {}
        self.metric_callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self.collection_intervals: Dict[str, int] = {}  # Metric name -> seconds
        self.collection_threads: Dict[str, threading.Thread] = {}
        self.is_collecting = False
        self._lock = threading.RLock()
        
        # System metrics
        self._start_system_metrics_collection()
    
    def register_metric(self, metric_name: str, retention_hours: int = None):
        """Register a new metric for collection."""
        with self._lock:
            if metric_name not in self.metrics:
                self.metrics[metric_name] = MetricSeries(
                    metric_name=metric_name,
                    retention_hours=retention_hours or self.retention_hours
                )
                logger.info(f"Registered metric: {metric_name}")
    
    def record_metric(self, metric_name: str, value: float, 
                     tags: Dict[str, str] = None, 
                     metadata: Dict[str, Any] = None):
        """Record a metric value."""
        with self._lock:
            # Auto-register metric if not exists
            if metric_name not in self.metrics:
                self.register_metric(metric_name)
            
            # Add data point
            self.metrics[metric_name].add_point(value, tags, metadata)
            
            # Check alert thresholds
            self._check_alert_thresholds(metric_name, value)
            
            # Execute callbacks
            self._execute_callbacks(metric_name, value, tags, metadata)
    
    def set_alert_threshold(self, metric_name: str, 
                          min_value: float = None, 
                          max_value: float = None):
        """Set alert thresholds for a metric."""
        with self._lock:
            if metric_name not in self.alert_thresholds:
                self.alert_thresholds[metric_name] = {}
            
            if min_value is not None:
                self.alert_thresholds[metric_name]['min'] = min_value
            
            if max_value is not None:
                self.alert_thresholds[metric_name]['max'] = max_value
            
            logger.info(f"Set alert thresholds for {metric_name}: {self.alert_thresholds[metric_name]}")
    
    def add_metric_callback(self, metric_name: str, callback: Callable):
        """Add callback function for metric updates."""
        with self._lock:
            self.metric_callbacks[metric_name].append(callback)
            logger.info(f"Added callback for metric: {metric_name}")
    
    def start_automatic_collection(self, metric_name: str, 
                                  collection_function: Callable[[], float],
                                  interval_seconds: int = 60):
        """Start automatic collection for a metric."""
        if metric_name in self.collection_threads:
            logger.warning(f"Automatic collection already running for {metric_name}")
            return
        
        self.collection_intervals[metric_name] = interval_seconds
        
        def collection_loop():
            while self.is_collecting and metric_name in self.collection_intervals:
                try:
                    value = collection_function()
                    self.record_metric(metric_name, value)
                    time.sleep(interval_seconds)
                except Exception as e:
                    logger.error(f"Error collecting metric {metric_name}: {e}")
                    time.sleep(interval_seconds)
        
        thread = threading.Thread(target=collection_loop, daemon=True)
        self.collection_threads[metric_name] = thread
        thread.start()
        
        logger.info(f"Started automatic collection for {metric_name} (interval: {interval_seconds}s)")
    
    def stop_automatic_collection(self, metric_name: str):
        """Stop automatic collection for a metric."""
        if metric_name in self.collection_intervals:
            del self.collection_intervals[metric_name]
        
        if metric_name in self.collection_threads:
            # Thread will stop when it checks is_collecting
            del self.collection_threads[metric_name]
        
        logger.info(f"Stopped automatic collection for {metric_name}")
    
    def get_metric_value(self, metric_name: str) -> Optional[float]:
        """Get the latest value for a metric."""
        with self._lock:
            if metric_name in self.metrics:
                return self.metrics[metric_name].get_latest_value()
            return None
    
    def get_metric_statistics(self, metric_name: str, 
                            hours: int = 1) -> Dict[str, Any]:
        """Get statistics for a metric over time period."""
        with self._lock:
            if metric_name not in self.metrics:
                return {"error": f"Metric {metric_name} not found"}
            
            metric_series = self.metrics[metric_name]
            
            # Get data points for time period
            cutoff = datetime.now() - timedelta(hours=hours)
            recent_points = [
                point.value for point in metric_series.data_points 
                if point.timestamp > cutoff
            ]
            
            if not recent_points:
                return {"error": "No data points in time period"}
            
            return {
                "metric_name": metric_name,
                "time_period_hours": hours,
                "data_points": len(recent_points),
                "latest_value": recent_points[-1],
                "average": statistics.mean(recent_points),
                "median": statistics.median(recent_points),
                "min_value": min(recent_points),
                "max_value": max(recent_points),
                "std_deviation": statistics.stdev(recent_points) if len(recent_points) > 1 else 0,
                "trend": self._calculate_trend(recent_points)
            }
    
    def get_all_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics."""
        with self._lock:
            summary = {
                "total_metrics": len(self.metrics),
                "metrics": {},
                "alerts_configured": len(self.alert_thresholds),
                "automatic_collection_active": len(self.collection_threads),
                "collection_status": "active" if self.is_collecting else "stopped"
            }
            
            for metric_name, metric_series in self.metrics.items():
                latest_value = metric_series.get_latest_value()
                data_points = len(metric_series.data_points)
                
                summary["metrics"][metric_name] = {
                    "latest_value": latest_value,
                    "data_points": data_points,
                    "last_updated": metric_series.data_points[-1].timestamp.isoformat() if data_points > 0 else None,
                    "has_alerts": metric_name in self.alert_thresholds,
                    "auto_collection": metric_name in self.collection_threads
                }
            
            return summary
    
    def export_metrics(self, filepath: str, 
                      metric_names: List[str] = None,
                      hours: int = 24):
        """Export metrics data to JSON file."""
        with self._lock:
            cutoff = datetime.now() - timedelta(hours=hours)
            
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "time_period_hours": hours,
                "metrics": {}
            }
            
            metrics_to_export = metric_names or list(self.metrics.keys())
            
            for metric_name in metrics_to_export:
                if metric_name not in self.metrics:
                    continue
                
                metric_series = self.metrics[metric_name]
                recent_points = [
                    {
                        "timestamp": point.timestamp.isoformat(),
                        "value": point.value,
                        "tags": point.tags,
                        "metadata": point.metadata
                    }
                    for point in metric_series.data_points 
                    if point.timestamp > cutoff
                ]
                
                export_data["metrics"][metric_name] = {
                    "data_points": recent_points,
                    "statistics": self.get_metric_statistics(metric_name, hours)
                }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Exported {len(metrics_to_export)} metrics to {filepath}")
    
    def _start_system_metrics_collection(self):
        """Start collecting basic system metrics."""
        self.is_collecting = True
        
        # CPU usage
        def get_cpu_usage():
            try:
                import psutil
                return psutil.cpu_percent()
            except ImportError:
                return 50.0  # Fallback value
        
        # Memory usage
        def get_memory_usage():
            try:
                import psutil
                return psutil.virtual_memory().percent
            except ImportError:
                return 60.0  # Fallback value
        
        # Start automatic collection for system metrics
        self.start_automatic_collection("system.cpu_usage", get_cpu_usage, 30)
        self.start_automatic_collection("system.memory_usage", get_memory_usage, 30)
        
        # Set reasonable alert thresholds
        self.set_alert_threshold("system.cpu_usage", max_value=90.0)
        self.set_alert_threshold("system.memory_usage", max_value=85.0)
    
    def _check_alert_thresholds(self, metric_name: str, value: float):
        """Check if metric value exceeds alert thresholds."""
        if metric_name not in self.alert_thresholds:
            return
        
        thresholds = self.alert_thresholds[metric_name]
        
        if 'min' in thresholds and value < thresholds['min']:
            logger.warning(f"Alert: {metric_name} below minimum threshold: {value} < {thresholds['min']}")
        
        if 'max' in thresholds and value > thresholds['max']:
            logger.warning(f"Alert: {metric_name} above maximum threshold: {value} > {thresholds['max']}")
    
    def _execute_callbacks(self, metric_name: str, value: float,
                          tags: Dict[str, str], metadata: Dict[str, Any]):
        """Execute registered callbacks for metric updates."""
        if metric_name not in self.metric_callbacks:
            return
        
        for callback in self.metric_callbacks[metric_name]:
            try:
                callback(metric_name, value, tags, metadata)
            except Exception as e:
                logger.error(f"Callback error for {metric_name}: {e}")
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from values."""
        if len(values) < 2:
            return "insufficient_data"
        
        # Simple trend calculation - compare first and last half
        mid_point = len(values) // 2
        first_half_avg = statistics.mean(values[:mid_point])
        second_half_avg = statistics.mean(values[mid_point:])
        
        if second_half_avg > first_half_avg * 1.1:
            return "increasing"
        elif second_half_avg < first_half_avg * 0.9:
            return "decreasing"
        else:
            return "stable"
    
    def start_collection(self):
        """Start metrics collection."""
        self.is_collecting = True
        logger.info("Metrics collection started")
    
    def stop_collection(self):
        """Stop all metrics collection."""
        self.is_collecting = False
        
        # Stop all automatic collection threads
        for metric_name in list(self.collection_threads.keys()):
            self.stop_automatic_collection(metric_name)
        
        logger.info("Metrics collection stopped")
    
    def cleanup(self):
        """Clean up resources."""
        self.stop_collection()
        
        with self._lock:
            self.metrics.clear()
            self.alert_thresholds.clear()
            self.metric_callbacks.clear()
        
        logger.info("Metrics collector cleaned up")


# Convenience functions
def create_metrics_collector(retention_hours: int = 24) -> MetricsCollector:
    """Create a new metrics collector instance."""
    return MetricsCollector(retention_hours=retention_hours)


def record_performance_metric(collector: MetricsCollector, 
                            operation: str, 
                            duration_ms: float,
                            success: bool = True):
    """Record a performance metric."""
    collector.record_metric(
        f"performance.{operation}.duration_ms",
        duration_ms,
        tags={"success": str(success)},
        metadata={"operation": operation}
    )
    
    # Also record success rate
    collector.record_metric(
        f"performance.{operation}.success_rate",
        1.0 if success else 0.0,
        tags={"operation": operation}
    )
