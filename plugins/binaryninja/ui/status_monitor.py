#!/usr/bin/env python3
"""
Binary Ninja Phase 2: UI/UX Enhancement - Real-time Status Monitor
Real-time monitoring of core services and analysis performance.
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Callable
from collections import deque
import json

try:
    from PySide2.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QProgressBar, QFrame, QGroupBox
    )
    from PySide2.QtCore import QTimer, Qt, Signal, QObject
    from PySide2.QtGui import QFont, QPainter, QPen, QBrush
    from PySide2.QtCharts import QChart, QChartView, QLineSeries, QDateTimeAxis, QValueAxis
    QT_AVAILABLE = True
except ImportError:
    # Mock classes for testing
    class QWidget: pass
    class QObject: pass
    class Signal: pass
    QT_AVAILABLE = False


class MetricsCollector(QObject):
    """Collects and manages real-time metrics from core services"""
    
    # Signals for real-time updates
    metrics_updated = Signal(dict) if QT_AVAILABLE else None
    service_status_changed = Signal(str, bool) if QT_AVAILABLE else None
    
    def __init__(self, plugin_instance=None, max_history=100):
        super().__init__()
        self.plugin = plugin_instance
        self.max_history = max_history
        self.metrics_history = {}
        self.service_status = {}
        self.is_collecting = False
        self.collection_thread = None
        self.collection_lock = threading.Lock()
        
        # Initialize metrics storage
        self.initialize_metrics_storage()
    
    def initialize_metrics_storage(self):
        """Initialize metrics storage structures"""
        self.metrics_history = {
            'cpu_usage': deque(maxlen=self.max_history),
            'memory_usage': deque(maxlen=self.max_history),
            'gpu_utilization': deque(maxlen=self.max_history),
            'analysis_throughput': deque(maxlen=self.max_history),
            'response_time': deque(maxlen=self.max_history),
            'timestamps': deque(maxlen=self.max_history)
        }
        
        self.service_status = {
            'sample_database': False,
            'validation_framework': False,
            'gpu_profiler': False,
            'pattern_database': False
        }
    
    def start_collection(self, interval=1.0):
        """Start metrics collection"""
        if self.is_collecting:
            return
            
        self.is_collecting = True
        self.collection_thread = threading.Thread(
            target=self._collection_worker,
            args=(interval,),
            daemon=True
        )
        self.collection_thread.start()
    
    def stop_collection(self):
        """Stop metrics collection"""
        self.is_collecting = False
        if self.collection_thread:
            self.collection_thread.join(timeout=2.0)
    
    def _collection_worker(self, interval):
        """Background worker for metrics collection"""
        while self.is_collecting:
            try:
                # Collect current metrics
                current_metrics = self.collect_current_metrics()
                
                # Update history
                with self.collection_lock:
                    self.update_metrics_history(current_metrics)
                
                # Emit signals for UI updates
                if QT_AVAILABLE and self.metrics_updated:
                    self.metrics_updated.emit(current_metrics)
                
                time.sleep(interval)
                
            except Exception as e:
                logging.debug(f"Metrics collection error: {e}")
                time.sleep(interval)
    
    def collect_current_metrics(self) -> Dict:
        """Collect current system and service metrics"""
        metrics = {
            'timestamp': time.time(),
            'cpu_usage': self.get_cpu_usage(),
            'memory_usage': self.get_memory_usage(),
            'gpu_utilization': self.get_gpu_utilization(),
            'analysis_throughput': self.get_analysis_throughput(),
            'response_time': self.get_response_time(),
            'service_status': self.get_service_status()
        }
        
        return metrics
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=None)
        except ImportError:
            # Mock data for testing
            import random
            return random.uniform(10, 80)
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return memory.used / (1024 * 1024)  # MB
        except ImportError:
            # Mock data for testing
            import random
            return random.uniform(500, 2000)
    
    def get_gpu_utilization(self) -> float:
        """Get GPU utilization percentage"""
        if self.plugin and hasattr(self.plugin, 'core_services'):
            try:
                gpu_service = self.plugin.core_services.get_service('gpu_profiler')
                if gpu_service:
                    metrics = gpu_service.get_current_metrics()
                    return metrics.get('utilization', 0.0)
            except Exception:
                pass
        
        # Mock data for testing
        import random
        return random.uniform(0, 95)
    
    def get_analysis_throughput(self) -> float:
        """Get analysis throughput (samples/second)"""
        # This would be calculated based on recent analysis completions
        # For now, return mock data
        import random
        return random.uniform(0.5, 5.0)
    
    def get_response_time(self) -> float:
        """Get average response time in milliseconds"""
        # This would be calculated from recent API calls
        # For now, return mock data
        import random
        return random.uniform(50, 500)
    
    def get_service_status(self) -> Dict[str, bool]:
        """Get current service availability status"""
        if self.plugin and hasattr(self.plugin, 'core_services'):
            try:
                status = self.plugin.core_services.get_service_status()
                
                # Check for status changes
                for service, available in status.items():
                    if service in self.service_status:
                        if self.service_status[service] != available:
                            if QT_AVAILABLE and self.service_status_changed:
                                self.service_status_changed.emit(service, available)
                
                self.service_status.update(status)
                return status
            except Exception:
                pass
        
        return self.service_status.copy()
    
    def update_metrics_history(self, metrics: Dict):
        """Update metrics history with new data point"""
        timestamp = metrics['timestamp']
        
        self.metrics_history['timestamps'].append(timestamp)
        self.metrics_history['cpu_usage'].append(metrics.get('cpu_usage', 0))
        self.metrics_history['memory_usage'].append(metrics.get('memory_usage', 0))
        self.metrics_history['gpu_utilization'].append(metrics.get('gpu_utilization', 0))
        self.metrics_history['analysis_throughput'].append(metrics.get('analysis_throughput', 0))
        self.metrics_history['response_time'].append(metrics.get('response_time', 0))
    
    def get_metrics_history(self, metric_name: str, duration_seconds: int = 60) -> List:
        """Get metrics history for specified duration"""
        with self.collection_lock:
            if metric_name not in self.metrics_history:
                return []
            
            current_time = time.time()
            cutoff_time = current_time - duration_seconds
            
            # Filter data within time window
            filtered_data = []
            timestamps = list(self.metrics_history['timestamps'])
            values = list(self.metrics_history[metric_name])
            
            for i, timestamp in enumerate(timestamps):
                if timestamp >= cutoff_time:
                    filtered_data.append((timestamp, values[i]))
            
            return filtered_data


class PerformanceChart(QWidget):
    """Real-time performance chart widget"""
    
    def __init__(self, title: str, metric_name: str, unit: str = "", parent=None):
        super().__init__(parent)
        self.title = title
        self.metric_name = metric_name
        self.unit = unit
        self.max_points = 60  # Show last 60 seconds
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the chart UI"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Title
        title_label = QLabel(self.title)
        title_label.setStyleSheet("font-weight: bold; color: #1976D2;")
        
        # Chart
        self.chart = QChart()
        self.chart.setTitle(f"{self.title} ({self.unit})")
        self.chart.setAnimationOptions(QChart.SeriesAnimations)
        
        # Series
        self.series = QLineSeries()
        self.chart.addSeries(self.series)
        
        # Axes
        self.x_axis = QDateTimeAxis()
        self.x_axis.setFormat("hh:mm:ss")
        self.chart.addAxis(self.x_axis, Qt.AlignBottom)
        self.series.attachAxis(self.x_axis)
        
        self.y_axis = QValueAxis()
        self.chart.addAxis(self.y_axis, Qt.AlignLeft)
        self.series.attachAxis(self.y_axis)
        
        # Chart view
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        
        layout.addWidget(title_label)
        layout.addWidget(self.chart_view)
    
    def update_data(self, data_points: List):
        """Update chart with new data points"""
        if not QT_AVAILABLE or not hasattr(self, 'series'):
            return
            
        try:
            # Clear existing data
            self.series.clear()
            
            # Add new data points
            for timestamp, value in data_points[-self.max_points:]:
                # Convert timestamp to QDateTime milliseconds
                ms_timestamp = int(timestamp * 1000)
                self.series.append(ms_timestamp, value)
            
            # Update axes ranges
            if data_points:
                timestamps = [point[0] * 1000 for point in data_points[-self.max_points:]]
                values = [point[1] for point in data_points[-self.max_points:]]
                
                if timestamps:
                    self.x_axis.setRange(min(timestamps), max(timestamps))
                
                if values:
                    min_val = min(values)
                    max_val = max(values)
                    padding = (max_val - min_val) * 0.1
                    self.y_axis.setRange(min_val - padding, max_val + padding)
                    
        except Exception as e:
            logging.debug(f"Chart update failed: {e}")


class ServiceHealthIndicator(QWidget):
    """Service health indicator with metrics display"""
    
    def __init__(self, service_name: str, parent=None):
        super().__init__(parent)
        self.service_name = service_name
        self.is_healthy = False
        self.last_metrics = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the health indicator UI"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header with status
        header_layout = QHBoxLayout()
        
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("color: #F44336; font-size: 16px;")  # Red initially
        
        self.service_label = QLabel(self.service_name)
        font = QFont()
        font.setBold(True)
        self.service_label.setFont(font)
        
        header_layout.addWidget(self.status_indicator)
        header_layout.addWidget(self.service_label)
        header_layout.addStretch()
        
        # Metrics display
        self.metrics_label = QLabel("Initializing...")
        self.metrics_label.setStyleSheet("color: gray; font-size: 10px;")
        
        # Health score bar
        self.health_bar = QProgressBar()
        self.health_bar.setRange(0, 100)
        self.health_bar.setValue(0)
        self.health_bar.setMaximumHeight(10)
        
        layout.addLayout(header_layout)
        layout.addWidget(self.metrics_label)
        layout.addWidget(self.health_bar)
    
    def update_health(self, is_healthy: bool, metrics: Dict = None):
        """Update health status and metrics"""
        self.is_healthy = is_healthy
        self.last_metrics = metrics or {}
        
        if not hasattr(self, 'status_indicator'):
            return
        
        # Update status indicator
        color = "#4CAF50" if is_healthy else "#F44336"  # Green/Red
        self.status_indicator.setStyleSheet(f"color: {color}; font-size: 16px;")
        
        # Update metrics display
        metrics_text = self.format_metrics(metrics)
        self.metrics_label.setText(metrics_text)
        
        # Update health score
        health_score = self.calculate_health_score(is_healthy, metrics)
        self.health_bar.setValue(health_score)
        
        # Color code health bar
        if health_score >= 80:
            self.health_bar.setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }")
        elif health_score >= 60:
            self.health_bar.setStyleSheet("QProgressBar::chunk { background-color: #FF9800; }")
        else:
            self.health_bar.setStyleSheet("QProgressBar::chunk { background-color: #F44336; }")
    
    def format_metrics(self, metrics: Dict) -> str:
        """Format metrics for display"""
        if not metrics:
            return "No metrics available"
        
        # Format based on service type and available metrics
        parts = []
        
        if 'response_time' in metrics:
            parts.append(f"Response: {metrics['response_time']:.0f}ms")
        
        if 'throughput' in metrics:
            parts.append(f"Throughput: {metrics['throughput']:.1f}/s")
        
        if 'memory_usage' in metrics:
            parts.append(f"Memory: {metrics['memory_usage']:.0f}MB")
        
        if 'utilization' in metrics:
            parts.append(f"Usage: {metrics['utilization']:.1f}%")
        
        if 'samples_count' in metrics:
            parts.append(f"Samples: {metrics['samples_count']}")
        
        return " | ".join(parts) if parts else "Active"
    
    def calculate_health_score(self, is_healthy: bool, metrics: Dict) -> int:
        """Calculate health score (0-100)"""
        if not is_healthy:
            return 0
        
        # Base score for being healthy
        score = 70
        
        # Adjust based on metrics
        if metrics:
            # Response time impact (lower is better)
            if 'response_time' in metrics:
                response_time = metrics['response_time']
                if response_time < 100:
                    score += 20
                elif response_time < 500:
                    score += 10
                else:
                    score -= 10
            
            # Utilization impact (moderate usage is good)
            if 'utilization' in metrics:
                utilization = metrics['utilization']
                if 20 <= utilization <= 80:
                    score += 10
                elif utilization > 90:
                    score -= 20
        
        return max(0, min(100, score))


class RealTimeStatusMonitor(QWidget):
    """Main real-time status monitoring widget"""
    
    def __init__(self, plugin_instance=None, parent=None):
        super().__init__(parent)
        self.plugin = plugin_instance
        self.metrics_collector = MetricsCollector(plugin_instance)
        self.performance_charts = {}
        self.service_indicators = {}
        self.setup_ui()
        self.setup_connections()
        self.start_monitoring()
    
    def setup_ui(self):
        """Initialize the monitoring UI"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("Real-time Status Monitor")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #1976D2; margin-bottom: 10px;")
        
        # Service health section
        health_section = self.create_service_health_section()
        
        # Performance charts section
        charts_section = self.create_performance_charts_section()
        
        layout.addWidget(title)
        layout.addWidget(health_section)
        layout.addWidget(charts_section)
    
    def create_service_health_section(self) -> QWidget:
        """Create service health monitoring section"""
        if not QT_AVAILABLE:
            return QWidget()
            
        group = QGroupBox("Service Health")
        layout = QGridLayout(group)
        
        services = [
            "Sample Database",
            "Validation Framework",
            "GPU Profiler",
            "Pattern Database"
        ]
        
        for i, service in enumerate(services):
            indicator = ServiceHealthIndicator(service)
            self.service_indicators[service] = indicator
            
            row = i // 2
            col = i % 2
            layout.addWidget(indicator, row, col)
        
        return group
    
    def create_performance_charts_section(self) -> QWidget:
        """Create performance charts section"""
        if not QT_AVAILABLE:
            return QWidget()
            
        group = QGroupBox("Performance Metrics")
        layout = QGridLayout(group)
        
        # Define charts
        chart_configs = [
            ("CPU Usage", "cpu_usage", "%"),
            ("Memory Usage", "memory_usage", "MB"),
            ("GPU Utilization", "gpu_utilization", "%"),
            ("Response Time", "response_time", "ms")
        ]
        
        for i, (title, metric, unit) in enumerate(chart_configs):
            chart = PerformanceChart(title, metric, unit)
            self.performance_charts[metric] = chart
            
            row = i // 2
            col = i % 2
            layout.addWidget(chart, row, col)
        
        return group
    
    def setup_connections(self):
        """Setup signal connections"""
        if not QT_AVAILABLE:
            return
            
        # Connect metrics collector signals
        if self.metrics_collector.metrics_updated:
            self.metrics_collector.metrics_updated.connect(self.on_metrics_updated)
        
        if self.metrics_collector.service_status_changed:
            self.metrics_collector.service_status_changed.connect(self.on_service_status_changed)
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.metrics_collector.start_collection(interval=1.0)
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.metrics_collector.stop_collection()
    
    def on_metrics_updated(self, metrics: Dict):
        """Handle metrics update"""
        try:
            # Update performance charts
            for metric_name, chart in self.performance_charts.items():
                history = self.metrics_collector.get_metrics_history(metric_name, 60)
                chart.update_data(history)
            
            # Update service health indicators
            service_status = metrics.get('service_status', {})
            service_mapping = {
                "Sample Database": "sample_database",
                "Validation Framework": "validation_framework",
                "GPU Profiler": "gpu_profiler",
                "Pattern Database": "pattern_database"
            }
            
            for display_name, service_key in service_mapping.items():
                if display_name in self.service_indicators:
                    is_healthy = service_status.get(service_key, False)
                    # Get service-specific metrics if available
                    service_metrics = {}  # Would be populated from actual service metrics
                    
                    self.service_indicators[display_name].update_health(is_healthy, service_metrics)
                    
        except Exception as e:
            logging.debug(f"Metrics update handling failed: {e}")
    
    def on_service_status_changed(self, service_name: str, is_available: bool):
        """Handle service status change"""
        logging.info(f"Service {service_name} status changed: {'Available' if is_available else 'Unavailable'}")
    
    def closeEvent(self, event):
        """Handle widget close event"""
        self.stop_monitoring()
        super().closeEvent(event)
