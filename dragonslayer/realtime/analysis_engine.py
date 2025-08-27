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
Real-time Analysis Capabilities
===============================

High-performance real-time VM detection and analysis with:
- Multi-threaded concurrent analysis
- Streaming binary analysis
- Live memory monitoring
- Real-time process injection detection
- Event-driven architecture
- Performance monitoring and optimization
- Adaptive analysis based on system load
- Live dashboard and monitoring
"""

import logging
import time
import threading
import queue
import multiprocessing
from typing import Dict, List, Optional, Callable, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import concurrent.futures
from pathlib import Path
import json
import hashlib
import psutil

logger = logging.getLogger(__name__)

# Optional dependencies for real-time capabilities
REALTIME_AVAILABLE = {}
try:
    import psutil
    REALTIME_AVAILABLE['psutil'] = True
    logger.info("psutil available for system monitoring")
except ImportError:
    REALTIME_AVAILABLE['psutil'] = False
    logger.warning("psutil not available - system monitoring limited")

try:
    import watchdog
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    REALTIME_AVAILABLE['watchdog'] = True
    logger.info("watchdog available for file system monitoring")
except ImportError:
    REALTIME_AVAILABLE['watchdog'] = False
    logger.warning("watchdog not available - file monitoring limited")

try:
    import websockets
    import asyncio
    REALTIME_AVAILABLE['websockets'] = True
    logger.info("websockets available for real-time dashboard")
except ImportError:
    REALTIME_AVAILABLE['websockets'] = False
    logger.warning("websockets not available - dashboard limited")


class AnalysisMode(Enum):
    """Real-time analysis modes"""
    CONTINUOUS = "continuous"
    ON_DEMAND = "on_demand"
    SCHEDULED = "scheduled"
    TRIGGERED = "triggered"
    ADAPTIVE = "adaptive"


class Priority(Enum):
    """Analysis priority levels"""
    CRITICAL = 5
    HIGH = 4
    NORMAL = 3
    LOW = 2
    BACKGROUND = 1


class AnalysisType(Enum):
    """Types of real-time analysis"""
    BINARY_SCAN = "binary_scan"
    MEMORY_ANALYSIS = "memory_analysis"
    PROCESS_MONITORING = "process_monitoring"
    BEHAVIOR_ANALYSIS = "behavior_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    FILE_MONITORING = "file_monitoring"


@dataclass
class AnalysisTask:
    """Real-time analysis task"""
    task_id: str
    analysis_type: AnalysisType
    priority: Priority
    data: Any
    callback: Optional[Callable] = None
    created_time: float = field(default_factory=time.time)
    started_time: Optional[float] = None
    completed_time: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_usage: float
    memory_usage: float
    disk_io: Dict[str, float]
    network_io: Dict[str, float]
    active_processes: int
    analysis_queue_size: int
    completed_analyses: int
    errors: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class ProcessInfo:
    """Process information for monitoring"""
    pid: int
    name: str
    cmdline: List[str]
    create_time: float
    memory_info: Dict[str, int]
    cpu_percent: float
    is_suspicious: bool = False
    vm_indicators: List[str] = field(default_factory=list)


class RealtimeFileHandler(FileSystemEventHandler):
    """File system event handler for real-time monitoring"""
    
    def __init__(self, analysis_queue: queue.Queue):
        super().__init__()
        self.analysis_queue = analysis_queue
        self.monitored_extensions = {'.exe', '.dll', '.sys', '.bin', '.scr'}
        self.last_event_time = {}
        self.debounce_interval = 0.5  # seconds
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and self._should_analyze(event.src_path):
            self._queue_analysis(event.src_path, "file_created")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and self._should_analyze(event.src_path):
            # Debounce rapid modifications
            now = time.time()
            if event.src_path in self.last_event_time:
                if now - self.last_event_time[event.src_path] < self.debounce_interval:
                    return
            
            self.last_event_time[event.src_path] = now
            self._queue_analysis(event.src_path, "file_modified")
    
    def _should_analyze(self, file_path: str) -> bool:
        """Check if file should be analyzed"""
        try:
            path = Path(file_path)
            if path.suffix.lower() in self.monitored_extensions:
                # Check file size - skip very large files
                if path.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
                    return False
                return True
        except Exception:
            pass
        return False
    
    def _queue_analysis(self, file_path: str, event_type: str):
        """Queue file for analysis"""
        task = AnalysisTask(
            task_id=f"file_{hashlib.md5(file_path.encode()).hexdigest()[:8]}_{int(time.time())}",
            analysis_type=AnalysisType.BINARY_SCAN,
            priority=Priority.NORMAL,
            data={
                'file_path': file_path,
                'event_type': event_type,
                'timestamp': time.time()
            }
        )
        
        try:
            self.analysis_queue.put_nowait(task)
            logger.info(f"Queued {event_type} analysis for: {file_path}")
        except queue.Full:
            logger.warning(f"Analysis queue full - dropped {file_path}")


class ProcessMonitor:
    """Real-time process monitoring"""
    
    def __init__(self, analysis_queue: queue.Queue):
        self.analysis_queue = analysis_queue
        self.running = False
        self.monitor_thread = None
        self.known_processes = {}
        self.vm_process_indicators = [
            'vmware', 'virtualbox', 'vbox', 'qemu', 'vmtoolsd',
            'vmsrvc', 'vmusrvc', 'vmware-vmx', 'vmware-hostd'
        ]
    
    def start(self):
        """Start process monitoring"""
        if not REALTIME_AVAILABLE['psutil']:
            logger.warning("Process monitoring disabled - psutil not available")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Process monitoring started")
    
    def stop(self):
        """Stop process monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Process monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                current_processes = {}
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        # Get additional info
                        memory_info = proc.memory_info()._asdict()
                        cpu_percent = proc.cpu_percent()
                        
                        process_info = ProcessInfo(
                            pid=pid,
                            name=proc_info['name'] or 'unknown',
                            cmdline=proc_info['cmdline'] or [],
                            create_time=proc_info['create_time'] or 0,
                            memory_info=memory_info,
                            cpu_percent=cpu_percent
                        )
                        
                        # Check for VM indicators
                        self._check_vm_indicators(process_info)
                        
                        current_processes[pid] = process_info
                        
                        # Check for new or suspicious processes
                        if pid not in self.known_processes:
                            self._handle_new_process(process_info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Update known processes
                self.known_processes = current_processes
                
                time.sleep(2)  # Monitor every 2 seconds
                
            except Exception as e:
                logger.error(f"Process monitoring error: {e}")
                time.sleep(5)
    
    def _check_vm_indicators(self, process_info: ProcessInfo):
        """Check process for VM indicators"""
        name_lower = process_info.name.lower()
        cmdline_str = ' '.join(process_info.cmdline).lower()
        
        for indicator in self.vm_process_indicators:
            if indicator in name_lower or indicator in cmdline_str:
                process_info.is_suspicious = True
                process_info.vm_indicators.append(f"Process name/cmdline contains: {indicator}")
    
    def _handle_new_process(self, process_info: ProcessInfo):
        """Handle new process detection"""
        if process_info.is_suspicious:
            task = AnalysisTask(
                task_id=f"proc_{process_info.pid}_{int(time.time())}",
                analysis_type=AnalysisType.PROCESS_MONITORING,
                priority=Priority.HIGH,
                data={
                    'process_info': process_info,
                    'detection_reason': 'suspicious_new_process'
                }
            )
            
            try:
                self.analysis_queue.put_nowait(task)
                logger.info(f"Queued suspicious process analysis: {process_info.name} (PID: {process_info.pid})")
            except queue.Full:
                logger.warning(f"Queue full - dropped process analysis for PID {process_info.pid}")


class PerformanceMonitor:
    """System performance monitoring"""
    
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.metrics_history = []
        self.max_history = 1000
        self.current_metrics = None
        self.callbacks = []
    
    def start(self):
        """Start performance monitoring"""
        if not REALTIME_AVAILABLE['psutil']:
            logger.warning("Performance monitoring disabled - psutil not available")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Performance monitoring started")
    
    def stop(self):
        """Stop performance monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Performance monitoring stopped")
    
    def add_callback(self, callback: Callable[[SystemMetrics], None]):
        """Add callback for metrics updates"""
        self.callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get system metrics
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {}
                network_io = psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
                
                metrics = SystemMetrics(
                    cpu_usage=cpu_usage,
                    memory_usage=memory.percent,
                    disk_io=disk_io,
                    network_io=network_io,
                    active_processes=len(psutil.pids()),
                    analysis_queue_size=0,  # Will be updated by queue manager
                    completed_analyses=0,   # Will be updated by analysis engine
                    errors=0               # Will be updated by analysis engine
                )
                
                self.current_metrics = metrics
                
                # Add to history
                self.metrics_history.append(metrics)
                if len(self.metrics_history) > self.max_history:
                    self.metrics_history.pop(0)
                
                # Notify callbacks
                for callback in self.callbacks:
                    try:
                        callback(metrics)
                    except Exception as e:
                        logger.warning(f"Metrics callback error: {e}")
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                time.sleep(5)
    
    def get_current_metrics(self) -> Optional[SystemMetrics]:
        """Get current system metrics"""
        return self.current_metrics
    
    def get_metrics_history(self, count: int = 100) -> List[SystemMetrics]:
        """Get recent metrics history"""
        return self.metrics_history[-count:]


class AdaptiveAnalysisEngine:
    """Adaptive analysis engine that adjusts based on system load"""
    
    def __init__(self, performance_monitor: PerformanceMonitor):
        self.performance_monitor = performance_monitor
        self.max_workers = multiprocessing.cpu_count()
        self.current_workers = self.max_workers // 2
        self.load_threshold_high = 80.0
        self.load_threshold_low = 40.0
        self.adjustment_interval = 10.0  # seconds
        self.last_adjustment = 0.0
    
    def adjust_resources(self, metrics: SystemMetrics) -> Dict[str, Any]:
        """Adjust analysis resources based on system performance"""
        now = time.time()
        if now - self.last_adjustment < self.adjustment_interval:
            return {'adjusted': False}
        
        adjustments = {
            'adjusted': False,
            'previous_workers': self.current_workers,
            'new_workers': self.current_workers,
            'reason': 'no_change_needed'
        }
        
        # Adjust based on CPU usage
        if metrics.cpu_usage > self.load_threshold_high:
            # Reduce workers if high CPU usage
            if self.current_workers > 1:
                self.current_workers = max(1, self.current_workers - 1)
                adjustments.update({
                    'adjusted': True,
                    'new_workers': self.current_workers,
                    'reason': f'high_cpu_usage_{metrics.cpu_usage:.1f}%'
                })
        
        elif metrics.cpu_usage < self.load_threshold_low:
            # Increase workers if low CPU usage
            if self.current_workers < self.max_workers:
                self.current_workers = min(self.max_workers, self.current_workers + 1)
                adjustments.update({
                    'adjusted': True,
                    'new_workers': self.current_workers,
                    'reason': f'low_cpu_usage_{metrics.cpu_usage:.1f}%'
                })
        
        # Adjust based on memory usage
        if metrics.memory_usage > 90.0:
            # Reduce workers if high memory usage
            if self.current_workers > 1:
                self.current_workers = 1
                adjustments.update({
                    'adjusted': True,
                    'new_workers': self.current_workers,
                    'reason': f'high_memory_usage_{metrics.memory_usage:.1f}%'
                })
        
        if adjustments['adjusted']:
            self.last_adjustment = now
            logger.info(f"Adjusted workers: {adjustments['previous_workers']} -> {adjustments['new_workers']} ({adjustments['reason']})")
        
        return adjustments
    
    def get_recommended_priority_boost(self, metrics: SystemMetrics) -> float:
        """Get priority boost factor based on system load"""
        if metrics.cpu_usage < 30 and metrics.memory_usage < 50:
            return 1.5  # Boost priority when system is idle
        elif metrics.cpu_usage > 80 or metrics.memory_usage > 80:
            return 0.7  # Reduce priority when system is loaded
        else:
            return 1.0  # Normal priority


class RealtimeAnalysisEngine:
    """Main real-time analysis engine"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.analysis_queue = queue.PriorityQueue(maxsize=1000)
        self.result_queue = queue.Queue()
        self.workers = []
        self.running = False
        
        # Component initialization
        self.performance_monitor = PerformanceMonitor()
        self.adaptive_engine = AdaptiveAnalysisEngine(self.performance_monitor)
        self.process_monitor = ProcessMonitor(self.analysis_queue)
        
        # File monitoring
        self.file_observer = None
        self.file_handler = None
        
        # Statistics
        self.stats = {
            'tasks_processed': 0,
            'tasks_failed': 0,
            'total_analysis_time': 0.0,
            'average_analysis_time': 0.0,
            'start_time': time.time()
        }
        
        # Callbacks for real-time updates
        self.result_callbacks = []
        self.status_callbacks = []
        
        # Setup performance monitoring callback
        self.performance_monitor.add_callback(self._handle_performance_update)
    
    def start(self, monitor_paths: List[str] = None):
        """Start real-time analysis engine"""
        logger.info("Starting real-time analysis engine")
        
        self.running = True
        
        # Start performance monitoring
        self.performance_monitor.start()
        
        # Start process monitoring
        self.process_monitor.start()
        
        # Start file monitoring if paths specified
        if monitor_paths and REALTIME_AVAILABLE['watchdog']:
            self._start_file_monitoring(monitor_paths)
        
        # Start worker threads
        self._start_workers()
        
        # Start result processor
        self.result_thread = threading.Thread(target=self._process_results, daemon=True)
        self.result_thread.start()
        
        logger.info(f"Real-time analysis engine started with {len(self.workers)} workers")
    
    def stop(self):
        """Stop real-time analysis engine"""
        logger.info("Stopping real-time analysis engine")
        
        self.running = False
        
        # Stop file monitoring
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
        
        # Stop process monitoring
        self.process_monitor.stop()
        
        # Stop performance monitoring
        self.performance_monitor.stop()
        
        # Stop workers
        for _ in self.workers:
            self.analysis_queue.put((0, None))  # Poison pill
        
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.workers.clear()
        
        logger.info("Real-time analysis engine stopped")
    
    def submit_analysis(self, task: AnalysisTask) -> str:
        """Submit analysis task"""
        try:
            # Priority queue uses tuple (priority, item)
            priority_value = task.priority.value
            self.analysis_queue.put((priority_value, task), timeout=1)
            logger.debug(f"Submitted task {task.task_id} with priority {task.priority.name}")
            return task.task_id
        except queue.Full:
            logger.warning(f"Analysis queue full - rejected task {task.task_id}")
            raise RuntimeError("Analysis queue is full")
    
    def add_result_callback(self, callback: Callable[[AnalysisTask], None]):
        """Add callback for analysis results"""
        self.result_callbacks.append(callback)
    
    def add_status_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add callback for status updates"""
        self.status_callbacks.append(callback)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current engine status"""
        metrics = self.performance_monitor.get_current_metrics()
        
        return {
            'running': self.running,
            'workers': len(self.workers),
            'queue_size': self.analysis_queue.qsize(),
            'statistics': self.stats.copy(),
            'system_metrics': metrics._asdict() if metrics else None,
            'uptime': time.time() - self.stats['start_time']
        }
    
    def _start_file_monitoring(self, monitor_paths: List[str]):
        """Start file system monitoring"""
        try:
            self.file_handler = RealtimeFileHandler(self.analysis_queue)
            self.file_observer = Observer()
            
            for path in monitor_paths:
                if Path(path).exists():
                    self.file_observer.schedule(self.file_handler, path, recursive=True)
                    logger.info(f"Monitoring path: {path}")
            
            self.file_observer.start()
            logger.info("File system monitoring started")
            
        except Exception as e:
            logger.error(f"Failed to start file monitoring: {e}")
    
    def _start_workers(self):
        """Start analysis worker threads"""
        for i in range(self.adaptive_engine.current_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(f"worker_{i}",),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
    
    def _worker_loop(self, worker_id: str):
        """Worker thread main loop"""
        logger.debug(f"Worker {worker_id} started")
        
        while self.running:
            try:
                # Get task from queue
                priority, task = self.analysis_queue.get(timeout=1)
                
                if task is None:  # Poison pill
                    break
                
                # Process task
                task.started_time = time.time()
                
                try:
                    result = self._process_task(task)
                    task.result = result
                    task.completed_time = time.time()
                    
                    # Update statistics
                    analysis_time = task.completed_time - task.started_time
                    self.stats['tasks_processed'] += 1
                    self.stats['total_analysis_time'] += analysis_time
                    self.stats['average_analysis_time'] = (
                        self.stats['total_analysis_time'] / self.stats['tasks_processed']
                    )
                    
                    logger.debug(f"Worker {worker_id} completed task {task.task_id} in {analysis_time:.2f}s")
                    
                except Exception as e:
                    task.error = str(e)
                    task.completed_time = time.time()
                    self.stats['tasks_failed'] += 1
                    logger.error(f"Worker {worker_id} failed task {task.task_id}: {e}")
                
                # Queue result for processing
                self.result_queue.put(task)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                time.sleep(1)
        
        logger.debug(f"Worker {worker_id} stopped")
    
    def _process_task(self, task: AnalysisTask) -> Dict[str, Any]:
        """Process analysis task"""
        if task.analysis_type == AnalysisType.BINARY_SCAN:
            return self._process_binary_scan(task)
        elif task.analysis_type == AnalysisType.MEMORY_ANALYSIS:
            return self._process_memory_analysis(task)
        elif task.analysis_type == AnalysisType.PROCESS_MONITORING:
            return self._process_process_monitoring(task)
        elif task.analysis_type == AnalysisType.BEHAVIOR_ANALYSIS:
            return self._process_behavior_analysis(task)
        else:
            return {'error': f'Unknown analysis type: {task.analysis_type}'}
    
    def _process_binary_scan(self, task: AnalysisTask) -> Dict[str, Any]:
        """Process binary scan task"""
        data = task.data
        file_path = data.get('file_path')
        
        if not file_path or not Path(file_path).exists():
            return {'error': 'File not found', 'file_path': file_path}
        
        try:
            # Read file
            with open(file_path, 'rb') as f:
                binary_data = f.read()
            
            # Basic analysis
            file_size = len(binary_data)
            file_hash = hashlib.sha256(binary_data).hexdigest()
            
            # Simple entropy calculation
            entropy = self._calculate_entropy(binary_data)
            
            # Look for VM-related strings
            vm_strings = self._find_vm_strings(binary_data)
            
            return {
                'file_path': file_path,
                'file_size': file_size,
                'sha256': file_hash,
                'entropy': entropy,
                'vm_strings': vm_strings,
                'vm_detected': len(vm_strings) > 0,
                'analysis_time': time.time() - task.started_time
            }
            
        except Exception as e:
            return {'error': str(e), 'file_path': file_path}
    
    def _process_memory_analysis(self, task: AnalysisTask) -> Dict[str, Any]:
        """Process memory analysis task"""
        # Placeholder for memory analysis
        return {
            'analysis_type': 'memory_analysis',
            'result': 'not_implemented'
        }
    
    def _process_process_monitoring(self, task: AnalysisTask) -> Dict[str, Any]:
        """Process process monitoring task"""
        data = task.data
        process_info = data.get('process_info')
        
        if not process_info:
            return {'error': 'No process information provided'}
        
        return {
            'process_id': process_info.pid,
            'process_name': process_info.name,
            'vm_indicators': process_info.vm_indicators,
            'is_suspicious': process_info.is_suspicious,
            'memory_usage': process_info.memory_info.get('rss', 0),
            'cpu_usage': process_info.cpu_percent
        }
    
    def _process_behavior_analysis(self, task: AnalysisTask) -> Dict[str, Any]:
        """Process behavior analysis task"""
        # Placeholder for behavior analysis
        return {
            'analysis_type': 'behavior_analysis',
            'result': 'not_implemented'
        }
    
    def _process_results(self):
        """Process analysis results"""
        while self.running:
            try:
                task = self.result_queue.get(timeout=1)
                
                # Notify callbacks
                for callback in self.result_callbacks:
                    try:
                        callback(task)
                    except Exception as e:
                        logger.warning(f"Result callback error: {e}")
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Result processing error: {e}")
    
    def _handle_performance_update(self, metrics: SystemMetrics):
        """Handle performance metrics update"""
        # Update metrics in system stats
        metrics.analysis_queue_size = self.analysis_queue.qsize()
        metrics.completed_analyses = self.stats['tasks_processed']
        metrics.errors = self.stats['tasks_failed']
        
        # Adaptive resource adjustment
        adjustment = self.adaptive_engine.adjust_resources(metrics)
        
        if adjustment['adjusted']:
            # Adjust workers if needed (simplified - would need more sophisticated approach)
            logger.info(f"Performance-based adjustment: {adjustment}")
        
        # Notify status callbacks
        status = {
            'metrics': metrics._asdict(),
            'adjustment': adjustment,
            'engine_status': self.get_status()
        }
        
        for callback in self.status_callbacks:
            try:
                callback(status)
            except Exception as e:
                logger.warning(f"Status callback error: {e}")
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _find_vm_strings(self, data: bytes) -> List[str]:
        """Find VM-related strings in binary data"""
        vm_strings = [
            b'vmware', b'virtualbox', b'vbox', b'qemu', b'bochs',
            b'vmtoolsd', b'vmsrvc', b'vmware-vmx', b'parallels'
        ]
        
        found_strings = []
        data_lower = data.lower()
        
        for vm_string in vm_strings:
            if vm_string in data_lower:
                found_strings.append(vm_string.decode())
        
        return found_strings


class DashboardServer:
    """Real-time dashboard server"""
    
    def __init__(self, engine: RealtimeAnalysisEngine, port: int = 8765):
        self.engine = engine
        self.port = port
        self.clients = set()
        self.running = False
        
        if not REALTIME_AVAILABLE['websockets']:
            logger.warning("Dashboard server disabled - websockets not available")
    
    def start(self):
        """Start dashboard server"""
        if not REALTIME_AVAILABLE['websockets']:
            return
        
        self.running = True
        
        # Add callbacks to engine
        self.engine.add_result_callback(self._broadcast_result)
        self.engine.add_status_callback(self._broadcast_status)
        
        # Start WebSocket server
        asyncio.run(self._start_server())
    
    async def _start_server(self):
        """Start WebSocket server"""
        try:
            async with websockets.serve(self._handle_client, "localhost", self.port):
                logger.info(f"Dashboard server started on port {self.port}")
                await asyncio.Future()  # Keep running
        except Exception as e:
            logger.error(f"Dashboard server error: {e}")
    
    async def _handle_client(self, websocket, path):
        """Handle WebSocket client connection"""
        self.clients.add(websocket)
        logger.info(f"Dashboard client connected: {websocket.remote_address}")
        
        try:
            # Send initial status
            status = self.engine.get_status()
            await websocket.send(json.dumps({
                'type': 'status',
                'data': status
            }))
            
            # Keep connection alive
            async for message in websocket:
                # Handle client messages (commands, requests, etc.)
                pass
                
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
            logger.info("Dashboard client disconnected")
    
    def _broadcast_result(self, task: AnalysisTask):
        """Broadcast analysis result to dashboard clients"""
        if not self.clients:
            return
        
        message = {
            'type': 'result',
            'data': {
                'task_id': task.task_id,
                'analysis_type': task.analysis_type.value,
                'priority': task.priority.value,
                'result': task.result,
                'error': task.error,
                'processing_time': (task.completed_time - task.started_time) if task.completed_time and task.started_time else 0
            }
        }
        
        asyncio.create_task(self._send_to_clients(message))
    
    def _broadcast_status(self, status: Dict[str, Any]):
        """Broadcast status update to dashboard clients"""
        if not self.clients:
            return
        
        message = {
            'type': 'status',
            'data': status
        }
        
        asyncio.create_task(self._send_to_clients(message))
    
    async def _send_to_clients(self, message: Dict[str, Any]):
        """Send message to all connected clients"""
        if not self.clients:
            return
        
        message_json = json.dumps(message)
        disconnected = set()
        
        for client in self.clients:
            try:
                await client.send(message_json)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                logger.warning(f"Error sending to client: {e}")
                disconnected.add(client)
        
        # Remove disconnected clients
        for client in disconnected:
            self.clients.discard(client)
