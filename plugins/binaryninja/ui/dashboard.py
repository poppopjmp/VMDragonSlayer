#!/usr/bin/env python3
"""
Binary Ninja Phase 2: UI/UX Enhancement - Main Dashboard
Real-time analysis dashboard for VMDragonSlayer Binary Ninja plugin.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from threading import Timer, Lock

try:
    import binaryninja as bn
    from binaryninja import interaction
    from PySide2.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QPushButton, QProgressBar, QTextEdit,
        QTreeWidget, QTreeWidgetItem, QTabWidget,
        QGroupBox, QFrame, QSplitter, QScrollArea
    )
    from PySide2.QtCore import QTimer, Qt, Signal, QThread, pyqtSignal
    from PySide2.QtGui import QFont, QColor, QPalette
    BN_UI_AVAILABLE = True
except ImportError:
    # Mock classes for testing without Binary Ninja
    class QWidget:
        def __init__(self, parent=None):
            pass
    class QVBoxLayout:
        def __init__(self, parent=None):
            pass
        def setContentsMargins(self, *args):
            pass
        def addWidget(self, widget):
            pass
        def addLayout(self, layout):
            pass
    class QHBoxLayout:
        def __init__(self, parent=None):
            pass
        def setContentsMargins(self, *args):
            pass
        def addWidget(self, widget):
            pass
        def addLayout(self, layout):
            pass
    class QGridLayout:
        def __init__(self, parent=None):
            pass
        def addWidget(self, widget, row, col, *args):
            pass
    class QLabel:
        def __init__(self, text="", parent=None):
            self.text = text
        def setText(self, text):
            self.text = text
        def setFont(self, font):
            pass
        def setAlignment(self, alignment):
            pass
        def setStyleSheet(self, style):
            pass
    class QPushButton:
        def __init__(self, text="", parent=None):
            self.text = text
        def setText(self, text):
            self.text = text
        def clicked(self):
            pass
        def setEnabled(self, enabled):
            pass
    class QProgressBar:
        def __init__(self, parent=None):
            self.value = 0
        def setValue(self, value):
            self.value = value
        def setRange(self, min_val, max_val):
            pass
    class QTreeWidget:
        def __init__(self, parent=None):
            pass
    class QTreeWidgetItem:
        def __init__(self, parent=None):
            pass
    class QTimer:
        def __init__(self, parent=None):
            pass
        def start(self, interval):
            pass
        def stop(self):
            pass
        def timeout(self):
            pass
    class Signal:
        def __init__(self, *args):
            pass
        def emit(self, *args):
            pass
        def connect(self, func):
            pass
    class QThread:
        def __init__(self, parent=None):
            pass
    class Qt:
        AlignCenter = None
        AlignLeft = None
    class QFont:
        def __init__(self):
            pass
    class QColor:
        def __init__(self, *args):
            pass
    class QPalette:
        def __init__(self):
            pass
    BN_UI_AVAILABLE = False


class StatusIndicator(QWidget):
    """Status indicator widget with color-coded status display"""
    
    def __init__(self, service_name: str, parent=None):
        if BN_UI_AVAILABLE:
            super().__init__(parent)
        self.service_name = service_name
        self.status = False
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the status indicator UI"""
        if not BN_UI_AVAILABLE:
            return
            
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Status indicator circle
        self.status_label = QLabel("●")
        self.status_label.setMinimumSize(16, 16)
        self.update_status_color()
        
        # Service name label
        self.name_label = QLabel(self.service_name)
        font = QFont()
        font.setBold(True)
        self.name_label.setFont(font)
        
        # Metrics label
        self.metrics_label = QLabel("N/A")
        self.metrics_label.setStyleSheet("color: gray;")
        
        layout.addWidget(self.status_label)
        layout.addWidget(self.name_label)
        layout.addStretch()
        layout.addWidget(self.metrics_label)
    
    def update_status(self, status: bool, metrics: Optional[Dict] = None):
        """Update the status indicator"""
        self.status = status
        self.update_status_color()
        
        if metrics:
            metrics_text = self.format_metrics(metrics)
            if hasattr(self, 'metrics_label'):
                self.metrics_label.setText(metrics_text)
    
    def update_status_color(self):
        """Update the status indicator color"""
        if not hasattr(self, 'status_label'):
            return
            
        color = "#4CAF50" if self.status else "#F44336"  # Green/Red
        self.status_label.setStyleSheet(f"color: {color}; font-size: 16px;")
    
    def format_metrics(self, metrics: Dict) -> str:
        """Format metrics for display"""
        if not metrics:
            return "N/A"
        
        try:
            # Validate that metrics is a dictionary
            if not isinstance(metrics, dict):
                return "N/A"
            
            # Format based on service type with type checking
            if 'execution_time' in metrics:
                exec_time = metrics['execution_time']
                if isinstance(exec_time, (int, float)):
                    return f"{exec_time:.2f}s"
                else:
                    return "N/A"
            elif 'samples_count' in metrics:
                samples = metrics['samples_count']
                if isinstance(samples, int) and samples is not None:
                    return f"{samples} samples"
                else:
                    return "N/A"
            elif 'patterns_loaded' in metrics:
                patterns = metrics['patterns_loaded']
                if isinstance(patterns, int) and patterns is not None:
                    return f"{patterns} patterns"
                else:
                    return "N/A"
            elif 'confidence' in metrics:
                confidence = metrics['confidence']
                if isinstance(confidence, (int, float)) and 0 <= confidence <= 1:
                    return f"{confidence:.1%} conf"
                else:
                    return "N/A"
            else:
                return "Active"
        except Exception:
            return "N/A"


class AnalysisProgressWidget(QWidget):
    """Analysis progress display with cancellation support"""
    
    def __init__(self, parent=None):
        if BN_UI_AVAILABLE:
            super().__init__(parent)
        self.is_running = False
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the progress widget UI"""
        if not BN_UI_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Progress header
        header_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-weight: bold; color: #2196F3;")
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_analysis)
        
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        header_layout.addWidget(self.cancel_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # Progress details
        self.details_label = QLabel("No analysis running")
        self.details_label.setStyleSheet("color: gray; font-size: 11px;")
        
        layout.addLayout(header_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.details_label)
    
    def start_analysis(self, binary_name: str):
        """Start analysis progress display"""
        self.is_running = True
        if hasattr(self, 'status_label'):
            self.status_label.setText("Analyzing...")
            self.status_label.setStyleSheet("font-weight: bold; color: #FF9800;")
            self.cancel_button.setEnabled(True)
            self.details_label.setText(f"Analyzing {binary_name}")
            self.progress_bar.setValue(0)
    
    def update_progress(self, progress: int, phase: str):
        """Update analysis progress"""
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setValue(progress)
            self.details_label.setText(f"Phase: {phase}")
    
    def complete_analysis(self, success: bool = True):
        """Complete analysis progress display"""
        self.is_running = False
        if hasattr(self, 'status_label'):
            if success:
                self.status_label.setText("Complete")
                self.status_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
                self.progress_bar.setValue(100)
                self.details_label.setText("Analysis completed successfully")
            else:
                self.status_label.setText("Failed")
                self.status_label.setStyleSheet("font-weight: bold; color: #F44336;")
                self.details_label.setText("Analysis failed")
            
            self.cancel_button.setEnabled(False)
    
    def cancel_analysis(self):
        """Cancel running analysis"""
        if self.is_running:
            self.is_running = False
            if hasattr(self, 'status_label'):
                self.status_label.setText("Cancelled")
                self.status_label.setStyleSheet("font-weight: bold; color: #FF5722;")
                self.details_label.setText("Analysis cancelled by user")
                self.cancel_button.setEnabled(False)


class VMHandlerTreeWidget(QWidget):
    """Interactive VM handler display with confidence visualization"""
    
    def __init__(self, parent=None):
        if BN_UI_AVAILABLE:
            super().__init__(parent)
        self.handlers = []
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the handler tree UI"""
        if not BN_UI_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header = QLabel("VM Handlers")
        header.setStyleSheet("font-weight: bold; font-size: 14px; color: #1976D2;")
        
        # Tree widget
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Handler", "Confidence", "Address", "Patterns"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemClicked.connect(self.on_handler_selected)
        
        layout.addWidget(header)
        layout.addWidget(self.tree)
    
    def update_handlers(self, handlers: List[Dict]):
        """Update the handler display"""
        self.handlers = handlers
        if not hasattr(self, 'tree'):
            return
            
        self.tree.clear()
        
        for handler in handlers:
            item = QTreeWidgetItem()
            
            # Handler name/type
            handler_name = handler.get('name', f"Handler_{handler.get('address', 0):x}")
            item.setText(0, handler_name)
            
            # Confidence with color coding
            confidence = handler.get('confidence', 0.0)
            confidence_text = f"{confidence:.1%}"
            item.setText(1, confidence_text)
            
            # Color code by confidence level
            if confidence >= 0.8:
                item.setBackground(1, QColor("#C8E6C9"))  # Light green
            elif confidence >= 0.6:
                item.setBackground(1, QColor("#FFF9C4"))  # Light yellow
            else:
                item.setBackground(1, QColor("#FFCDD2"))  # Light red
            
            # Address
            address = handler.get('address', 0)
            item.setText(2, f"0x{address:x}")
            
            # Pattern matches
            patterns = handler.get('pattern_matches', [])
            pattern_text = f"{len(patterns)} patterns" if patterns else "No patterns"
            item.setText(3, pattern_text)
            
            # Store handler data
            item.setData(0, Qt.UserRole, handler)
            
            self.tree.addTopLevelItem(item)
        
        # Auto-resize columns
        for i in range(4):
            self.tree.resizeColumnToContents(i)
    
    def on_handler_selected(self, item, column):
        """Handle handler selection"""
        handler_data = item.data(0, Qt.UserRole)
        if handler_data:
            # Emit signal or call callback for handler navigation
            self.navigate_to_handler(handler_data)
    
    def navigate_to_handler(self, handler: Dict):
        """Navigate to handler in Binary Ninja"""
        address = handler.get('address')
        if address and BN_UI_AVAILABLE:
            try:
                # Get current binary view and navigate
                context = bn.UIContext.activeContext()
                if context:
                    view_frame = context.getCurrentViewFrame()
                    if view_frame:
                        view_frame.navigate("Linear", address)
            except Exception as e:
                logging.warning(f"Navigation failed: {e}")


class VMStructureVisualizationWidget(QWidget):
    """VM structure visualization with interactive graph"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vm_structure = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the structure visualization UI"""
        if not BN_UI_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header = QLabel("VM Structure")
        header.setStyleSheet("font-weight: bold; font-size: 14px; color: #1976D2;")
        
        # Structure display area
        self.structure_area = QTextEdit()
        self.structure_area.setReadOnly(True)
        self.structure_area.setMaximumHeight(200)
        
        # Statistics
        self.stats_widget = self.create_stats_widget()
        
        layout.addWidget(header)
        layout.addWidget(self.structure_area)
        layout.addWidget(self.stats_widget)
    
    def create_stats_widget(self) -> QWidget:
        """Create VM statistics widget"""
        if not BN_UI_AVAILABLE:
            return QWidget()
            
        stats_frame = QGroupBox("VM Statistics")
        layout = QGridLayout(stats_frame)
        
        self.vm_type_label = QLabel("Unknown")
        self.handler_count_label = QLabel("0")
        self.dispatcher_count_label = QLabel("0")
        self.confidence_label = QLabel("0%")
        
        layout.addWidget(QLabel("VM Type:"), 0, 0)
        layout.addWidget(self.vm_type_label, 0, 1)
        layout.addWidget(QLabel("Handlers:"), 1, 0)
        layout.addWidget(self.handler_count_label, 1, 1)
        layout.addWidget(QLabel("Dispatchers:"), 2, 0)
        layout.addWidget(self.dispatcher_count_label, 2, 1)
        layout.addWidget(QLabel("Confidence:"), 3, 0)
        layout.addWidget(self.confidence_label, 3, 1)
        
        return stats_frame
    
    def update_structure(self, vm_structure: Dict):
        """Update the VM structure display"""
        self.vm_structure = vm_structure
        
        if hasattr(self, 'structure_area'):
            # Format structure for display
            structure_text = self.format_structure_display(vm_structure)
            self.structure_area.setPlainText(structure_text)
        
        if hasattr(self, 'vm_type_label'):
            # Update statistics
            vm_type = vm_structure.get('vm_type', 'Unknown')
            self.vm_type_label.setText(vm_type)
            
            handlers = vm_structure.get('handlers', [])
            self.handler_count_label.setText(str(len(handlers)))
            
            dispatchers = vm_structure.get('dispatcher_candidates', [])
            self.dispatcher_count_label.setText(str(len(dispatchers)))
            
            confidence = vm_structure.get('confidence', 0.0)
            self.confidence_label.setText(f"{confidence:.1%}")
    
    def format_structure_display(self, structure: Dict) -> str:
        """Format VM structure for text display"""
        lines = []
        
        # VM Type
        vm_type = structure.get('vm_type', 'Unknown')
        lines.append(f"VM Type: {vm_type}")
        lines.append("")
        
        # Dispatchers
        dispatchers = structure.get('dispatcher_candidates', [])
        if dispatchers:
            lines.append("Dispatchers:")
            for i, dispatcher in enumerate(dispatchers):
                addr = dispatcher.get('address', 0)
                refs = dispatcher.get('handler_refs', 0)
                lines.append(f"  {i+1}. 0x{addr:x} ({refs} handler refs)")
            lines.append("")
        
        # Handler organization
        handlers = structure.get('handlers', [])
        if handlers:
            lines.append(f"Handlers ({len(handlers)} total):")
            for i, handler in enumerate(handlers[:5]):  # Show first 5
                addr = handler.get('address', 0)
                conf = handler.get('confidence', 0.0)
                lines.append(f"  {i+1}. 0x{addr:x} (conf: {conf:.1%})")
            
            if len(handlers) > 5:
                lines.append(f"  ... and {len(handlers) - 5} more")
        
        return "\n".join(lines)


class VMDragonSlayerDashboard(QWidget):
    """Main dashboard widget for VMDragonSlayer Binary Ninja plugin"""
    
    def __init__(self, plugin_instance=None):
        super().__init__()
        self.plugin = plugin_instance
        self.update_timer = None
        self.update_lock = Lock()
        self.setup_ui()
        self.setup_update_timer()
    
    def setup_ui(self):
        """Initialize the main dashboard UI"""
        if not BN_UI_AVAILABLE:
            return
            
        self.setWindowTitle("VMDragonSlayer Dashboard")
        self.setMinimumSize(800, 600)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Main content area
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Controls and Status
        left_panel = self.create_left_panel()
        content_splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self.create_right_panel()
        content_splitter.addWidget(right_panel)
        
        # Set splitter proportions
        content_splitter.setStretchFactor(0, 1)
        content_splitter.setStretchFactor(1, 2)
        
        main_layout.addWidget(content_splitter)
    
    def create_header(self) -> QWidget:
        """Create dashboard header"""
        if not BN_UI_AVAILABLE:
            return QWidget()
            
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_frame.setStyleSheet("background-color: #1E88E5; color: white; padding: 10px;")
        
        layout = QHBoxLayout(header_frame)
        
        title = QLabel("VMDragonSlayer Analysis Dashboard")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        
        version_label = QLabel("v2.0 - Binary Ninja")
        version_label.setStyleSheet("font-size: 12px; opacity: 0.8;")
        
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(version_label)
        
        return header_frame
    
    def create_left_panel(self) -> QWidget:
        """Create left control panel"""
        if not BN_UI_AVAILABLE:
            return QWidget()
            
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Analysis controls
        controls_group = self.create_analysis_controls()
        layout.addWidget(controls_group)
        
        # Service status
        status_group = self.create_service_status()
        layout.addWidget(status_group)
        
        # Progress monitor
        self.progress_widget = AnalysisProgressWidget()
        layout.addWidget(self.progress_widget)
        
        layout.addStretch()
        
        return panel
    
    def create_analysis_controls(self) -> QWidget:
        """Create analysis control buttons"""
        if not BN_UI_AVAILABLE:
            return QWidget()
            
        group = QGroupBox("Analysis Controls")
        layout = QVBoxLayout(group)
        
        # Start analysis button
        self.start_button = QPushButton("Start Analysis")
        self.start_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")
        self.start_button.clicked.connect(self.start_analysis)
        
        # Quick scan button
        self.quick_scan_button = QPushButton("Quick Handler Scan")
        self.quick_scan_button.clicked.connect(self.quick_scan)
        
        # Settings button
        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self.show_settings)
        
        # Export button
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        
        layout.addWidget(self.start_button)
        layout.addWidget(self.quick_scan_button)
        layout.addWidget(self.settings_button)
        layout.addWidget(self.export_button)
        
        return group
    
    def create_service_status(self) -> QWidget:
        """Create service status indicators"""
        if not BN_UI_AVAILABLE:
            return QWidget()
            
        group = QGroupBox("Core Services Status")
        layout = QVBoxLayout(group)
        
        # Service indicators
        self.service_indicators = {}
        services = [
            "Sample Database",
            "Validation Framework", 
            "GPU Profiler",
            "Pattern Database"
        ]
        
        for service in services:
            indicator = StatusIndicator(service)
            self.service_indicators[service] = indicator
            layout.addWidget(indicator)
        
        return group
    
    def create_right_panel(self) -> QWidget:
        """Create right results panel"""
        if not BN_UI_AVAILABLE:
            return QWidget()
            
        # Tab widget for different result views
        self.results_tabs = QTabWidget()
        
        # VM Handlers tab
        self.handlers_widget = VMHandlerTreeWidget()
        self.results_tabs.addTab(self.handlers_widget, "VM Handlers")
        
        # VM Structure tab
        self.structure_widget = VMStructureVisualizationWidget()
        self.results_tabs.addTab(self.structure_widget, "VM Structure")
        
        # Analysis log tab
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setMaximumHeight(150)
        self.results_tabs.addTab(self.log_widget, "Analysis Log")
        
        return self.results_tabs
    
    def setup_update_timer(self):
        """Setup real-time update timer"""
        if not BN_UI_AVAILABLE:
            return
            
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_service_status)
        self.update_timer.start(1000)  # Update every second
    
    def update_service_status(self):
        """Update service status indicators"""
        if not self.plugin or not hasattr(self, 'service_indicators'):
            return
            
        with self.update_lock:
            try:
                # Get service status from plugin
                if hasattr(self.plugin, 'core_services'):
                    status = self.plugin.core_services.get_service_status()
                    metrics = self.plugin.core_services.get_service_metrics()
                    
                    service_mapping = {
                        "Sample Database": "sample_database",
                        "Validation Framework": "validation_framework",
                        "GPU Profiler": "gpu_profiler", 
                        "Pattern Database": "pattern_database"
                    }
                    
                    for display_name, service_key in service_mapping.items():
                        if display_name in self.service_indicators:
                            service_status = status.get(service_key, False)
                            service_metrics = metrics.get(service_key, {})
                            self.service_indicators[display_name].update_status(
                                service_status, service_metrics
                            )
            except Exception as e:
                logging.debug(f"Service status update failed: {e}")
    
    def start_analysis(self):
        """Start full VM analysis"""
        if not self.plugin:
            return
            
        try:
            # Get current binary view
            context = bn.UIContext.activeContext()
            if not context:
                return
                
            view_frame = context.getCurrentViewFrame()
            if not view_frame:
                return
                
            binary_view = view_frame.getCurrentBinaryView()
            if not binary_view:
                return
            
            # Start analysis in background thread
            binary_name = binary_view.file.filename
            self.progress_widget.start_analysis(binary_name)
            
            # Run analysis
            self.run_analysis_async(binary_view)
            
        except Exception as e:
            logging.error(f"Analysis start failed: {e}")
            self.progress_widget.complete_analysis(False)
    
    def run_analysis_async(self, binary_view):
        """Run analysis in background thread"""
        def analysis_worker():
            try:
                # Phase 1: Handler Discovery
                self.progress_widget.update_progress(20, "Handler Discovery")
                results = self.plugin.analyze_binary_view(binary_view)
                
                # Phase 2: Structure Analysis
                self.progress_widget.update_progress(60, "Structure Analysis")
                
                # Phase 3: Result Processing
                self.progress_widget.update_progress(90, "Processing Results")
                
                # Update UI with results
                self.update_results(results)
                
                # Complete
                self.progress_widget.complete_analysis(True)
                if hasattr(self, 'export_button'):
                    self.export_button.setEnabled(True)
                
            except Exception as e:
                logging.error(f"Analysis failed: {e}")
                self.progress_widget.complete_analysis(False)
        
        # Start worker thread
        import threading
        thread = threading.Thread(target=analysis_worker)
        thread.daemon = True
        thread.start()
    
    def update_results(self, results: Dict):
        """Update result displays"""
        try:
            # Update handlers
            handlers = results.get('handlers', [])
            self.handlers_widget.update_handlers(handlers)
            
            # Update structure
            vm_structure = results.get('vm_structure', {})
            self.structure_widget.update_structure(vm_structure)
            
            # Update log
            if hasattr(self, 'log_widget'):
                analysis_time = results.get('analysis_time', 0)
                confidence = results.get('confidence_score', 0)
                log_entry = f"[{time.strftime('%H:%M:%S')}] Analysis completed in {analysis_time:.2f}s (confidence: {confidence:.1%})\n"
                self.log_widget.append(log_entry)
                
        except Exception as e:
            logging.error(f"Results update failed: {e}")
    
    def quick_scan(self):
        """Perform quick handler scan"""
        # Implement quick scan functionality
        pass
    
    def show_settings(self):
        """Show settings dialog"""
        # Implement settings dialog
        pass
    
    def export_results(self):
        """Export analysis results"""
        # Implement results export
        pass


# Binary Ninja plugin integration functions
def create_dashboard_dock_widget():
    """Create dashboard as Binary Ninja dock widget"""
    if not BN_UI_AVAILABLE:
        return None
        
    try:
        # Get plugin instance
        from ..vmdragonslayer_bn import VMDragonSlayerBinaryNinjaPlugin
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
        
        # Create dashboard
        dashboard = VMDragonSlayerDashboard(plugin_instance)
        
        return dashboard
        
    except Exception as e:
        logging.error(f"Dashboard creation failed: {e}")
        return None


def register_dashboard_commands():
    """Register Binary Ninja commands for dashboard"""
    if not BN_UI_AVAILABLE:
        return
        
    try:
        import binaryninja as bn
        
        def show_dashboard(bv):
            """Show VMDragonSlayer dashboard"""
            dashboard = create_dashboard_dock_widget()
            if dashboard:
                # Add as dock widget
                bn.DockHandler.addDockWidget("VMDragonSlayer Dashboard", dashboard, Qt.RightDockWidgetArea)
        
        # Register command
        bn.PluginCommand.register(
            "VMDragonSlayer\\Show Dashboard",
            "Show VMDragonSlayer analysis dashboard",
            show_dashboard
        )
        
    except Exception as e:
        logging.error(f"Dashboard command registration failed: {e}")


# Initialize dashboard when module is imported
if BN_UI_AVAILABLE:
    register_dashboard_commands()
