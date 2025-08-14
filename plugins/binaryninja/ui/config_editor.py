#!/usr/bin/env python3
"""
Binary Ninja Phase 2: UI/UX Enhancement - Configuration Editor
Visual configuration management for VMDragonSlayer settings.
"""

import logging
import json
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path

try:
    from PySide2.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QTabWidget,
        QLabel, QGroupBox, QPushButton, QComboBox, QLineEdit, QSpinBox,
        QDoubleSpinBox, QCheckBox, QSlider, QTextEdit, QFileDialog,
        QMessageBox, QFrame, QScrollArea
    )
    from PySide2.QtCore import Qt, Signal
    from PySide2.QtGui import QFont, QValidator, QIntValidator, QDoubleValidator
    QT_AVAILABLE = True
except ImportError:
    # Mock classes for testing
    class QWidget: pass
    class Signal: pass
    QT_AVAILABLE = False


class ConfigurationModel:
    """Model for managing configuration data"""
    
    def __init__(self):
        self.config_data = {}
        self.default_config = self._get_default_config()
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'analysis': {
                'timeout': 300,
                'max_depth': 10,
                'confidence_threshold': 0.7,
                'enable_gpu': True,
                'parallel_threads': 4
            },
            'pattern_matching': {
                'min_confidence': 0.5,
                'max_patterns': 1000,
                'enable_fuzzy_matching': True,
                'signature_threshold': 0.8
            },
            'vm_detection': {
                'handler_min_size': 10,
                'dispatcher_patterns': ['switch', 'computed_jump', 'indirect_call'],
                'enable_heuristics': True,
                'vm_confidence_threshold': 0.6
            },
            'output': {
                'verbose_logging': False,
                'save_intermediate_results': True,
                'output_format': 'json',
                'export_path': ''
            },
            'ui': {
                'auto_refresh': True,
                'refresh_interval': 1000,
                'max_display_items': 500,
                'enable_animations': True
            }
        }
        
    def load_config(self, config_path: str) -> bool:
        """Load configuration from file"""
        try:
            path = Path(config_path)
            if not path.exists():
                self.config_data = self.default_config.copy()
                return False
                
            with open(path, 'r') as f:
                if path.suffix.lower() == '.json':
                    self.config_data = json.load(f)
                elif path.suffix.lower() in ['.yml', '.yaml']:
                    self.config_data = yaml.safe_load(f)
                else:
                    return False
                    
            # Merge with defaults for missing keys
            self._merge_with_defaults()
            return True
            
        except Exception as e:
            logging.error("Error loading config: %s", e)
            self.config_data = self.default_config.copy()
            return False
            
    def save_config(self, config_path: str) -> bool:
        """Save configuration to file"""
        try:
            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                if path.suffix.lower() == '.json':
                    json.dump(self.config_data, f, indent=2)
                elif path.suffix.lower() in ['.yml', '.yaml']:
                    yaml.dump(self.config_data, f, default_flow_style=False)
                else:
                    return False
                    
            return True
            
        except Exception as e:
            logging.error("Error saving config: %s", e)
            return False
            
    def _merge_with_defaults(self):
        """Merge loaded config with defaults"""
        def merge_dicts(default, loaded):
            result = default.copy()
            for key, value in loaded.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dicts(result[key], value)
                else:
                    result[key] = value
            return result
            
        self.config_data = merge_dicts(self.default_config, self.config_data)
        
    def get_value(self, section: str, key: str) -> Any:
        """Get configuration value"""
        return self.config_data.get(section, {}).get(key)
        
    def set_value(self, section: str, key: str, value: Any):
        """Set configuration value"""
        if section not in self.config_data:
            self.config_data[section] = {}
        self.config_data[section][key] = value
        
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config_data = self.default_config.copy()


class ConfigSectionWidget(QWidget):
    """Widget for editing a configuration section"""
    
    value_changed = Signal(str, str, object)
    
    def __init__(self, section_name: str, section_config: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.section_name = section_name
        self.section_config = section_config
        self.widgets = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the section UI"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        
        # Section title
        title = QLabel(self.section_name.replace('_', ' ').title())
        title.setFont(QFont("", 12, QFont.Bold))
        layout.addWidget(title)
        
        # Configuration items
        grid_layout = QGridLayout()
        row = 0
        
        for key, value in self.section_config.items():
            label = QLabel(key.replace('_', ' ').title() + ":")
            grid_layout.addWidget(label, row, 0)
            
            widget = self._create_widget_for_value(key, value)
            grid_layout.addWidget(widget, row, 1)
            
            self.widgets[key] = widget
            row += 1
            
        layout.addLayout(grid_layout)
        layout.addStretch()
        
    def _create_widget_for_value(self, key: str, value: Any) -> QWidget:
        """Create appropriate widget for configuration value"""
        if isinstance(value, bool):
            widget = QCheckBox()
            widget.setChecked(value)
            widget.toggled.connect(lambda v: self.value_changed.emit(self.section_name, key, v))
            return widget
            
        elif isinstance(value, int):
            widget = QSpinBox()
            widget.setRange(-999999, 999999)
            widget.setValue(value)
            widget.valueChanged.connect(lambda v: self.value_changed.emit(self.section_name, key, v))
            return widget
            
        elif isinstance(value, float):
            widget = QDoubleSpinBox()
            widget.setRange(0.0, 1.0)
            widget.setDecimals(2)
            widget.setSingleStep(0.01)
            widget.setValue(value)
            widget.valueChanged.connect(lambda v: self.value_changed.emit(self.section_name, key, v))
            return widget
            
        elif isinstance(value, list):
            widget = QTextEdit()
            widget.setMaximumHeight(80)
            widget.setPlainText('\n'.join(str(item) for item in value))
            widget.textChanged.connect(lambda: self._handle_list_change(widget, key))
            return widget
            
        else:  # String
            widget = QLineEdit()
            widget.setText(str(value))
            widget.textChanged.connect(lambda v: self.value_changed.emit(self.section_name, key, v))
            return widget
            
    def _handle_list_change(self, widget: QTextEdit, key: str):
        """Handle changes to list values"""
        text = widget.toPlainText()
        value_list = [line.strip() for line in text.split('\n') if line.strip()]
        self.value_changed.emit(self.section_name, key, value_list)
        
    def update_value(self, key: str, value: Any):
        """Update widget value"""
        if key not in self.widgets:
            return
            
        widget = self.widgets[key]
        
        if isinstance(widget, QCheckBox):
            widget.setChecked(value)
        elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
            widget.setValue(value)
        elif isinstance(widget, QTextEdit):
            if isinstance(value, list):
                widget.setPlainText('\n'.join(str(item) for item in value))
            else:
                widget.setPlainText(str(value))
        elif isinstance(widget, QLineEdit):
            widget.setText(str(value))


class ConfigurationEditor(QWidget):
    """Main configuration editor widget"""
    
    config_changed = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config_model = ConfigurationModel()
        self.section_widgets = {}
        self.current_config_path = ""
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the UI"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Configuration Editor")
        title.setFont(QFont("", 14, QFont.Bold))
        layout.addWidget(title)
        
        # File operations
        file_layout = QHBoxLayout()
        
        self.load_btn = QPushButton("Load Config")
        self.save_btn = QPushButton("Save Config")
        self.save_as_btn = QPushButton("Save As...")
        self.reset_btn = QPushButton("Reset to Defaults")
        
        file_layout.addWidget(self.load_btn)
        file_layout.addWidget(self.save_btn)
        file_layout.addWidget(self.save_as_btn)
        file_layout.addWidget(self.reset_btn)
        file_layout.addStretch()
        
        layout.addLayout(file_layout)
        
        # Current file label
        self.file_label = QLabel("No configuration file loaded")
        layout.addWidget(self.file_label)
        
        # Configuration tabs
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Connect signals
        self.load_btn.clicked.connect(self.load_config)
        self.save_btn.clicked.connect(self.save_config)
        self.save_as_btn.clicked.connect(self.save_config_as)
        self.reset_btn.clicked.connect(self.reset_config)
        
        # Load default configuration
        self.load_default_config()
        
    def load_default_config(self):
        """Load default configuration"""
        self.config_model.config_data = self.config_model.default_config.copy()
        self._rebuild_ui()
        
    def load_config(self):
        """Load configuration from file"""
        if not QT_AVAILABLE:
            return
            
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", 
            "Config Files (*.json *.yml *.yaml);;All Files (*)"
        )
        
        if file_path:
            success = self.config_model.load_config(file_path)
            if success:
                self.current_config_path = file_path
                self.file_label.setText(f"Loaded: {Path(file_path).name}")
                self._rebuild_ui()
                QMessageBox.information(self, "Success", "Configuration loaded successfully")
            else:
                QMessageBox.warning(self, "Error", "Failed to load configuration file")
                
    def save_config(self):
        """Save current configuration"""
        if not self.current_config_path:
            self.save_config_as()
            return
            
        success = self.config_model.save_config(self.current_config_path)
        if success:
            QMessageBox.information(self, "Success", "Configuration saved successfully")
        else:
            QMessageBox.warning(self, "Error", "Failed to save configuration file")
            
    def save_config_as(self):
        """Save configuration to new file"""
        if not QT_AVAILABLE:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "", 
            "JSON Files (*.json);;YAML Files (*.yml);;All Files (*)"
        )
        
        if file_path:
            success = self.config_model.save_config(file_path)
            if success:
                self.current_config_path = file_path
                self.file_label.setText(f"Saved: {Path(file_path).name}")
                QMessageBox.information(self, "Success", "Configuration saved successfully")
            else:
                QMessageBox.warning(self, "Error", "Failed to save configuration file")
                
    def reset_config(self):
        """Reset configuration to defaults"""
        if not QT_AVAILABLE:
            return
            
        reply = QMessageBox.question(
            self, "Reset Configuration", 
            "Are you sure you want to reset all settings to default values?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.config_model.reset_to_defaults()
            self._rebuild_ui()
            self.config_changed.emit()
            
    def _rebuild_ui(self):
        """Rebuild the configuration UI"""
        # Clear existing tabs
        self.tab_widget.clear()
        self.section_widgets.clear()
        
        # Create tabs for each configuration section
        for section_name, section_config in self.config_model.config_data.items():
            section_widget = ConfigSectionWidget(section_name, section_config)
            section_widget.value_changed.connect(self._on_value_changed)
            
            scroll_area = QScrollArea()
            scroll_area.setWidget(section_widget)
            scroll_area.setWidgetResizable(True)
            
            self.tab_widget.addTab(scroll_area, section_name.replace('_', ' ').title())
            self.section_widgets[section_name] = section_widget
            
    def _on_value_changed(self, section: str, key: str, value: Any):
        """Handle configuration value changes"""
        self.config_model.set_value(section, key, value)
        self.config_changed.emit()
        
    def get_config_data(self) -> Dict[str, Any]:
        """Get current configuration data"""
        return self.config_model.config_data.copy()
        
    def set_config_data(self, config_data: Dict[str, Any]):
        """Set configuration data"""
        self.config_model.config_data = config_data
        self._rebuild_ui()


# Mock implementation for testing
if not QT_AVAILABLE:
    class ConfigurationEditor:
        def __init__(self, parent=None):
            self.config_model = ConfigurationModel()
            
        def load_default_config(self):
            logging.info("Configuration Editor: Loading default config")
            
        def get_config_data(self) -> Dict[str, Any]:
            return self.config_model.config_data.copy()
            
        def set_config_data(self, config_data: Dict[str, Any]):
            self.config_model.config_data = config_data
            logging.info("Configuration Editor: Config data updated")
