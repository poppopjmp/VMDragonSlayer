#!/usr/bin/env python3
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
Binary Ninja Phase 2: UI/UX Enhancement - VM Structure Explorer
Interactive visualization of VM architecture and components.
"""

import logging
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

try:
    from PySide2.QtWidgets import (
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QTreeWidget,
        QTreeWidgetItem,
        QSplitter,
        QTextEdit,
        QLabel,
        QGroupBox,
        QPushButton,
        QComboBox,
        QFrame,
        QScrollArea,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QHeaderView,
        QProgressBar,
        QCheckBox,
    )
    from PySide2.QtCore import Qt, Signal, QTimer, pyqtSignal
    from PySide2.QtGui import QFont, QColor, QPalette, QIcon

    QT_AVAILABLE = True
except ImportError:
    # Mock classes for testing
    class QWidget:
        def __init__(self, parent=None):
            pass

    class QVBoxLayout:
        def __init__(self, parent=None):
            pass

    class QHBoxLayout:
        def __init__(self, parent=None):
            pass

    class QTreeWidget:
        def __init__(self, parent=None):
            pass

    class QTreeWidgetItem:
        def __init__(self, parent=None):
            pass

    class QSplitter:
        def __init__(self, parent=None):
            pass

    class QTextEdit:
        def __init__(self, parent=None):
            pass

    class QLabel:
        def __init__(self, parent=None):
            pass

    class QGroupBox:
        def __init__(self, parent=None):
            pass

    class QPushButton:
        def __init__(self, parent=None):
            pass

    class QComboBox:
        def __init__(self, parent=None):
            pass

    class QFrame:
        def __init__(self, parent=None):
            pass

    class QScrollArea:
        def __init__(self, parent=None):
            pass

    class QTabWidget:
        def __init__(self, parent=None):
            pass

    class QTableWidget:
        def __init__(self, parent=None):
            pass

    class QTableWidgetItem:
        def __init__(self, parent=None):
            pass

    class QHeaderView:
        def __init__(self, parent=None):
            pass

    class QProgressBar:
        def __init__(self, parent=None):
            pass

    class QCheckBox:
        def __init__(self, parent=None):
            pass

    class Signal:
        def __init__(self, *args):
            pass

        def emit(self, *args):
            pass

    class QTimer:
        def __init__(self, parent=None):
            pass

    class Qt:
        CheckState = None
        Checked = None
        Unchecked = None

    class QFont:
        def __init__(self):
            pass

    class QColor:
        def __init__(self, *args):
            pass

    class QPalette:
        def __init__(self):
            pass

    class QIcon:
        def __init__(self):
            pass

    QT_AVAILABLE = False


class VMComponentNode:
    """Represents a VM component in the hierarchy"""

    def __init__(
        self,
        name: str,
        component_type: str,
        confidence: float = 0.0,
        address: Optional[int] = None,
        size: Optional[int] = None,
    ):
        self.name = name
        self.component_type = component_type
        self.confidence = confidence
        self.address = address
        self.size = size
        self.children = []
        self.properties = {}
        self.patterns_matched = []

    def add_child(self, child_node):
        """Add a child component"""
        self.children.append(child_node)

    def add_property(self, key: str, value: Any):
        """Add a property to the component"""
        self.properties[key] = value

    def add_pattern(self, pattern_name: str, confidence: float):
        """Add a matched pattern"""
        self.patterns_matched.append({"name": pattern_name, "confidence": confidence})


class VMArchitectureTree(QTreeWidget):
    """Tree widget for displaying VM architecture hierarchy"""

    component_selected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.vm_components = {}

    def setup_ui(self):
        """Initialize the tree widget"""
        if not QT_AVAILABLE:
            return

        self.setHeaderLabels(["Component", "Type", "Confidence", "Address", "Size"])
        self.setAlternatingRowColors(True)
        self.setRootIsDecorated(True)
        self.setExpandsOnDoubleClick(True)

        # Configure columns
        header = self.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        # Connect signals
        self.itemSelectionChanged.connect(self.on_selection_changed)
        self.itemDoubleClicked.connect(self.on_item_double_clicked)

    def load_vm_structure(self, vm_analysis_data: Dict[str, Any]):
        """Load VM structure from analysis data"""
        self.clear()
        self.vm_components.clear()

        if not vm_analysis_data:
            return

        try:
            # Create root node
            root_item = QTreeWidgetItem(self)
            root_item.setText(0, "VM Root")
            root_item.setText(1, "Virtual Machine")
            root_item.setText(2, "100.0%")
            root_item.setExpanded(True)

            # Add VM components
            self._add_handlers(root_item, vm_analysis_data.get("handlers", []))
            self._add_dispatcher(root_item, vm_analysis_data.get("dispatcher", {}))
            self._add_interpreter_loop(
                root_item, vm_analysis_data.get("interpreter", {})
            )
            self._add_memory_layout(
                root_item, vm_analysis_data.get("memory_layout", {})
            )

        except Exception as e:
            logging.error(f"Error loading VM structure: {e}")

    def _add_handlers(self, parent_item: QTreeWidgetItem, handlers: List[Dict]):
        """Add VM handlers to the tree"""
        if not handlers:
            return

        handlers_item = QTreeWidgetItem(parent_item)
        handlers_item.setText(0, f"Handlers ({len(handlers)})")
        handlers_item.setText(1, "Handler Collection")
        handlers_item.setText(2, "N/A")
        handlers_item.setExpanded(True)

        for i, handler in enumerate(handlers):
            handler_item = QTreeWidgetItem(handlers_item)
            handler_item.setText(0, f"Handler_{i:02d}")
            handler_item.setText(1, handler.get("type", "Unknown"))
            handler_item.setText(2, f"{handler.get('confidence', 0.0)*100:.1f}%")
            handler_item.setText(3, f"0x{handler.get('address', 0):08x}")
            handler_item.setText(4, f"{handler.get('size', 0)} bytes")

            # Store handler data
            handler_item.setData(0, Qt.UserRole, handler)

    def _add_dispatcher(self, parent_item: QTreeWidgetItem, dispatcher: Dict):
        """Add VM dispatcher to the tree"""
        if not dispatcher:
            return

        disp_item = QTreeWidgetItem(parent_item)
        disp_item.setText(0, "Dispatcher")
        disp_item.setText(1, dispatcher.get("type", "Switch Dispatcher"))
        disp_item.setText(2, f"{dispatcher.get('confidence', 0.0)*100:.1f}%")
        disp_item.setText(3, f"0x{dispatcher.get('address', 0):08x}")
        disp_item.setText(4, f"{dispatcher.get('size', 0)} bytes")
        disp_item.setData(0, Qt.UserRole, dispatcher)

    def _add_interpreter_loop(self, parent_item: QTreeWidgetItem, interpreter: Dict):
        """Add interpreter loop to the tree"""
        if not interpreter:
            return

        interp_item = QTreeWidgetItem(parent_item)
        interp_item.setText(0, "Interpreter Loop")
        interp_item.setText(1, interpreter.get("type", "Main Loop"))
        interp_item.setText(2, f"{interpreter.get('confidence', 0.0)*100:.1f}%")
        interp_item.setText(3, f"0x{interpreter.get('address', 0):08x}")
        interp_item.setText(4, f"{interpreter.get('size', 0)} bytes")
        interp_item.setData(0, Qt.UserRole, interpreter)

    def _add_memory_layout(self, parent_item: QTreeWidgetItem, memory_layout: Dict):
        """Add memory layout information"""
        if not memory_layout:
            return

        mem_item = QTreeWidgetItem(parent_item)
        mem_item.setText(0, "Memory Layout")
        mem_item.setText(1, "Memory Structure")
        mem_item.setText(2, "N/A")
        mem_item.setExpanded(True)

        # Add memory regions
        for region_name, region_data in memory_layout.items():
            region_item = QTreeWidgetItem(mem_item)
            region_item.setText(0, region_name)
            region_item.setText(1, region_data.get("type", "Memory Region"))
            region_item.setText(2, f"{region_data.get('confidence', 0.0)*100:.1f}%")
            region_item.setText(3, f"0x{region_data.get('start_address', 0):08x}")
            region_item.setText(4, f"{region_data.get('size', 0)} bytes")
            region_item.setData(0, Qt.UserRole, region_data)

    def on_selection_changed(self):
        """Handle selection changes"""
        selected_items = self.selectedItems()
        if selected_items:
            item = selected_items[0]
            component_data = item.data(0, Qt.UserRole)
            if component_data:
                self.component_selected.emit(component_data)

    def on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle double-click events"""
        component_data = item.data(0, Qt.UserRole)
        if component_data and "address" in component_data:
            # Signal to navigate to address in Binary Ninja
            logging.info(f"Navigate to address: 0x{component_data['address']:08x}")


class ComponentDetailsPanel(QWidget):
    """Panel for displaying detailed information about selected components"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.current_component = None

    def setup_ui(self):
        """Initialize the details panel"""
        if not QT_AVAILABLE:
            return

        layout = QVBoxLayout(self)

        # Component overview
        overview_group = QGroupBox("Component Overview")
        overview_layout = QVBoxLayout(overview_group)

        self.name_label = QLabel("No component selected")
        self.name_label.setFont(QFont("", 12, QFont.Bold))
        overview_layout.addWidget(self.name_label)

        self.type_label = QLabel("")
        overview_layout.addWidget(self.type_label)

        self.confidence_label = QLabel("")
        overview_layout.addWidget(self.confidence_label)

        self.address_label = QLabel("")
        overview_layout.addWidget(self.address_label)

        layout.addWidget(overview_group)

        # Properties table
        props_group = QGroupBox("Properties")
        props_layout = QVBoxLayout(props_group)

        self.properties_table = QTableWidget()
        self.properties_table.setColumnCount(2)
        self.properties_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.properties_table.horizontalHeader().setStretchLastSection(True)
        props_layout.addWidget(self.properties_table)

        layout.addWidget(props_group)

        # Patterns matched
        patterns_group = QGroupBox("Pattern Matches")
        patterns_layout = QVBoxLayout(patterns_group)

        self.patterns_table = QTableWidget()
        self.patterns_table.setColumnCount(2)
        self.patterns_table.setHorizontalHeaderLabels(["Pattern", "Confidence"])
        self.patterns_table.horizontalHeader().setStretchLastSection(True)
        patterns_layout.addWidget(self.patterns_table)

        layout.addWidget(patterns_group)

        # Stretch
        layout.addStretch()

    def update_component(self, component_data: Dict[str, Any]):
        """Update the panel with component data"""
        self.current_component = component_data

        if not component_data:
            self.name_label.setText("No component selected")
            self.type_label.setText("")
            self.confidence_label.setText("")
            self.address_label.setText("")
            self.properties_table.setRowCount(0)
            self.patterns_table.setRowCount(0)
            return

        # Update overview
        self.name_label.setText(component_data.get("name", "Unknown Component"))
        self.type_label.setText(f"Type: {component_data.get('type', 'Unknown')}")

        confidence = component_data.get("confidence", 0.0)
        self.confidence_label.setText(f"Confidence: {confidence*100:.1f}%")

        if "address" in component_data:
            self.address_label.setText(f"Address: 0x{component_data['address']:08x}")
        else:
            self.address_label.setText("Address: N/A")

        # Update properties
        properties = component_data.get("properties", {})
        self.properties_table.setRowCount(len(properties))

        for row, (key, value) in enumerate(properties.items()):
            self.properties_table.setItem(row, 0, QTableWidgetItem(str(key)))
            self.properties_table.setItem(row, 1, QTableWidgetItem(str(value)))

        # Update patterns
        patterns = component_data.get("patterns_matched", [])
        self.patterns_table.setRowCount(len(patterns))

        for row, pattern in enumerate(patterns):
            self.patterns_table.setItem(
                row, 0, QTableWidgetItem(pattern.get("name", ""))
            )
            confidence_str = f"{pattern.get('confidence', 0.0)*100:.1f}%"
            self.patterns_table.setItem(row, 1, QTableWidgetItem(confidence_str))


class VMStructureExplorer(QWidget):
    """Main VM structure explorer widget"""

    navigate_to_address = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.vm_data = {}

    def setup_ui(self):
        """Initialize the UI"""
        if not QT_AVAILABLE:
            return

        layout = QVBoxLayout(self)

        # Title
        title = QLabel("VM Structure Explorer")
        title.setFont(QFont("", 14, QFont.Bold))
        layout.addWidget(title)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - architecture tree
        tree_panel = QWidget()
        tree_layout = QVBoxLayout(tree_panel)

        tree_label = QLabel("VM Architecture")
        tree_label.setFont(QFont("", 10, QFont.Bold))
        tree_layout.addWidget(tree_label)

        self.architecture_tree = VMArchitectureTree()
        tree_layout.addWidget(self.architecture_tree)

        # Controls
        controls_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.expand_all_btn = QPushButton("Expand All")
        self.collapse_all_btn = QPushButton("Collapse All")

        controls_layout.addWidget(self.refresh_btn)
        controls_layout.addWidget(self.expand_all_btn)
        controls_layout.addWidget(self.collapse_all_btn)
        controls_layout.addStretch()

        tree_layout.addLayout(controls_layout)
        splitter.addWidget(tree_panel)

        # Right panel - component details
        self.details_panel = ComponentDetailsPanel()
        splitter.addWidget(self.details_panel)

        # Set splitter proportions
        splitter.setSizes([300, 200])
        layout.addWidget(splitter)

        # Connect signals
        self.architecture_tree.component_selected.connect(
            self.details_panel.update_component
        )
        self.refresh_btn.clicked.connect(self.refresh_structure)
        self.expand_all_btn.clicked.connect(self.architecture_tree.expandAll)
        self.collapse_all_btn.clicked.connect(self.architecture_tree.collapseAll)

    def load_vm_analysis(self, analysis_data: Dict[str, Any]):
        """Load VM analysis data"""
        self.vm_data = analysis_data
        self.architecture_tree.load_vm_structure(analysis_data)

    def refresh_structure(self):
        """Refresh the VM structure display"""
        if self.vm_data:
            self.architecture_tree.load_vm_structure(self.vm_data)

    def get_selected_component(self) -> Optional[Dict[str, Any]]:
        """Get the currently selected component"""
        return self.details_panel.current_component


# Mock implementation for testing
if not QT_AVAILABLE:

    class VMStructureExplorer:
        def __init__(self, parent=None):
            self.vm_data = {}

        def load_vm_analysis(self, analysis_data: Dict[str, Any]):
            self.vm_data = analysis_data
            logging.info(
                f"VM Structure Explorer: Loaded analysis data with {len(analysis_data)} components"
            )

        def refresh_structure(self):
            logging.info("VM Structure Explorer: Refreshing structure")

        def get_selected_component(self) -> Optional[Dict[str, Any]]:
            return None
