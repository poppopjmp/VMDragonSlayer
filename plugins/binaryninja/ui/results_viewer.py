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
Binary Ninja Phase 2: UI/UX Enhancement - Results Viewer
Interactive visualization of VM analysis results with detailed views.
"""

import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from PySide2.QtWidgets import (
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QGridLayout,
        QLabel,
        QPushButton,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QTabWidget,
        QGroupBox,
        QSplitter,
        QHeaderView,
        QTableWidget,
        QTableWidgetItem,
        QProgressBar,
        QScrollArea,
        QFrame,
        QLineEdit,
        QComboBox,
    )
    from PySide2.QtCore import Qt, Signal, QSortFilterProxyModel, QAbstractTableModel
    from PySide2.QtGui import QFont, QColor, QPixmap, QPainter, QIcon

    QT_AVAILABLE = True
except ImportError:
    # Mock classes for testing
    class QWidget:
        pass

    class QAbstractTableModel:
        pass

    class Signal:
        pass

    QT_AVAILABLE = False


class HandlerTableModel(QAbstractTableModel):
    """Table model for VM handlers with sorting and filtering"""

    def __init__(self, handlers: List[Dict] = None):
        super().__init__()
        self.handlers = handlers or []
        self.headers = ["Address", "Name", "Confidence", "Type", "Patterns", "MLIL Ops"]

    def rowCount(self, parent=None):
        return len(self.handlers)

    def columnCount(self, parent=None):
        return len(self.headers)

    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def data(self, index, role):
        if not index.isValid() or not (0 <= index.row() < len(self.handlers)):
            return None

        handler = self.handlers[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            if column == 0:  # Address
                return f"0x{handler.get('address', 0):x}"
            elif column == 1:  # Name
                return handler.get("name", f"Handler_{handler.get('address', 0):x}")
            elif column == 2:  # Confidence
                return f"{handler.get('confidence', 0.0):.1%}"
            elif column == 3:  # Type
                return handler.get("handler_type", "Unknown")
            elif column == 4:  # Patterns
                patterns = handler.get("pattern_matches", [])
                return f"{len(patterns)} matches"
            elif column == 5:  # MLIL Operations
                ops = handler.get("mlil_operations", [])
                return ", ".join(ops[:3]) + ("..." if len(ops) > 3 else "")

        elif role == Qt.BackgroundRole and column == 2:  # Confidence color coding
            confidence = handler.get("confidence", 0.0)
            if confidence >= 0.8:
                return QColor("#C8E6C9")  # Light green
            elif confidence >= 0.6:
                return QColor("#FFF9C4")  # Light yellow
            else:
                return QColor("#FFCDD2")  # Light red

        elif role == Qt.UserRole:
            return handler

        return None

    def update_handlers(self, handlers: List[Dict]):
        """Update handlers data"""
        self.beginResetModel()
        self.handlers = handlers
        self.endResetModel()


class ConfidenceVisualizationWidget(QWidget):
    """Confidence level visualization with color-coded bars"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.confidence_data = {}
        self.setup_ui()

    def setup_ui(self):
        """Initialize confidence visualization UI"""
        if not QT_AVAILABLE:
            return

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Title
        title = QLabel("Confidence Distribution")
        title.setStyleSheet("font-weight: bold; font-size: 14px; color: #1976D2;")

        # Confidence levels display
        self.confidence_frame = QFrame()
        self.confidence_layout = QGridLayout(self.confidence_frame)

        # Statistics
        self.stats_label = QLabel("No data available")
        self.stats_label.setStyleSheet("color: gray; font-size: 11px;")

        layout.addWidget(title)
        layout.addWidget(self.confidence_frame)
        layout.addWidget(self.stats_label)

    def update_confidence_data(self, handlers: List[Dict]):
        """Update confidence visualization with handler data"""
        if not handlers:
            if hasattr(self, "stats_label"):
                self.stats_label.setText("No handlers detected")
            return

        # Calculate confidence statistics
        confidences = [h.get("confidence", 0.0) for h in handlers]

        # Group by confidence levels
        high_conf = len([c for c in confidences if c >= 0.8])
        medium_conf = len([c for c in confidences if 0.6 <= c < 0.8])
        low_conf = len([c for c in confidences if c < 0.6])

        self.confidence_data = {
            "high": high_conf,
            "medium": medium_conf,
            "low": low_conf,
            "average": sum(confidences) / len(confidences) if confidences else 0,
            "total": len(handlers),
        }

        if hasattr(self, "confidence_layout"):
            self.update_confidence_bars()
            self.update_statistics()

    def update_confidence_bars(self):
        """Update confidence level bars"""
        if not QT_AVAILABLE or not hasattr(self, "confidence_layout"):
            return

        # Clear existing widgets
        for i in reversed(range(self.confidence_layout.count())):
            self.confidence_layout.itemAt(i).widget().setParent(None)

        total = self.confidence_data.get("total", 0)
        if total == 0:
            return

        # Confidence levels
        levels = [
            ("High (≥80%)", self.confidence_data["high"], "#4CAF50"),
            ("Medium (60-80%)", self.confidence_data["medium"], "#FF9800"),
            ("Low (<60%)", self.confidence_data["low"], "#F44336"),
        ]

        for i, (label, count, color) in enumerate(levels):
            # Label
            level_label = QLabel(label)
            level_label.setStyleSheet("font-weight: bold;")

            # Progress bar
            progress = QProgressBar()
            progress.setRange(0, total)
            progress.setValue(count)
            progress.setStyleSheet(
                f"QProgressBar::chunk {{ background-color: {color}; }}"
            )

            # Count label
            count_label = QLabel(f"{count}/{total}")
            count_label.setMinimumWidth(50)

            self.confidence_layout.addWidget(level_label, i, 0)
            self.confidence_layout.addWidget(progress, i, 1)
            self.confidence_layout.addWidget(count_label, i, 2)

    def update_statistics(self):
        """Update confidence statistics"""
        if not hasattr(self, "stats_label"):
            return

        avg_conf = self.confidence_data.get("average", 0)
        total = self.confidence_data.get("total", 0)
        high_count = self.confidence_data.get("high", 0)

        stats_text = f"Average: {avg_conf:.1%} | Total Handlers: {total} | High Confidence: {high_count}"
        self.stats_label.setText(stats_text)


class PatternMatchViewer(QWidget):
    """Detailed pattern match results viewer"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pattern_matches = []
        self.setup_ui()

    def setup_ui(self):
        """Initialize pattern match viewer UI"""
        if not QT_AVAILABLE:
            return

        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Header with filter
        header_layout = QHBoxLayout()

        title = QLabel("Pattern Matches")
        title.setStyleSheet("font-weight: bold; font-size: 14px; color: #1976D2;")

        # Filter controls
        filter_label = QLabel("Filter:")
        self.pattern_filter = QComboBox()
        self.pattern_filter.addItems(
            ["All Patterns", "High Confidence", "VM Specific", "Control Flow"]
        )
        self.pattern_filter.currentTextChanged.connect(self.filter_patterns)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(filter_label)
        header_layout.addWidget(self.pattern_filter)

        # Pattern tree
        self.pattern_tree = QTreeWidget()
        self.pattern_tree.setHeaderLabels(
            ["Pattern", "Confidence", "Category", "Description"]
        )
        self.pattern_tree.setAlternatingRowColors(True)
        self.pattern_tree.itemClicked.connect(self.on_pattern_selected)

        # Pattern details
        self.details_text = QTextEdit()
        self.details_text.setMaximumHeight(100)
        self.details_text.setReadOnly(True)

        layout.addLayout(header_layout)
        layout.addWidget(self.pattern_tree)
        layout.addWidget(QLabel("Pattern Details:"))
        layout.addWidget(self.details_text)

    def update_patterns(self, handlers: List[Dict]):
        """Update pattern matches from handlers"""
        self.pattern_matches = []

        # Collect all pattern matches from handlers
        for handler in handlers:
            handler_patterns = handler.get("pattern_matches", [])
            for pattern in handler_patterns:
                pattern_info = pattern.copy()
                pattern_info["handler_address"] = handler.get("address", 0)
                self.pattern_matches.append(pattern_info)

        self.refresh_pattern_display()

    def refresh_pattern_display(self):
        """Refresh the pattern display tree"""
        if not hasattr(self, "pattern_tree"):
            return

        self.pattern_tree.clear()

        # Apply current filter
        filtered_patterns = self.apply_current_filter()

        # Group patterns by category
        categories = {}
        for pattern in filtered_patterns:
            category = pattern.get("category", "Unknown")
            if category not in categories:
                categories[category] = []
            categories[category].append(pattern)

        # Populate tree
        for category, patterns in categories.items():
            category_item = QTreeWidgetItem()
            category_item.setText(0, f"{category} ({len(patterns)})")
            category_item.setFont(0, QFont("", -1, QFont.Bold))

            for pattern in patterns:
                pattern_item = QTreeWidgetItem(category_item)

                # Pattern name
                pattern_name = pattern.get("pattern", "Unknown Pattern")
                pattern_item.setText(0, pattern_name)

                # Confidence
                confidence = pattern.get("confidence", 0.0)
                pattern_item.setText(1, f"{confidence:.1%}")

                # Category
                pattern_item.setText(2, pattern.get("category", "Unknown"))

                # Description
                description = pattern.get("description", "No description available")
                pattern_item.setText(
                    3,
                    description[:50] + "..." if len(description) > 50 else description,
                )

                # Store pattern data
                pattern_item.setData(0, Qt.UserRole, pattern)

                # Color code by confidence
                if confidence >= 0.8:
                    pattern_item.setBackground(1, QColor("#C8E6C9"))
                elif confidence >= 0.6:
                    pattern_item.setBackground(1, QColor("#FFF9C4"))
                else:
                    pattern_item.setBackground(1, QColor("#FFCDD2"))

            self.pattern_tree.addTopLevelItem(category_item)
            category_item.setExpanded(True)

        # Auto-resize columns
        for i in range(4):
            self.pattern_tree.resizeColumnToContents(i)

    def apply_current_filter(self) -> List[Dict]:
        """Apply current filter to pattern matches"""
        if not hasattr(self, "pattern_filter"):
            return self.pattern_matches

        filter_text = self.pattern_filter.currentText()

        if filter_text == "All Patterns":
            return self.pattern_matches
        elif filter_text == "High Confidence":
            return [p for p in self.pattern_matches if p.get("confidence", 0) >= 0.8]
        elif filter_text == "VM Specific":
            return [
                p for p in self.pattern_matches if "vm" in p.get("category", "").lower()
            ]
        elif filter_text == "Control Flow":
            return [
                p
                for p in self.pattern_matches
                if "control" in p.get("category", "").lower()
            ]

        return self.pattern_matches

    def filter_patterns(self):
        """Handle pattern filter change"""
        self.refresh_pattern_display()

    def on_pattern_selected(self, item, column):
        """Handle pattern selection"""
        pattern_data = item.data(0, Qt.UserRole)
        if pattern_data and hasattr(self, "details_text"):
            self.show_pattern_details(pattern_data)

    def show_pattern_details(self, pattern: Dict):
        """Show detailed pattern information"""
        details = []

        details.append(f"Pattern: {pattern.get('pattern', 'Unknown')}")
        details.append(f"Confidence: {pattern.get('confidence', 0.0):.1%}")
        details.append(f"Category: {pattern.get('category', 'Unknown')}")
        details.append(f"Handler Address: 0x{pattern.get('handler_address', 0):x}")
        details.append("")
        details.append(
            f"Description: {pattern.get('description', 'No description available')}"
        )

        if "signature" in pattern:
            details.append("")
            details.append(f"Signature: {pattern['signature']}")

        if "references" in pattern:
            details.append("")
            details.append("References:")
            for ref in pattern["references"][:5]:  # Show first 5 references
                details.append(f"  - {ref}")

        self.details_text.setPlainText("\n".join(details))


class AnalysisTimelineWidget(QWidget):
    """Timeline view of analysis progress and milestones"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.timeline_events = []
        self.setup_ui()

    def setup_ui(self):
        """Initialize timeline UI"""
        if not QT_AVAILABLE:
            return

        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Title
        title = QLabel("Analysis Timeline")
        title.setStyleSheet("font-weight: bold; font-size: 14px; color: #1976D2;")

        # Timeline area
        self.timeline_scroll = QScrollArea()
        self.timeline_widget = QWidget()
        self.timeline_layout = QVBoxLayout(self.timeline_widget)
        self.timeline_scroll.setWidget(self.timeline_widget)
        self.timeline_scroll.setWidgetResizable(True)

        layout.addWidget(title)
        layout.addWidget(self.timeline_scroll)

    def add_timeline_event(
        self, event_type: str, description: str, timestamp: float = None
    ):
        """Add a new timeline event"""
        if timestamp is None:
            timestamp = datetime.now().timestamp()

        event = {
            "type": event_type,
            "description": description,
            "timestamp": timestamp,
            "datetime": datetime.fromtimestamp(timestamp),
        }

        self.timeline_events.append(event)
        self.refresh_timeline()

    def refresh_timeline(self):
        """Refresh the timeline display"""
        if not hasattr(self, "timeline_layout"):
            return

        # Clear existing events
        for i in reversed(range(self.timeline_layout.count())):
            item = self.timeline_layout.itemAt(i)
            if item and item.widget():
                item.widget().setParent(None)

        # Sort events by timestamp (newest first)
        sorted_events = sorted(
            self.timeline_events, key=lambda x: x["timestamp"], reverse=True
        )

        for event in sorted_events[-20:]:  # Show last 20 events
            event_widget = self.create_timeline_event_widget(event)
            self.timeline_layout.addWidget(event_widget)

        # Add stretch at the end
        self.timeline_layout.addStretch()

    def create_timeline_event_widget(self, event: Dict) -> QWidget:
        """Create widget for timeline event"""
        if not QT_AVAILABLE:
            return QWidget()

        widget = QFrame()
        widget.setFrameStyle(QFrame.StyledPanel)
        widget.setMaximumHeight(60)

        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 5, 10, 5)

        # Event type indicator
        type_label = QLabel("●")
        type_colors = {
            "start": "#4CAF50",
            "phase": "#2196F3",
            "milestone": "#FF9800",
            "complete": "#4CAF50",
            "error": "#F44336",
            "info": "#607D8B",
        }
        color = type_colors.get(event["type"], "#607D8B")
        type_label.setStyleSheet(f"color: {color}; font-size: 16px;")

        # Event details
        details_layout = QVBoxLayout()

        description_label = QLabel(event["description"])
        description_label.setStyleSheet("font-weight: bold;")

        time_label = QLabel(event["datetime"].strftime("%H:%M:%S"))
        time_label.setStyleSheet("color: gray; font-size: 11px;")

        details_layout.addWidget(description_label)
        details_layout.addWidget(time_label)

        layout.addWidget(type_label)
        layout.addLayout(details_layout)
        layout.addStretch()

        return widget


class VMAnalysisResultsViewer(QWidget):
    """Main results viewer with tabbed interface"""

    handler_selected = Signal(dict) if QT_AVAILABLE else None
    export_requested = Signal(str) if QT_AVAILABLE else None

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_results = {}
        self.setup_ui()

    def setup_ui(self):
        """Initialize the results viewer UI"""
        if not QT_AVAILABLE:
            return

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header with controls
        header = self.create_header()
        layout.addWidget(header)

        # Main content tabs
        self.tabs = QTabWidget()

        # Handlers tab
        self.handlers_tab = self.create_handlers_tab()
        self.tabs.addTab(self.handlers_tab, "VM Handlers")

        # Patterns tab
        self.patterns_tab = PatternMatchViewer()
        self.tabs.addTab(self.patterns_tab, "Pattern Matches")

        # Confidence tab
        self.confidence_tab = ConfidenceVisualizationWidget()
        self.tabs.addTab(self.confidence_tab, "Confidence Analysis")

        # Timeline tab
        self.timeline_tab = AnalysisTimelineWidget()
        self.tabs.addTab(self.timeline_tab, "Analysis Timeline")

        layout.addWidget(self.tabs)

    def create_header(self) -> QWidget:
        """Create results viewer header"""
        if not QT_AVAILABLE:
            return QWidget()

        header = QFrame()
        header.setFrameStyle(QFrame.StyledPanel)
        layout = QHBoxLayout(header)

        # Title
        self.title_label = QLabel("Analysis Results")
        self.title_label.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #1976D2;"
        )

        # Summary stats
        self.stats_label = QLabel("No results available")
        self.stats_label.setStyleSheet("color: gray;")

        # Export button
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)

        layout.addWidget(self.title_label)
        layout.addWidget(self.stats_label)
        layout.addStretch()
        layout.addWidget(self.export_button)

        return header

    def create_handlers_tab(self) -> QWidget:
        """Create VM handlers tab"""
        if not QT_AVAILABLE:
            return QWidget()

        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Handler table
        self.handler_model = HandlerTableModel()
        self.handler_table = QTableWidget()
        self.setup_handler_table()

        layout.addWidget(self.handler_table)

        return widget

    def setup_handler_table(self):
        """Setup handler table widget"""
        if not hasattr(self, "handler_table"):
            return

        headers = ["Address", "Name", "Confidence", "Type", "Patterns", "MLIL Ops"]
        self.handler_table.setColumnCount(len(headers))
        self.handler_table.setHorizontalHeaderLabels(headers)

        # Configure table
        self.handler_table.setAlternatingRowColors(True)
        self.handler_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.handler_table.setSortingEnabled(True)

        # Auto-resize columns
        header = self.handler_table.horizontalHeader()
        header.setStretchLastSection(True)
        for i in range(len(headers) - 1):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)

        # Connect selection
        self.handler_table.itemSelectionChanged.connect(self.on_handler_table_selection)

    def update_results(self, results: Dict):
        """Update all result displays"""
        self.current_results = results

        handlers = results.get("handlers", [])

        # Update handler table
        self.update_handler_table(handlers)

        # Update pattern matches
        if hasattr(self, "patterns_tab"):
            self.patterns_tab.update_patterns(handlers)

        # Update confidence analysis
        if hasattr(self, "confidence_tab"):
            self.confidence_tab.update_confidence_data(handlers)

        # Update timeline
        self.update_timeline(results)

        # Update header
        self.update_header_stats(results)

        # Enable export
        if hasattr(self, "export_button"):
            self.export_button.setEnabled(True)

    def update_handler_table(self, handlers: List[Dict]):
        """Update handler table display"""
        if not hasattr(self, "handler_table"):
            return

        self.handler_table.setRowCount(len(handlers))

        for row, handler in enumerate(handlers):
            # Address
            addr_item = QTableWidgetItem(f"0x{handler.get('address', 0):x}")
            self.handler_table.setItem(row, 0, addr_item)

            # Name
            name = handler.get("name", f"Handler_{handler.get('address', 0):x}")
            name_item = QTableWidgetItem(name)
            self.handler_table.setItem(row, 1, name_item)

            # Confidence
            confidence = handler.get("confidence", 0.0)
            conf_item = QTableWidgetItem(f"{confidence:.1%}")
            # Color code confidence
            if confidence >= 0.8:
                conf_item.setBackground(QColor("#C8E6C9"))
            elif confidence >= 0.6:
                conf_item.setBackground(QColor("#FFF9C4"))
            else:
                conf_item.setBackground(QColor("#FFCDD2"))
            self.handler_table.setItem(row, 2, conf_item)

            # Type
            handler_type = handler.get("handler_type", "Unknown")
            type_item = QTableWidgetItem(handler_type)
            self.handler_table.setItem(row, 3, type_item)

            # Patterns
            patterns = handler.get("pattern_matches", [])
            pattern_item = QTableWidgetItem(f"{len(patterns)} matches")
            self.handler_table.setItem(row, 4, pattern_item)

            # MLIL Operations
            ops = handler.get("mlil_operations", [])
            ops_text = ", ".join(ops[:3]) + ("..." if len(ops) > 3 else "")
            ops_item = QTableWidgetItem(ops_text)
            self.handler_table.setItem(row, 5, ops_item)

            # Store handler data
            addr_item.setData(Qt.UserRole, handler)

    def update_timeline(self, results: Dict):
        """Update analysis timeline"""
        if not hasattr(self, "timeline_tab"):
            return

        # Add completion event
        handlers_count = len(results.get("handlers", []))
        analysis_time = results.get("analysis_time", 0)

        self.timeline_tab.add_timeline_event(
            "complete",
            f"Analysis completed: {handlers_count} handlers found in {analysis_time:.2f}s",
        )

    def update_header_stats(self, results: Dict):
        """Update header statistics"""
        if not hasattr(self, "stats_label"):
            return

        handlers = results.get("handlers", [])
        confidence = results.get("confidence_score", 0.0)
        analysis_time = results.get("analysis_time", 0.0)

        stats_text = f"{len(handlers)} handlers | {confidence:.1%} confidence | {analysis_time:.2f}s"
        self.stats_label.setText(stats_text)

    def on_handler_table_selection(self):
        """Handle handler table selection"""
        if not hasattr(self, "handler_table"):
            return

        current_row = self.handler_table.currentRow()
        if current_row >= 0:
            addr_item = self.handler_table.item(current_row, 0)
            if addr_item:
                handler_data = addr_item.data(Qt.UserRole)
                if handler_data and self.handler_selected:
                    self.handler_selected.emit(handler_data)

    def export_results(self):
        """Export analysis results"""
        if self.export_requested:
            self.export_requested.emit("json")  # Default to JSON export
