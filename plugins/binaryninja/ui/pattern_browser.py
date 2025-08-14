#!/usr/bin/env python3
"""
Binary Ninja Phase 2: UI/UX Enhancement - Pattern Match Browser
Interactive browser for pattern matching results and confidence scores.
"""

import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

try:
    from PySide2.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
        QLabel, QGroupBox, QPushButton, QComboBox, QSplitter, QTextEdit,
        QHeaderView, QAbstractItemView, QFrame, QProgressBar, QCheckBox,
        QSpinBox, QSlider, QLineEdit
    )
    from PySide2.QtCore import Qt, Signal, QSortFilterProxyModel, QTimer
    from PySide2.QtGui import QFont, QColor
    QT_AVAILABLE = True
except ImportError:
    # Mock classes for testing
    class QWidget: pass
    class Signal: pass
    QT_AVAILABLE = False


class PatternMatchModel:
    """Data model for pattern matches"""
    
    def __init__(self):
        self.matches = []
        self.filtered_matches = []
        self.confidence_threshold = 0.5
        self.pattern_types = set()
        
    def load_matches(self, pattern_data: List[Dict[str, Any]]):
        """Load pattern match data"""
        self.matches = pattern_data
        self.pattern_types = set(match.get('pattern_type', 'Unknown') for match in pattern_data)
        self.apply_filters()
        
    def apply_filters(self, confidence_threshold: float = None, pattern_type: str = None):
        """Apply filters to the pattern matches"""
        if confidence_threshold is not None:
            self.confidence_threshold = confidence_threshold
            
        self.filtered_matches = []
        for match in self.matches:
            # Confidence filter
            if match.get('confidence', 0.0) < self.confidence_threshold:
                continue
                
            # Pattern type filter
            if pattern_type and pattern_type != "All" and match.get('pattern_type') != pattern_type:
                continue
                
            self.filtered_matches.append(match)
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about pattern matches"""
        if not self.matches:
            return {}
            
        stats = {
            'total_matches': len(self.matches),
            'filtered_matches': len(self.filtered_matches),
            'pattern_types': len(self.pattern_types),
            'average_confidence': sum(m.get('confidence', 0.0) for m in self.matches) / len(self.matches),
            'high_confidence_matches': len([m for m in self.matches if m.get('confidence', 0.0) > 0.8])
        }
        
        # Per-type statistics
        type_stats = defaultdict(list)
        for match in self.matches:
            pattern_type = match.get('pattern_type', 'Unknown')
            type_stats[pattern_type].append(match.get('confidence', 0.0))
            
        stats['type_statistics'] = {}
        for pattern_type, confidences in type_stats.items():
            stats['type_statistics'][pattern_type] = {
                'count': len(confidences),
                'average_confidence': sum(confidences) / len(confidences),
                'max_confidence': max(confidences),
                'min_confidence': min(confidences)
            }
            
        return stats


class PatternMatchTable(QTableWidget):
    """Table widget for displaying pattern matches"""
    
    pattern_selected = Signal(object)
    navigate_to_address = Signal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pattern_model = PatternMatchModel()
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the table"""
        if not QT_AVAILABLE:
            return
            
        # Configure table
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            'Pattern Name', 'Type', 'Confidence', 'Address', 'Size', 'Description'
        ])
        
        # Configure selection and behavior
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        
        # Configure columns
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        
        # Connect signals
        self.itemSelectionChanged.connect(self.on_selection_changed)
        self.itemDoubleClicked.connect(self.on_item_double_clicked)
        
    def load_pattern_matches(self, pattern_data: List[Dict[str, Any]]):
        """Load pattern match data into the table"""
        self.pattern_model.load_matches(pattern_data)
        self.refresh_table()
        
    def refresh_table(self):
        """Refresh the table display"""
        matches = self.pattern_model.filtered_matches
        self.setRowCount(len(matches))
        
        for row, match in enumerate(matches):
            # Pattern name
            name_item = QTableWidgetItem(match.get('pattern_name', 'Unknown'))
            name_item.setData(Qt.UserRole, match)
            self.setItem(row, 0, name_item)
            
            # Pattern type
            type_item = QTableWidgetItem(match.get('pattern_type', 'Unknown'))
            self.setItem(row, 1, type_item)
            
            # Confidence
            confidence = match.get('confidence', 0.0)
            confidence_item = QTableWidgetItem(f"{confidence*100:.1f}%")
            confidence_item.setData(Qt.UserRole, confidence)
            
            # Color code by confidence
            if confidence >= 0.8:
                confidence_item.setBackground(QColor(144, 238, 144))  # Light green
            elif confidence >= 0.6:
                confidence_item.setBackground(QColor(255, 255, 144))  # Light yellow
            else:
                confidence_item.setBackground(QColor(255, 182, 193))  # Light red
                
            self.setItem(row, 2, confidence_item)
            
            # Address
            address = match.get('address', 0)
            address_item = QTableWidgetItem(f"0x{address:08x}")
            address_item.setData(Qt.UserRole, address)
            self.setItem(row, 3, address_item)
            
            # Size
            size = match.get('size', 0)
            self.setItem(row, 4, QTableWidgetItem(f"{size} bytes"))
            
            # Description
            description = match.get('description', '')
            self.setItem(row, 5, QTableWidgetItem(description))
            
    def apply_filters(self, confidence_threshold: float, pattern_type: str):
        """Apply filters and refresh the table"""
        self.pattern_model.apply_filters(confidence_threshold, pattern_type)
        self.refresh_table()
        
    def on_selection_changed(self):
        """Handle selection changes"""
        selected_items = self.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            name_item = self.item(row, 0)
            if name_item:
                pattern_data = name_item.data(Qt.UserRole)
                if pattern_data:
                    self.pattern_selected.emit(pattern_data)
                    
    def on_item_double_clicked(self, item: QTableWidgetItem):
        """Handle double-click events"""
        if item.column() == 3:  # Address column
            address = item.data(Qt.UserRole)
            if address:
                self.navigate_to_address.emit(address)


class PatternDetailsPanel(QWidget):
    """Panel for displaying detailed pattern information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.current_pattern = None
        
    def setup_ui(self):
        """Initialize the details panel"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        
        # Pattern overview
        overview_group = QGroupBox("Pattern Details")
        overview_layout = QVBoxLayout(overview_group)
        
        self.name_label = QLabel("No pattern selected")
        self.name_label.setFont(QFont("", 12, QFont.Bold))
        overview_layout.addWidget(self.name_label)
        
        self.type_label = QLabel("")
        overview_layout.addWidget(self.type_label)
        
        self.confidence_label = QLabel("")
        overview_layout.addWidget(self.confidence_label)
        
        self.address_label = QLabel("")
        overview_layout.addWidget(self.address_label)
        
        layout.addWidget(overview_group)
        
        # Pattern description
        desc_group = QGroupBox("Description")
        desc_layout = QVBoxLayout(desc_group)
        
        self.description_text = QTextEdit()
        self.description_text.setMaximumHeight(100)
        self.description_text.setReadOnly(True)
        desc_layout.addWidget(self.description_text)
        
        layout.addWidget(desc_group)
        
        # Pattern signature
        sig_group = QGroupBox("Pattern Signature")
        sig_layout = QVBoxLayout(sig_group)
        
        self.signature_text = QTextEdit()
        self.signature_text.setMaximumHeight(150)
        self.signature_text.setReadOnly(True)
        self.signature_text.setFont(QFont("Courier", 9))
        sig_layout.addWidget(self.signature_text)
        
        layout.addWidget(sig_group)
        
        # Stretch
        layout.addStretch()
        
    def update_pattern(self, pattern_data: Dict[str, Any]):
        """Update the panel with pattern data"""
        self.current_pattern = pattern_data
        
        if not pattern_data:
            self.name_label.setText("No pattern selected")
            self.type_label.setText("")
            self.confidence_label.setText("")
            self.address_label.setText("")
            self.description_text.clear()
            self.signature_text.clear()
            return
            
        # Update overview
        self.name_label.setText(pattern_data.get('pattern_name', 'Unknown Pattern'))
        self.type_label.setText(f"Type: {pattern_data.get('pattern_type', 'Unknown')}")
        
        confidence = pattern_data.get('confidence', 0.0)
        self.confidence_label.setText(f"Confidence: {confidence*100:.1f}%")
        
        address = pattern_data.get('address', 0)
        self.address_label.setText(f"Address: 0x{address:08x}")
        
        # Update description
        description = pattern_data.get('description', 'No description available')
        self.description_text.setPlainText(description)
        
        # Update signature
        signature = pattern_data.get('signature', 'No signature available')
        self.signature_text.setPlainText(signature)


class PatternStatisticsPanel(QWidget):
    """Panel for displaying pattern match statistics"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the statistics panel"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        
        # Overall statistics
        stats_group = QGroupBox("Match Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.total_matches_label = QLabel("Total Matches: 0")
        stats_layout.addWidget(self.total_matches_label)
        
        self.filtered_matches_label = QLabel("Filtered Matches: 0")
        stats_layout.addWidget(self.filtered_matches_label)
        
        self.avg_confidence_label = QLabel("Average Confidence: 0.0%")
        stats_layout.addWidget(self.avg_confidence_label)
        
        self.high_confidence_label = QLabel("High Confidence (>80%): 0")
        stats_layout.addWidget(self.high_confidence_label)
        
        layout.addWidget(stats_group)
        
        # Type statistics
        type_stats_group = QGroupBox("Pattern Type Statistics")
        type_stats_layout = QVBoxLayout(type_stats_group)
        
        self.type_stats_text = QTextEdit()
        self.type_stats_text.setMaximumHeight(150)
        self.type_stats_text.setReadOnly(True)
        self.type_stats_text.setFont(QFont("Courier", 9))
        type_stats_layout.addWidget(self.type_stats_text)
        
        layout.addWidget(type_stats_group)
        
        # Stretch
        layout.addStretch()
        
    def update_statistics(self, stats: Dict[str, Any]):
        """Update the statistics display"""
        if not stats:
            self.total_matches_label.setText("Total Matches: 0")
            self.filtered_matches_label.setText("Filtered Matches: 0")
            self.avg_confidence_label.setText("Average Confidence: 0.0%")
            self.high_confidence_label.setText("High Confidence (>80%): 0")
            self.type_stats_text.clear()
            return
            
        # Update overall statistics
        self.total_matches_label.setText(f"Total Matches: {stats.get('total_matches', 0)}")
        self.filtered_matches_label.setText(f"Filtered Matches: {stats.get('filtered_matches', 0)}")
        
        avg_conf = stats.get('average_confidence', 0.0)
        self.avg_confidence_label.setText(f"Average Confidence: {avg_conf*100:.1f}%")
        
        high_conf = stats.get('high_confidence_matches', 0)
        self.high_confidence_label.setText(f"High Confidence (>80%): {high_conf}")
        
        # Update type statistics
        type_stats = stats.get('type_statistics', {})
        type_text = ""
        for pattern_type, type_data in type_stats.items():
            type_text += f"{pattern_type}:\n"
            type_text += f"  Count: {type_data['count']}\n"
            type_text += f"  Avg Confidence: {type_data['average_confidence']*100:.1f}%\n"
            type_text += f"  Range: {type_data['min_confidence']*100:.1f}% - {type_data['max_confidence']*100:.1f}%\n\n"
            
        self.type_stats_text.setPlainText(type_text)


class PatternMatchBrowser(QWidget):
    """Main pattern match browser widget"""
    
    navigate_to_address = Signal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.pattern_data = []
        
    def setup_ui(self):
        """Initialize the UI"""
        if not QT_AVAILABLE:
            return
            
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Pattern Match Browser")
        title.setFont(QFont("", 14, QFont.Bold))
        layout.addWidget(title)
        
        # Filter controls
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout(filter_group)
        
        # Confidence threshold
        filter_layout.addWidget(QLabel("Min Confidence:"))
        self.confidence_slider = QSlider(Qt.Horizontal)
        self.confidence_slider.setRange(0, 100)
        self.confidence_slider.setValue(50)
        filter_layout.addWidget(self.confidence_slider)
        
        self.confidence_label = QLabel("50%")
        filter_layout.addWidget(self.confidence_label)
        
        # Pattern type filter
        filter_layout.addWidget(QLabel("Pattern Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItem("All")
        filter_layout.addWidget(self.type_combo)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        filter_layout.addWidget(self.refresh_btn)
        
        filter_layout.addStretch()
        layout.addWidget(filter_group)
        
        # Main content area
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - pattern table and statistics
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Pattern table
        self.pattern_table = PatternMatchTable()
        left_layout.addWidget(self.pattern_table)
        
        # Statistics panel
        self.statistics_panel = PatternStatisticsPanel()
        left_layout.addWidget(self.statistics_panel)
        
        content_splitter.addWidget(left_panel)
        
        # Right panel - pattern details
        self.details_panel = PatternDetailsPanel()
        content_splitter.addWidget(self.details_panel)
        
        # Set splitter proportions
        content_splitter.setSizes([400, 200])
        layout.addWidget(content_splitter)
        
        # Connect signals
        self.confidence_slider.valueChanged.connect(self.on_confidence_changed)
        self.type_combo.currentTextChanged.connect(self.on_type_filter_changed)
        self.refresh_btn.clicked.connect(self.refresh_patterns)
        self.pattern_table.pattern_selected.connect(self.details_panel.update_pattern)
        self.pattern_table.navigate_to_address.connect(self.navigate_to_address)
        
    def load_pattern_matches(self, pattern_data: List[Dict[str, Any]]):
        """Load pattern match data"""
        self.pattern_data = pattern_data
        
        # Update type combo box
        pattern_types = set(match.get('pattern_type', 'Unknown') for match in pattern_data)
        self.type_combo.clear()
        self.type_combo.addItem("All")
        for pattern_type in sorted(pattern_types):
            self.type_combo.addItem(pattern_type)
            
        # Load data into table
        self.pattern_table.load_pattern_matches(pattern_data)
        
        # Update statistics
        stats = self.pattern_table.pattern_model.get_statistics()
        self.statistics_panel.update_statistics(stats)
        
    def on_confidence_changed(self, value: int):
        """Handle confidence threshold changes"""
        confidence = value / 100.0
        self.confidence_label.setText(f"{value}%")
        
        pattern_type = self.type_combo.currentText()
        self.pattern_table.apply_filters(confidence, pattern_type)
        
        # Update statistics
        stats = self.pattern_table.pattern_model.get_statistics()
        self.statistics_panel.update_statistics(stats)
        
    def on_type_filter_changed(self, pattern_type: str):
        """Handle pattern type filter changes"""
        confidence = self.confidence_slider.value() / 100.0
        self.pattern_table.apply_filters(confidence, pattern_type)
        
        # Update statistics
        stats = self.pattern_table.pattern_model.get_statistics()
        self.statistics_panel.update_statistics(stats)
        
    def refresh_patterns(self):
        """Refresh the pattern display"""
        if self.pattern_data:
            self.load_pattern_matches(self.pattern_data)
            
    def get_selected_pattern(self) -> Optional[Dict[str, Any]]:
        """Get the currently selected pattern"""
        return self.details_panel.current_pattern


# Mock implementation for testing
if not QT_AVAILABLE:
    class PatternMatchBrowser:
        def __init__(self, parent=None):
            self.pattern_data = []
            
        def load_pattern_matches(self, pattern_data: List[Dict[str, Any]]):
            self.pattern_data = pattern_data
            logging.info("Pattern Match Browser: Loaded %d pattern matches", len(pattern_data))
            
        def refresh_patterns(self):
            logging.info("Pattern Match Browser: Refreshing patterns")
            
        def get_selected_pattern(self) -> Optional[Dict[str, Any]]:
            return None
