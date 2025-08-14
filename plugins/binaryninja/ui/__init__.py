"""
VMDragonSlayer Binary Ninja UI Components
UI framework for advanced VM analysis in Binary Ninja
"""

from .dashboard import VMDragonSlayerDashboard
from .status_monitor import RealTimeStatusMonitor
from .results_viewer import VMAnalysisResultsViewer, PatternMatchViewer
from .vm_structure_explorer import VMStructureExplorer
from .pattern_browser import PatternMatchBrowser
from .config_editor import ConfigurationEditor

__all__ = [
    'VMDragonSlayerDashboard',
    'RealTimeStatusMonitor',
    'VMAnalysisResultsViewer',
    'PatternMatchViewer',
    'VMStructureExplorer',
    'PatternMatchBrowser',
    'ConfigurationEditor'
]
