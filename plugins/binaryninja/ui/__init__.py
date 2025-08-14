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
    "VMDragonSlayerDashboard",
    "RealTimeStatusMonitor",
    "VMAnalysisResultsViewer",
    "PatternMatchViewer",
    "VMStructureExplorer",
    "PatternMatchBrowser",
    "ConfigurationEditor",
]
