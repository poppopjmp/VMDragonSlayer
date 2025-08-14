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
VMDragonSlayer UI Module
========================

Unified user interface components for VMDragonSlayer malware analysis platform.
Provides web-based dashboards, visualization components, and API interfaces.

Module Components:
- dashboard: Main dashboard implementation
- widgets: Reusable UI widgets
- charts: Data visualization components
- interface: Core UI interface classes
"""

from .charts import (
    AnalyticsCharts,
    ChartConfig,
    ChartGenerator,
    create_analytics_charts,
    create_chart_config,
    create_chart_generator,
)
from .dashboard import Dashboard, DashboardConfig
from .interface import ComponentBase, ComponentState, UIInterface, create_interface
from .widgets import (
    AlertWidget,
    BaseWidget,
    ChartWidget,
    LogWidget,
    MetricWidget,
    ProgressWidget,
    SystemInfoWidget,
    TableWidget,
    WidgetConfig,
    WidgetManager,
    create_chart_widget,
    create_metric_widget,
    create_table_widget,
    create_widget_manager,
)

__all__ = [
    # Core components
    "Dashboard",
    "DashboardConfig",
    # Widget system
    "WidgetManager",
    "BaseWidget",
    "MetricWidget",
    "ChartWidget",
    "TableWidget",
    "LogWidget",
    "ProgressWidget",
    "AlertWidget",
    "SystemInfoWidget",
    "WidgetConfig",
    # Widget utilities
    "create_widget_manager",
    "create_metric_widget",
    "create_chart_widget",
    "create_table_widget",
    # Chart system
    "ChartGenerator",
    "AnalyticsCharts",
    "ChartConfig",
    # Chart utilities
    "create_chart_generator",
    "create_analytics_charts",
    "create_chart_config",
    # Interface utilities
    "UIInterface",
    "ComponentBase",
    "ComponentState",
    "create_interface",
]

# Version and compatibility info
__version__ = "1.0.0"
__author__ = "VMDragonSlayer Team"
__license__ = "MIT"


def get_ui_info():
    """Get UI module information"""
    return {
        "module": "vmdragonslayer.ui",
        "version": __version__,
        "components": [
            "Dashboard - Main web dashboard",
            "WidgetManager - UI widget system",
            "ChartGenerator - Data visualization",
            "UIInterface - Core interface classes",
        ],
        "features": [
            "Real-time web dashboard",
            "Interactive data visualization",
            "Responsive design",
            "Drag-and-drop widgets",
            "Export capabilities",
            "Multi-theme support",
            "Accessibility compliance",
            "Mobile support",
        ],
    }
