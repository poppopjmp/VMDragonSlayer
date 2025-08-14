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

from .dashboard import Dashboard, DashboardConfig
from .widgets import (
    WidgetManager, BaseWidget, MetricWidget, ChartWidget, TableWidget,
    LogWidget, ProgressWidget, AlertWidget, SystemInfoWidget, WidgetConfig,
    create_widget_manager, create_metric_widget, create_chart_widget, create_table_widget
)
from .charts import (
    ChartGenerator, AnalyticsCharts, ChartConfig,
    create_chart_generator, create_analytics_charts, create_chart_config
)
from .interface import (
    UIInterface, ComponentBase, ComponentState,
    create_interface
)

__all__ = [
    # Core components
    'Dashboard',
    'DashboardConfig',
    
    # Widget system
    'WidgetManager',
    'BaseWidget',
    'MetricWidget',
    'ChartWidget',
    'TableWidget',
    'LogWidget',
    'ProgressWidget',
    'AlertWidget',
    'SystemInfoWidget',
    'WidgetConfig',
    
    # Widget utilities
    'create_widget_manager',
    'create_metric_widget',
    'create_chart_widget',
    'create_table_widget',
    
    # Chart system
    'ChartGenerator',
    'AnalyticsCharts',
    'ChartConfig',
    
    # Chart utilities
    'create_chart_generator',
    'create_analytics_charts',
    'create_chart_config',
    
    # Interface utilities
    'UIInterface',
    'ComponentBase',
    'ComponentState',
    'create_interface'
]

# Version and compatibility info
__version__ = '1.0.0'
__author__ = 'VMDragonSlayer Team'
__license__ = 'MIT'

def get_ui_info():
    """Get UI module information"""
    return {
        'module': 'vmdragonslayer.ui',
        'version': __version__,
        'components': [
            'Dashboard - Main web dashboard',
            'WidgetManager - UI widget system',
            'ChartGenerator - Data visualization',
            'UIInterface - Core interface classes'
        ],
        'features': [
            'Real-time web dashboard',
            'Interactive data visualization',
            'Responsive design',
            'Drag-and-drop widgets',
            'Export capabilities',
            'Multi-theme support',
            'Accessibility compliance',
            'Mobile support'
        ]
    }
