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
UI Widgets
==========

Comprehensive widget system for VMDragonSlayer UI.
Provides interactive components for building dashboards and interfaces.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class WidgetConfig:
    """Configuration for widget components."""

    title: str
    widget_type: str
    size: str = "medium"  # small, medium, large, full
    position: Dict[str, int] = None
    properties: Dict[str, Any] = None
    data_source: Optional[str] = None
    refresh_interval: int = 30  # seconds
    is_resizable: bool = True
    is_draggable: bool = True


class BaseWidget(ABC):
    """Base class for all dashboard widgets."""

    def __init__(self, config: WidgetConfig):
        self.config = config
        self.data = {}
        self.last_updated = None
        self.error_state = None
        self.is_loading = False

    @abstractmethod
    def render(self) -> Dict[str, Any]:
        """Render the widget component."""
        pass

    @abstractmethod
    def update_data(self, data: Any) -> None:
        """Update widget data."""
        pass

    def get_layout_style(self) -> Dict[str, Any]:
        """Get layout styling based on widget size."""
        size_styles = {
            "small": {"width": "300px", "height": "200px"},
            "medium": {"width": "400px", "height": "300px"},
            "large": {"width": "600px", "height": "400px"},
            "full": {"width": "100%", "height": "500px"},
        }

        base_style = {
            "border": "1px solid #ddd",
            "borderRadius": "8px",
            "padding": "15px",
            "margin": "10px",
            "backgroundColor": "#fff",
            "boxShadow": "0 2px 4px rgba(0,0,0,0.1)",
        }

        size_style = size_styles.get(self.config.size, size_styles["medium"])
        base_style.update(size_style)

        if self.config.position:
            base_style.update(
                {
                    "position": "absolute",
                    "left": f"{self.config.position.get('x', 0)}px",
                    "top": f"{self.config.position.get('y', 0)}px",
                }
            )

        return base_style

    def create_widget_header(self) -> Dict[str, Any]:
        """Create standard widget header."""
        return {
            "type": "div",
            "className": "widget-header d-flex justify-content-between align-items-center",
            "style": {
                "borderBottom": "1px solid #eee",
                "paddingBottom": "10px",
                "marginBottom": "15px",
            },
            "children": [
                {
                    "type": "h5",
                    "className": "widget-title mb-0",
                    "children": self.config.title,
                },
                {
                    "type": "div",
                    "className": "widget-controls",
                    "children": [
                        {
                            "type": "button",
                            "className": "btn btn-sm btn-outline-secondary",
                            "onClick": f'refreshWidget("{id(self)}")',
                            "children": "🔄",
                        }
                    ],
                },
            ],
        }


class MetricWidget(BaseWidget):
    """Widget for displaying single metrics."""

    def render(self) -> Dict[str, Any]:
        value = self.data.get("value", "N/A")
        unit = self.data.get("unit", "")
        trend = self.data.get("trend", 0)

        trend_icon = "📈" if trend > 0 else "📉" if trend < 0 else "➡️"
        trend_color = "#28a745" if trend > 0 else "#dc3545" if trend < 0 else "#6c757d"

        return {
            "type": "div",
            "className": "metric-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "metric-content text-center",
                    "children": [
                        {
                            "type": "div",
                            "className": "metric-value",
                            "style": {
                                "fontSize": "2.5rem",
                                "fontWeight": "bold",
                                "color": "#333",
                            },
                            "children": f"{value} {unit}",
                        },
                        {
                            "type": "div",
                            "className": "metric-trend",
                            "style": {"color": trend_color, "fontSize": "1.2rem"},
                            "children": f"{trend_icon} {trend:+.1f}%",
                        },
                    ],
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()


class ChartWidget(BaseWidget):
    """Widget for displaying charts and graphs."""

    def render(self) -> Dict[str, Any]:
        self.config.properties.get("chart_type", "line")

        return {
            "type": "div",
            "className": "chart-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "chart-container",
                    "id": f"chart-{id(self)}",
                    "style": {"height": "250px", "width": "100%"},
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()
        # Chart data would be processed and sent to frontend for rendering


class TableWidget(BaseWidget):
    """Widget for displaying data tables."""

    def render(self) -> Dict[str, Any]:
        headers = self.data.get("headers", [])
        rows = self.data.get("rows", [])

        return {
            "type": "div",
            "className": "table-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "table-container",
                    "style": {"maxHeight": "300px", "overflowY": "auto"},
                    "children": [
                        {
                            "type": "table",
                            "className": "table table-striped table-hover",
                            "children": [
                                {
                                    "type": "thead",
                                    "children": [
                                        {
                                            "type": "tr",
                                            "children": [
                                                {"type": "th", "children": header}
                                                for header in headers
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tbody",
                                    "children": [
                                        {
                                            "type": "tr",
                                            "children": [
                                                {"type": "td", "children": str(cell)}
                                                for cell in row
                                            ],
                                        }
                                        for row in rows
                                    ],
                                },
                            ],
                        }
                    ],
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()


class LogWidget(BaseWidget):
    """Widget for displaying log entries."""

    def render(self) -> Dict[str, Any]:
        logs = self.data.get("logs", [])
        max_entries = self.config.properties.get("max_entries", 50)

        log_entries = []
        for log in logs[-max_entries:]:
            level = log.get("level", "INFO")
            level_color = {
                "ERROR": "#dc3545",
                "WARNING": "#ffc107",
                "INFO": "#17a2b8",
                "DEBUG": "#6c757d",
            }.get(level, "#333")

            log_entries.append(
                {
                    "type": "div",
                    "className": "log-entry",
                    "style": {
                        "borderLeft": f"3px solid {level_color}",
                        "paddingLeft": "10px",
                        "marginBottom": "5px",
                        "fontSize": "0.9rem",
                    },
                    "children": [
                        {
                            "type": "span",
                            "className": "log-timestamp",
                            "style": {"color": "#6c757d", "marginRight": "10px"},
                            "children": log.get("timestamp", ""),
                        },
                        {
                            "type": "span",
                            "className": f"log-level badge bg-{level.lower()}",
                            "style": {"marginRight": "10px"},
                            "children": level,
                        },
                        {
                            "type": "span",
                            "className": "log-message",
                            "children": log.get("message", ""),
                        },
                    ],
                }
            )

        return {
            "type": "div",
            "className": "log-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "log-container",
                    "style": {
                        "maxHeight": "300px",
                        "overflowY": "auto",
                        "backgroundColor": "#f8f9fa",
                        "padding": "10px",
                        "borderRadius": "4px",
                    },
                    "children": log_entries,
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()


class ProgressWidget(BaseWidget):
    """Widget for displaying progress indicators."""

    def render(self) -> Dict[str, Any]:
        tasks = self.data.get("tasks", [])

        progress_bars = []
        for task in tasks:
            progress = task.get("progress", 0)
            status = task.get("status", "running")

            status_color = {
                "completed": "success",
                "running": "primary",
                "failed": "danger",
                "paused": "warning",
            }.get(status, "secondary")

            progress_bars.append(
                {
                    "type": "div",
                    "className": "progress-item mb-3",
                    "children": [
                        {
                            "type": "div",
                            "className": "d-flex justify-content-between mb-1",
                            "children": [
                                {"type": "span", "children": task.get("name", "Task")},
                                {"type": "span", "children": f"{progress:.1f}%"},
                            ],
                        },
                        {
                            "type": "div",
                            "className": "progress",
                            "children": [
                                {
                                    "type": "div",
                                    "className": f"progress-bar bg-{status_color}",
                                    "style": {"width": f"{progress}%"},
                                    "attributes": {
                                        "role": "progressbar",
                                        "aria-valuenow": progress,
                                        "aria-valuemin": 0,
                                        "aria-valuemax": 100,
                                    },
                                }
                            ],
                        },
                    ],
                }
            )

        return {
            "type": "div",
            "className": "progress-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "progress-content",
                    "children": progress_bars,
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()


class AlertWidget(BaseWidget):
    """Widget for displaying alerts and notifications."""

    def render(self) -> Dict[str, Any]:
        alerts = self.data.get("alerts", [])

        alert_items = []
        for alert in alerts:
            severity = alert.get("severity", "info")
            severity_class = {
                "critical": "danger",
                "warning": "warning",
                "info": "info",
                "success": "success",
            }.get(severity, "secondary")

            alert_items.append(
                {
                    "type": "div",
                    "className": f"alert alert-{severity_class} d-flex align-items-center",
                    "children": [
                        {
                            "type": "div",
                            "className": "alert-icon me-2",
                            "children": {
                                "critical": "🚨",
                                "warning": "⚠️",
                                "info": "ℹ️",
                                "success": "",
                            }.get(severity, "📢"),
                        },
                        {
                            "type": "div",
                            "className": "alert-content",
                            "children": [
                                {
                                    "type": "strong",
                                    "children": alert.get("title", "Alert"),
                                },
                                {"type": "div", "children": alert.get("message", "")},
                                {
                                    "type": "small",
                                    "className": "text-muted",
                                    "children": alert.get("timestamp", ""),
                                },
                            ],
                        },
                    ],
                }
            )

        return {
            "type": "div",
            "className": "alert-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "alert-container",
                    "style": {"maxHeight": "300px", "overflowY": "auto"},
                    "children": alert_items,
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()


class SystemInfoWidget(BaseWidget):
    """Widget for displaying system information."""

    def render(self) -> Dict[str, Any]:
        info = self.data.get("system_info", {})

        info_items = []
        for key, value in info.items():
            info_items.append(
                {
                    "type": "div",
                    "className": "row mb-2",
                    "children": [
                        {
                            "type": "div",
                            "className": "col-6",
                            "children": {
                                "type": "strong",
                                "children": key.replace("_", " ").title(),
                            },
                        },
                        {"type": "div", "className": "col-6", "children": str(value)},
                    ],
                }
            )

        return {
            "type": "div",
            "className": "system-info-widget",
            "style": self.get_layout_style(),
            "children": [
                self.create_widget_header(),
                {
                    "type": "div",
                    "className": "system-info-content",
                    "children": info_items,
                },
            ],
        }

    def update_data(self, data: Any) -> None:
        self.data = data
        self.last_updated = time.time()


class WidgetManager:
    """
    Manager for dashboard widgets.

    Handles widget creation, layout, and data updates.
    """

    def __init__(self):
        self.widgets = {}
        self.widget_types = {
            "metric": MetricWidget,
            "chart": ChartWidget,
            "table": TableWidget,
            "log": LogWidget,
            "progress": ProgressWidget,
            "alert": AlertWidget,
            "system_info": SystemInfoWidget,
        }
        self.layouts = {}

    def register_widget_type(self, name: str, widget_class: type):
        """Register a new widget type."""
        self.widget_types[name] = widget_class

    def create_widget(self, widget_id: str, config: WidgetConfig) -> BaseWidget:
        """Create a new widget instance."""
        if config.widget_type not in self.widget_types:
            raise ValueError(f"Unknown widget type: {config.widget_type}")

        widget_class = self.widget_types[config.widget_type]
        widget = widget_class(config)
        self.widgets[widget_id] = widget

        return widget

    def remove_widget(self, widget_id: str):
        """Remove a widget."""
        if widget_id in self.widgets:
            del self.widgets[widget_id]

    def get_widget(self, widget_id: str) -> Optional[BaseWidget]:
        """Get a widget by ID."""
        return self.widgets.get(widget_id)

    def update_widget_data(self, widget_id: str, data: Any):
        """Update data for a specific widget."""
        widget = self.widgets.get(widget_id)
        if widget:
            widget.update_data(data)

    def render_layout(self, layout_name: str) -> List[Dict[str, Any]]:
        """Render all widgets in a layout."""
        layout = self.layouts.get(layout_name, [])
        rendered_widgets = []

        for widget_id in layout:
            widget = self.widgets.get(widget_id)
            if widget:
                rendered_widgets.append(widget.render())

        return rendered_widgets

    def create_dashboard_layout(
        self, widget_ids: List[str], layout_type: str = "grid"
    ) -> Dict[str, Any]:
        """Create a dashboard layout with specified widgets."""
        rendered_widgets = []

        for widget_id in widget_ids:
            widget = self.widgets.get(widget_id)
            if widget:
                rendered_widgets.append(widget.render())

        if layout_type == "grid":
            return {
                "type": "div",
                "className": "dashboard-grid",
                "style": {
                    "display": "grid",
                    "gridTemplateColumns": "repeat(auto-fit, minmax(400px, 1fr))",
                    "gap": "1rem",
                    "padding": "1rem",
                },
                "children": rendered_widgets,
            }
        elif layout_type == "flex":
            return {
                "type": "div",
                "className": "dashboard-flex",
                "style": {
                    "display": "flex",
                    "flexWrap": "wrap",
                    "gap": "1rem",
                    "padding": "1rem",
                },
                "children": rendered_widgets,
            }
        else:
            return {
                "type": "div",
                "className": "dashboard-container",
                "children": rendered_widgets,
            }

    def export_layout(self, layout_name: str) -> str:
        """Export layout configuration as JSON."""
        layout_config = {"name": layout_name, "widgets": []}

        layout_widgets = self.layouts.get(layout_name, [])
        for widget_id in layout_widgets:
            widget = self.widgets.get(widget_id)
            if widget:
                layout_config["widgets"].append(
                    {
                        "id": widget_id,
                        "config": {
                            "title": widget.config.title,
                            "widget_type": widget.config.widget_type,
                            "size": widget.config.size,
                            "position": widget.config.position,
                            "properties": widget.config.properties,
                        },
                    }
                )

        return json.dumps(layout_config, indent=2)

    def import_layout(self, layout_json: str) -> str:
        """Import layout configuration from JSON."""
        layout_config = json.loads(layout_json)
        layout_name = layout_config["name"]

        widget_ids = []
        for widget_data in layout_config["widgets"]:
            widget_id = widget_data["id"]
            config = WidgetConfig(**widget_data["config"])

            self.create_widget(widget_id, config)
            widget_ids.append(widget_id)

        self.layouts[layout_name] = widget_ids
        return layout_name


# Utility functions
def create_widget_manager() -> WidgetManager:
    """Create and return a widget manager instance."""
    return WidgetManager()


def create_metric_widget(
    title: str, value: Any, unit: str = "", trend: float = 0
) -> WidgetConfig:
    """Create configuration for a metric widget."""
    return WidgetConfig(
        title=title,
        widget_type="metric",
        properties={"value": value, "unit": unit, "trend": trend},
    )


def create_chart_widget(title: str, chart_type: str = "line") -> WidgetConfig:
    """Create configuration for a chart widget."""
    return WidgetConfig(
        title=title, widget_type="chart", properties={"chart_type": chart_type}
    )


def create_table_widget(
    title: str, headers: List[str], rows: List[List[Any]]
) -> WidgetConfig:
    """Create configuration for a table widget."""
    return WidgetConfig(
        title=title, widget_type="table", properties={"headers": headers, "rows": rows}
    )
