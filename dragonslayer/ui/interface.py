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
UI Interface
============

Core interface classes for VMDragonSlayer UI components.
Provides base classes and utilities for building user interfaces.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ComponentState:
    """State management for UI components."""

    data: Dict[str, Any]
    props: Dict[str, Any]
    is_loading: bool = False
    error_message: Optional[str] = None
    last_updated: Optional[str] = None


class ComponentBase(ABC):
    """Base class for UI components."""

    def __init__(self, props: Optional[Dict[str, Any]] = None):
        self.props = props or {}
        self.state = ComponentState(data={}, props=self.props)
        self.children = []
        self.event_handlers = {}

    @abstractmethod
    def render(self) -> Dict[str, Any]:
        """Render the component."""
        pass

    def set_state(self, new_state: Dict[str, Any]):
        """Update component state."""
        self.state.data.update(new_state)
        self.state.last_updated = str(time.time())

    def get_state(self) -> Dict[str, Any]:
        """Get current component state."""
        return self.state.data.copy()

    def add_event_handler(self, event: str, handler: callable):
        """Add event handler."""
        self.event_handlers[event] = handler

    def trigger_event(self, event: str, *args, **kwargs):
        """Trigger event handler."""
        if event in self.event_handlers:
            return self.event_handlers[event](*args, **kwargs)


class UIInterface:
    """
    Core UI interface for VMDragonSlayer.

    Provides common interface patterns and utilities
    for building consistent user interfaces.
    """

    def __init__(self, theme: str = "default"):
        self.theme = theme
        self.components = {}
        self.layouts = {}

        # Initialize theme settings
        self.theme_config = self._get_theme_config(theme)

    def _get_theme_config(self, theme: str) -> Dict[str, Any]:
        """Get theme configuration."""
        themes = {
            "default": {
                "primary_color": "#007bff",
                "secondary_color": "#6c757d",
                "success_color": "#28a745",
                "danger_color": "#dc3545",
                "warning_color": "#ffc107",
                "info_color": "#17a2b8",
                "light_color": "#f8f9fa",
                "dark_color": "#343a40",
                "font_family": "Arial, sans-serif",
                "font_size": "14px",
            },
            "dark": {
                "primary_color": "#0d6efd",
                "secondary_color": "#495057",
                "success_color": "#198754",
                "danger_color": "#dc3545",
                "warning_color": "#fd7e14",
                "info_color": "#0dcaf0",
                "light_color": "#212529",
                "dark_color": "#f8f9fa",
                "font_family": "Arial, sans-serif",
                "font_size": "14px",
            },
        }

        return themes.get(theme, themes["default"])

    def register_component(self, name: str, component_class: type):
        """Register a UI component."""
        self.components[name] = component_class

    def create_component(self, name: str, props: Optional[Dict[str, Any]] = None):
        """Create a component instance."""
        if name not in self.components:
            raise ValueError(f"Component '{name}' not registered")

        return self.components[name](props)

    def create_layout(self, layout_type: str, children: List[Any]) -> Dict[str, Any]:
        """Create a layout container."""
        layouts = {
            "container": self._create_container_layout,
            "row": self._create_row_layout,
            "column": self._create_column_layout,
            "grid": self._create_grid_layout,
            "sidebar": self._create_sidebar_layout,
        }

        if layout_type not in layouts:
            raise ValueError(f"Layout type '{layout_type}' not supported")

        return layouts[layout_type](children)

    def _create_container_layout(self, children: List[Any]) -> Dict[str, Any]:
        """Create container layout."""
        return {"type": "div", "className": "container-fluid", "children": children}

    def _create_row_layout(self, children: List[Any]) -> Dict[str, Any]:
        """Create row layout."""
        return {"type": "div", "className": "row", "children": children}

    def _create_column_layout(self, children: List[Any]) -> Dict[str, Any]:
        """Create column layout."""
        return {"type": "div", "className": "col", "children": children}

    def _create_grid_layout(self, children: List[Any]) -> Dict[str, Any]:
        """Create grid layout."""
        return {
            "type": "div",
            "className": "grid-container",
            "style": {
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fit, minmax(300px, 1fr))",
                "gap": "1rem",
            },
            "children": children,
        }

    def _create_sidebar_layout(self, children: List[Any]) -> Dict[str, Any]:
        """Create sidebar layout."""
        return {
            "type": "div",
            "className": "sidebar-container d-flex",
            "children": [
                {
                    "type": "div",
                    "className": "sidebar",
                    "style": {"width": "250px", "minHeight": "100vh"},
                    "children": children[:1] if children else [],
                },
                {
                    "type": "div",
                    "className": "main-content flex-grow-1",
                    "children": children[1:] if len(children) > 1 else [],
                },
            ],
        }

    def create_button(
        self,
        text: str,
        onClick: Optional[callable] = None,
        variant: str = "primary",
        size: str = "medium",
    ) -> Dict[str, Any]:
        """Create button component."""
        return {
            "type": "button",
            "className": f"btn btn-{variant} btn-{size}",
            "onClick": onClick,
            "children": text,
        }

    def create_card(
        self, title: str, content: Any, actions: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """Create card component."""
        card_content = [
            {"type": "div", "className": "card-header", "children": title},
            {"type": "div", "className": "card-body", "children": content},
        ]

        if actions:
            card_content.append(
                {"type": "div", "className": "card-footer", "children": actions}
            )

        return {"type": "div", "className": "card", "children": card_content}

    def create_alert(
        self, message: str, alert_type: str = "info", dismissible: bool = False
    ) -> Dict[str, Any]:
        """Create alert component."""
        classes = ["alert", f"alert-{alert_type}"]
        if dismissible:
            classes.append("alert-dismissible")

        children = [message]
        if dismissible:
            children.append(
                {
                    "type": "button",
                    "className": "btn-close",
                    "attributes": {"data-bs-dismiss": "alert"},
                }
            )

        return {"type": "div", "className": " ".join(classes), "children": children}

    def create_progress_bar(
        self,
        value: float,
        max_value: float = 100,
        show_label: bool = True,
        variant: str = "primary",
    ) -> Dict[str, Any]:
        """Create progress bar component."""
        percentage = (value / max_value) * 100

        children = []
        if show_label:
            children.append(f"{percentage:.1f}%")

        return {
            "type": "div",
            "className": "progress",
            "children": [
                {
                    "type": "div",
                    "className": f"progress-bar bg-{variant}",
                    "style": {"width": f"{percentage}%"},
                    "children": children,
                }
            ],
        }

    def create_spinner(
        self, size: str = "medium", variant: str = "primary"
    ) -> Dict[str, Any]:
        """Create loading spinner."""
        size_class = "spinner-border-sm" if size == "small" else "spinner-border"

        return {
            "type": "div",
            "className": f"spinner-border text-{variant} {size_class}",
            "attributes": {"role": "status"},
            "children": [
                {
                    "type": "span",
                    "className": "visually-hidden",
                    "children": "Loading...",
                }
            ],
        }

    def create_badge(self, text: str, variant: str = "secondary") -> Dict[str, Any]:
        """Create badge component."""
        return {"type": "span", "className": f"badge bg-{variant}", "children": text}

    def create_table(
        self,
        headers: List[str],
        rows: List[List[Any]],
        striped: bool = True,
        hover: bool = True,
    ) -> Dict[str, Any]:
        """Create table component."""
        classes = ["table"]
        if striped:
            classes.append("table-striped")
        if hover:
            classes.append("table-hover")

        header_cells = [{"type": "th", "children": header} for header in headers]

        body_rows = []
        for row in rows:
            row_cells = [{"type": "td", "children": str(cell)} for cell in row]
            body_rows.append({"type": "tr", "children": row_cells})

        return {
            "type": "table",
            "className": " ".join(classes),
            "children": [
                {
                    "type": "thead",
                    "children": [{"type": "tr", "children": header_cells}],
                },
                {"type": "tbody", "children": body_rows},
            ],
        }

    def get_css_styles(self) -> str:
        """Get CSS styles for the theme."""
        return f"""
        :root {{
            --primary-color: {self.theme_config['primary_color']};
            --secondary-color: {self.theme_config['secondary_color']};
            --success-color: {self.theme_config['success_color']};
            --danger-color: {self.theme_config['danger_color']};
            --warning-color: {self.theme_config['warning_color']};
            --info-color: {self.theme_config['info_color']};
            --light-color: {self.theme_config['light_color']};
            --dark-color: {self.theme_config['dark_color']};
            --font-family: {self.theme_config['font_family']};
            --font-size: {self.theme_config['font_size']};
        }}

        body {{
            font-family: var(--font-family);
            font-size: var(--font-size);
        }}

        .dashboard-widget {{
            margin-bottom: 1rem;
            border-radius: 0.375rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }}

        .widget-grid {{
            display: grid;
            gap: 1rem;
            grid-template-columns: repeat(12, 1fr);
        }}

        .responsive-grid {{
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        }}

        @media (max-width: 768px) {{
            .widget-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        """


# Utility functions
def create_interface(theme: str = "default") -> UIInterface:
    """Create and return a UI interface instance."""
    return UIInterface(theme)


 
