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
Dashboard
=========

Unified web dashboard for VMDragonSlayer analysis platform.

Consolidates functionality from:
- Enterprise dashboard components
- Advanced UI interface
- Real-time monitoring
- Interactive analytics
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from ..core.exceptions import UIError, VMDragonSlayerError

logger = logging.getLogger(__name__)

# Handle optional dependencies gracefully
try:
    import dash
    import dash_bootstrap_components as dbc
    from dash import Input, Output, State, callback, dash_table, dcc, html
    from dash.exceptions import PreventUpdate

    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    logger.warning("Dash not available, web dashboard disabled")

try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logger.warning("Plotly not available, visualizations disabled")

try:
    import numpy as np
    import pandas as pd

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logger.warning("Pandas not available, data processing limited")


@dataclass
class DashboardConfig:
    """Configuration for dashboard."""

    title: str = "VMDragonSlayer Analytics"
    host: str = "127.0.0.1"
    port: int = 8050
    debug: bool = False
    auto_refresh: bool = True
    refresh_interval: int = 30  # seconds
    theme: str = "bootstrap"  # bootstrap, material, dark

    # Widget configuration
    default_widgets: List[str] = None
    widget_grid_cols: int = 12
    widget_grid_rows: int = 20

    # Performance settings
    max_data_points: int = 1000
    cache_timeout: int = 300  # seconds

    def __post_init__(self):
        """Set default widgets if not provided."""
        if self.default_widgets is None:
            self.default_widgets = [
                "threat_overview",
                "analysis_queue",
                "detection_trends",
                "system_health",
                "recent_analyses",
            ]


class Dashboard:
    """
    Unified web dashboard for VMDragonSlayer.

    Provides real-time monitoring, analytics visualization,
    and interactive controls for the analysis platform.
    """

    def __init__(self, config: Optional[DashboardConfig] = None):
        self.config = config or DashboardConfig()
        self.app = None
        self.data_manager = None
        self.widget_manager = None
        self.chart_generator = None

        if DASH_AVAILABLE:
            self._initialize_app()
        else:
            logger.error(
                "Dashboard requires Dash - install with: pip install dash dash-bootstrap-components"
            )

    def _initialize_app(self):
        """Initialize Dash application."""
        # Select theme
        theme_map = {
            "bootstrap": dbc.themes.BOOTSTRAP,
            "material": dbc.themes.BOOTSTRAP,  # fallback
            "dark": dbc.themes.SLATE,
        }
        external_stylesheets = [theme_map.get(self.config.theme, dbc.themes.BOOTSTRAP)]

        self.app = dash.Dash(
            __name__,
            external_stylesheets=external_stylesheets,
            title=self.config.title,
            update_title="Loading...",
            suppress_callback_exceptions=True,
        )

        # Setup layout
        self.app.layout = self._create_main_layout()

        # Register callbacks
        self._register_callbacks()

        logger.info(f"Dashboard initialized with theme: {self.config.theme}")

    def _create_main_layout(self):
        """Create main dashboard layout."""
        if not DASH_AVAILABLE:
            return html.Div("Dashboard not available - missing dependencies")

        return dbc.Container(
            [
                # Header
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                html.H1(self.config.title, className="mb-0"),
                                html.P(
                                    "Real-time malware analysis and monitoring",
                                    className="text-muted",
                                ),
                            ],
                            width=8,
                        ),
                        dbc.Col(
                            [
                                dbc.ButtonGroup(
                                    [
                                        dbc.Button(
                                            "Refresh",
                                            id="refresh-btn",
                                            color="primary",
                                            size="sm",
                                        ),
                                        dbc.Button(
                                            "Settings",
                                            id="settings-btn",
                                            color="secondary",
                                            size="sm",
                                        ),
                                        dbc.Button(
                                            "Export",
                                            id="export-btn",
                                            color="info",
                                            size="sm",
                                        ),
                                    ]
                                )
                            ],
                            width=4,
                            className="text-end",
                        ),
                    ],
                    className="mb-4",
                ),
                # Time range selector
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.ButtonGroup(
                                    [
                                        dbc.Button(
                                            "1H",
                                            id="1h-btn",
                                            color="outline-secondary",
                                            size="sm",
                                        ),
                                        dbc.Button(
                                            "24H",
                                            id="24h-btn",
                                            color="outline-secondary",
                                            size="sm",
                                        ),
                                        dbc.Button(
                                            "7D",
                                            id="7d-btn",
                                            color="secondary",
                                            size="sm",
                                        ),
                                        dbc.Button(
                                            "30D",
                                            id="30d-btn",
                                            color="outline-secondary",
                                            size="sm",
                                        ),
                                    ],
                                    className="mb-3",
                                )
                            ]
                        )
                    ]
                ),
                # Main content area
                html.Div(id="dashboard-content"),
                # Auto-refresh interval
                dcc.Interval(
                    id="interval-component",
                    interval=self.config.refresh_interval * 1000,
                    n_intervals=0,
                    disabled=not self.config.auto_refresh,
                ),
                # Data stores
                dcc.Store(id="dashboard-data"),
                dcc.Store(id="time-range", data="7d"),
                dcc.Store(id="widget-config", data=self.config.default_widgets),
            ],
            fluid=True,
        )

    def _register_callbacks(self):
        """Register dashboard callbacks."""
        if not DASH_AVAILABLE:
            return

        @self.app.callback(
            Output("dashboard-content", "children"),
            [
                Input("interval-component", "n_intervals"),
                Input("time-range", "data"),
                Input("widget-config", "data"),
            ],
            prevent_initial_call=False,
        )
        def update_dashboard_content(n_intervals, time_range, widget_config):
            """Update main dashboard content."""
            try:
                # Get latest data
                data = self._get_dashboard_data(time_range)

                # Generate widgets based on configuration
                widgets = self._generate_widgets(data, widget_config)

                return widgets

            except Exception as e:
                logger.error(f"Error updating dashboard: {e}")
                return html.Div(
                    f"Error loading dashboard: {str(e)}", className="alert alert-danger"
                )

        @self.app.callback(
            Output("time-range", "data"),
            [
                Input("1h-btn", "n_clicks"),
                Input("24h-btn", "n_clicks"),
                Input("7d-btn", "n_clicks"),
                Input("30d-btn", "n_clicks"),
            ],
            prevent_initial_call=True,
        )
        def update_time_range(h1_clicks, h24_clicks, d7_clicks, d30_clicks):
            """Update selected time range."""
            ctx = dash.callback_context
            if not ctx.triggered:
                raise PreventUpdate

            button_id = ctx.triggered[0]["prop_id"].split(".")[0]

            range_map = {
                "1h-btn": "1h",
                "24h-btn": "24h",
                "7d-btn": "7d",
                "30d-btn": "30d",
            }

            return range_map.get(button_id, "7d")

    def _get_dashboard_data(self, time_range: str) -> Dict[str, Any]:
        """Get dashboard data for specified time range."""
        # This would interface with the actual data sources
        # For now, return mock data structure

        now = datetime.now()

        if time_range == "1h":
            start_time = now - timedelta(hours=1)
        elif time_range == "24h":
            start_time = now - timedelta(days=1)
        elif time_range == "7d":
            start_time = now - timedelta(days=7)
        elif time_range == "30d":
            start_time = now - timedelta(days=30)
        else:
            start_time = now - timedelta(days=7)

        return {
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": now.isoformat(),
            "threat_metrics": {
                "total_analyses": 1250,
                "threat_detections": 45,
                "detection_rate": 3.6,
                "avg_processing_time": 12.3,
                "threat_trends": self._generate_trend_data(start_time, now),
            },
            "performance_metrics": {
                "cpu_usage": 67.5,
                "memory_usage": 78.2,
                "disk_usage": 45.1,
                "gpu_usage": 82.3,
            },
            "recent_analyses": self._generate_recent_analyses(10),
            "system_status": {
                "api_server": "healthy",
                "database": "healthy",
                "ml_engine": "healthy",
                "analysis_queue": "healthy",
            },
        }

    def _generate_trend_data(
        self, start_time: datetime, end_time: datetime
    ) -> List[Dict]:
        """Generate trend data for charts."""
        if not PANDAS_AVAILABLE:
            return []

        # Generate sample trend data
        time_points = pd.date_range(start_time, end_time, freq="1H")

        trends = []
        for i, timestamp in enumerate(time_points):
            trends.append(
                {
                    "date": timestamp.isoformat(),
                    "threats": max(
                        0, int(5 + 3 * np.sin(i * 0.1) + np.random.normal(0, 1))
                    ),
                    "analyses": max(
                        1, int(50 + 20 * np.sin(i * 0.05) + np.random.normal(0, 5))
                    ),
                }
            )

        return trends

    def _generate_recent_analyses(self, count: int) -> List[Dict]:
        """Generate recent analyses data."""
        analyses = []
        for i in range(count):
            analyses.append(
                {
                    "id": f"analysis_{i+1:04d}",
                    "file_name": f"sample_{i+1}.exe",
                    "status": np.random.choice(
                        ["completed", "running", "queued"], p=[0.7, 0.2, 0.1]
                    ),
                    "threat_level": np.random.choice(
                        ["low", "medium", "high"], p=[0.6, 0.3, 0.1]
                    ),
                    "confidence": round(np.random.uniform(0.7, 0.99), 2),
                    "timestamp": (
                        datetime.now() - timedelta(minutes=i * 5)
                    ).isoformat(),
                }
            )

        return analyses

    def _generate_widgets(self, data: Dict[str, Any], widget_config: List[str]) -> List:
        """Generate dashboard widgets based on configuration."""
        if not DASH_AVAILABLE:
            return []

        widgets = []

        # Metrics cards row
        widgets.append(
            dbc.Row(
                [
                    dbc.Col(
                        [
                            self._create_metric_card(
                                "Total Analyses",
                                data["threat_metrics"]["total_analyses"],
                                "📊",
                                "primary",
                            )
                        ],
                        width=3,
                    ),
                    dbc.Col(
                        [
                            self._create_metric_card(
                                "Threats Detected",
                                data["threat_metrics"]["threat_detections"],
                                "🔍",
                                "danger",
                            )
                        ],
                        width=3,
                    ),
                    dbc.Col(
                        [
                            self._create_metric_card(
                                "Detection Rate",
                                f"{data['threat_metrics']['detection_rate']:.1f}%",
                                "🎯",
                                "success",
                            )
                        ],
                        width=3,
                    ),
                    dbc.Col(
                        [
                            self._create_metric_card(
                                "Avg Time",
                                f"{data['threat_metrics']['avg_processing_time']:.1f}s",
                                "⏱️",
                                "info",
                            )
                        ],
                        width=3,
                    ),
                ],
                className="mb-4",
            )
        )

        # Charts row
        if PLOTLY_AVAILABLE and "detection_trends" in widget_config:
            widgets.append(
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Threat Detection Trends"),
                                        dbc.CardBody(
                                            [
                                                self._create_trend_chart(
                                                    data["threat_metrics"][
                                                        "threat_trends"
                                                    ]
                                                )
                                            ]
                                        ),
                                    ]
                                )
                            ],
                            width=8,
                        ),
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardHeader("System Performance"),
                                        dbc.CardBody(
                                            [
                                                self._create_performance_gauges(
                                                    data["performance_metrics"]
                                                )
                                            ]
                                        ),
                                    ]
                                )
                            ],
                            width=4,
                        ),
                    ],
                    className="mb-4",
                )
            )

        # Recent analyses table
        if "recent_analyses" in widget_config:
            widgets.append(
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Recent Analyses"),
                                        dbc.CardBody(
                                            [
                                                self._create_analyses_table(
                                                    data["recent_analyses"]
                                                )
                                            ]
                                        ),
                                    ]
                                )
                            ],
                            width=12,
                        )
                    ]
                )
            )

        return widgets

    def _create_metric_card(
        self, title: str, value: Union[str, int], icon: str, color: str
    ) -> dbc.Card:
        """Create metric card widget."""
        return dbc.Card(
            [
                dbc.CardBody(
                    [
                        html.Div(
                            [
                                html.H4(icon, className="text-muted mb-0"),
                                html.H3(str(value), className=f"text-{color} mb-0"),
                                html.P(title, className="text-muted mb-0 small"),
                            ]
                        )
                    ]
                )
            ],
            className="text-center",
        )

    def _create_trend_chart(self, trend_data: List[Dict]) -> dcc.Graph:
        """Create trend chart."""
        if not PLOTLY_AVAILABLE or not PANDAS_AVAILABLE:
            return html.Div("Chart not available - missing dependencies")

        if not trend_data:
            return html.Div("No data available")

        df = pd.DataFrame(trend_data)
        df["date"] = pd.to_datetime(df["date"])

        fig = px.line(
            df,
            x="date",
            y="threats",
            title="Threat Detections Over Time",
            color_discrete_sequence=["#dc3545"],
        )

        fig.update_layout(
            margin={"l": 20, "r": 20, "t": 40, "b": 20}, height=300, showlegend=False
        )

        return dcc.Graph(figure=fig, config={"displayModeBar": False})

    def _create_performance_gauges(self, perf_data: Dict[str, float]) -> html.Div:
        """Create performance gauge charts."""
        if not PLOTLY_AVAILABLE:
            return html.Div("Gauges not available - missing dependencies")

        gauges = []
        for metric, value in perf_data.items():
            if metric.endswith("_usage"):
                color = "red" if value > 80 else "yellow" if value > 60 else "green"

                fig = go.Figure(
                    go.Indicator(
                        mode="gauge+number",
                        value=value,
                        domain={"x": [0, 1], "y": [0, 1]},
                        title={"text": metric.replace("_", " ").title()},
                        gauge={
                            "axis": {"range": [None, 100]},
                            "bar": {"color": color},
                            "steps": [
                                {"range": [0, 60], "color": "lightgray"},
                                {"range": [60, 80], "color": "gray"},
                            ],
                        },
                    )
                )

                fig.update_layout(margin={"l": 10, "r": 10, "t": 30, "b": 10}, height=150)

                gauges.append(
                    dcc.Graph(
                        figure=fig,
                        config={"displayModeBar": False},
                        style={"height": "150px"},
                    )
                )

        return html.Div(gauges)

    def _create_analyses_table(self, analyses_data: List[Dict]) -> dash_table.DataTable:
        """Create analyses data table."""
        if not analyses_data:
            return html.Div("No recent analyses available")

        return dash_table.DataTable(
            data=analyses_data,
            columns=[
                {"name": "ID", "id": "id"},
                {"name": "File", "id": "file_name"},
                {"name": "Status", "id": "status"},
                {"name": "Threat Level", "id": "threat_level"},
                {
                    "name": "Confidence",
                    "id": "confidence",
                    "type": "numeric",
                    "format": ".2%",
                },
                {"name": "Time", "id": "timestamp", "type": "datetime"},
            ],
            style_cell={"textAlign": "left", "padding": "8px"},
            style_header={
                "backgroundColor": "rgb(230, 230, 230)",
                "fontWeight": "bold",
            },
            style_data_conditional=[
                {
                    "if": {"filter_query": "{status} = completed"},
                    "backgroundColor": "#d4edda",
                    "color": "#155724",
                },
                {
                    "if": {"filter_query": "{status} = running"},
                    "backgroundColor": "#fff3cd",
                    "color": "#856404",
                },
                {
                    "if": {"filter_query": "{threat_level} = high"},
                    "backgroundColor": "#f8d7da",
                    "color": "#721c24",
                },
            ],
            page_size=10,
            sort_action="native",
            filter_action="native",
        )

    def run(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        debug: Optional[bool] = None,
    ):
        """Run the dashboard server."""
        if not DASH_AVAILABLE:
            raise UIError("Dashboard not available - install Dash dependencies")

        if not self.app:
            raise UIError("Dashboard not initialized")

        host = host or self.config.host
        port = port or self.config.port
        debug = debug if debug is not None else self.config.debug

        logger.info(f"Starting dashboard server on {host}:{port}")

        try:
            self.app.run_server(
                host=host, port=port, debug=debug, dev_tools_hot_reload=debug
            )
        except Exception as e:
            logger.error(f"Failed to start dashboard server: {e}")
            raise UIError(f"Dashboard server failed: {e}") from e

    def get_app(self):
        """Get the Dash app instance for external hosting."""
        return self.app


# Exception classes are defined in core.exceptions as VMDragonSlayerError/UIError


def create_dashboard(config: Optional[DashboardConfig] = None) -> Dashboard:
    """Create and return a configured dashboard instance."""
    return Dashboard(config)


# Example usage
if __name__ == "__main__":
    # Create and run dashboard
    dashboard = create_dashboard()
    dashboard.run(debug=True)
