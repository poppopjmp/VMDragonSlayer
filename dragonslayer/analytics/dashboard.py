"""
Analytics Dashboard
===================

Real-time analytics dashboard consolidating enterprise dashboard functionality.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

try:
    import dash
    from dash import dcc, html, Input, Output, callback
    import plotly.graph_objects as go
    import plotly.express as px
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    logger.info("Dash not available, web dashboard disabled")


class AnalyticsDashboard:
    """
    Real-time analytics dashboard with web interface.
    
    Consolidates functionality from enterprise dashboard components.
    """
    
    def __init__(self, port: int = 8050, debug: bool = False):
        self.port = port
        self.debug = debug
        self.app = None
        self.data_cache = {}
        
        if DASH_AVAILABLE:
            self._initialize_dashboard()
        else:
            logger.warning("Dashboard unavailable - Dash not installed")
    
    def _initialize_dashboard(self):
        """Initialize Dash application."""
        if not DASH_AVAILABLE:
            return
        
        self.app = dash.Dash(__name__)
        self.app.title = "VMDragonSlayer Analytics Dashboard"
        
        # Define layout
        self.app.layout = html.Div([
            html.H1("VMDragonSlayer Analytics Dashboard", 
                   className="dashboard-title"),
            
            html.Div([
                html.H2("System Overview"),
                html.Div(id="system-overview", className="metrics-row")
            ], className="dashboard-section"),
            
            html.Div([
                html.H2("Real-time Metrics"),
                dcc.Graph(id="real-time-chart"),
                dcc.Interval(
                    id='interval-component',
                    interval=5*1000,  # Update every 5 seconds
                    n_intervals=0
                )
            ], className="dashboard-section"),
            
            html.Div([
                html.H2("Analysis Trends"),
                dcc.Graph(id="trend-chart")
            ], className="dashboard-section"),
            
            html.Div([
                html.H2("Threat Intelligence"),
                dcc.Graph(id="threat-chart")
            ], className="dashboard-section")
        ], className="dashboard-container")
        
        # Set up callbacks
        self._setup_callbacks()
    
    def _setup_callbacks(self):
        """Set up dashboard callbacks."""
        if not DASH_AVAILABLE:
            return
        
        @self.app.callback(
            Output('system-overview', 'children'),
            Input('interval-component', 'n_intervals')
        )
        def update_system_overview(n):
            metrics = self._get_system_metrics()
            
            return html.Div([
                html.Div([
                    html.H3(str(metrics.get('total_analyses', 0))),
                    html.P("Total Analyses")
                ], className="metric-card"),
                
                html.Div([
                    html.H3(str(metrics.get('active_users', 0))),
                    html.P("Active Users")
                ], className="metric-card"),
                
                html.Div([
                    html.H3(f"{metrics.get('detection_rate', 0):.1%}"),
                    html.P("Detection Rate")
                ], className="metric-card"),
                
                html.Div([
                    html.H3(str(metrics.get('threats_detected', 0))),
                    html.P("Threats Detected")
                ], className="metric-card")
            ], className="metrics-grid")
        
        @self.app.callback(
            Output('real-time-chart', 'figure'),
            Input('interval-component', 'n_intervals')
        )
        def update_real_time_chart(n):
            data = self._get_real_time_data()
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=data.get('timestamps', []),
                y=data.get('analysis_count', []),
                mode='lines+markers',
                name='Analyses per Hour',
                line=dict(color='#1f77b4', width=3)
            ))
            
            fig.update_layout(
                title="Real-time Analysis Activity",
                xaxis_title="Time",
                yaxis_title="Number of Analyses",
                height=400,
                showlegend=True
            )
            
            return fig
        
        @self.app.callback(
            Output('trend-chart', 'figure'),
            Input('interval-component', 'n_intervals')
        )
        def update_trend_chart(n):
            data = self._get_trend_data()
            
            fig = go.Figure()
            
            # Add multiple traces for different metrics
            fig.add_trace(go.Scatter(
                x=data.get('dates', []),
                y=data.get('daily_analyses', []),
                mode='lines+markers',
                name='Daily Analyses',
                line=dict(color='#2ca02c')
            ))
            
            fig.add_trace(go.Scatter(
                x=data.get('dates', []),
                y=data.get('malware_detected', []),
                mode='lines+markers',
                name='Malware Detected',
                line=dict(color='#d62728'),
                yaxis='y2'
            ))
            
            fig.update_layout(
                title="7-Day Analysis Trends",
                xaxis_title="Date",
                yaxis_title="Analyses Count",
                yaxis2=dict(
                    title="Malware Count",
                    overlaying='y',
                    side='right'
                ),
                height=400,
                showlegend=True
            )
            
            return fig
        
        @self.app.callback(
            Output('threat-chart', 'figure'),
            Input('interval-component', 'n_intervals')
        )
        def update_threat_chart(n):
            data = self._get_threat_data()
            
            fig = go.Figure(data=[
                go.Pie(
                    labels=data.get('threat_types', []),
                    values=data.get('threat_counts', []),
                    hole=0.3
                )
            ])
            
            fig.update_layout(
                title="Threat Type Distribution",
                height=400
            )
            
            return fig
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics."""
        # In practice, this would fetch from a database or monitoring system
        return {
            'total_analyses': 1247,
            'active_users': 8,
            'detection_rate': 0.742,
            'threats_detected': 89
        }
    
    def _get_real_time_data(self) -> Dict[str, List]:
        """Get real-time analysis data."""
        # Generate sample real-time data
        now = datetime.now()
        timestamps = []
        analysis_counts = []
        
        for i in range(24):  # Last 24 hours
            timestamp = now - timedelta(hours=i)
            timestamps.append(timestamp)
            # Simulate varying analysis counts
            count = 20 + (i % 5) * 8 + (i % 3) * 3
            analysis_counts.append(count)
        
        return {
            'timestamps': timestamps[::-1],  # Reverse for chronological order
            'analysis_count': analysis_counts[::-1]
        }
    
    def _get_trend_data(self) -> Dict[str, List]:
        """Get trend analysis data."""
        # Generate sample trend data for the last 7 days
        dates = []
        daily_analyses = []
        malware_detected = []
        
        for i in range(7):
            date = datetime.now() - timedelta(days=i)
            dates.append(date.strftime('%Y-%m-%d'))
            
            # Simulate trend data
            analyses = 450 + (i % 3) * 50 - i * 10
            malware = analyses * 0.15 + (i % 2) * 5
            
            daily_analyses.append(analyses)
            malware_detected.append(int(malware))
        
        return {
            'dates': dates[::-1],  # Reverse for chronological order
            'daily_analyses': daily_analyses[::-1],
            'malware_detected': malware_detected[::-1]
        }
    
    def _get_threat_data(self) -> Dict[str, List]:
        """Get threat intelligence data."""
        return {
            'threat_types': ['Trojan', 'Virus', 'Worm', 'Adware', 'Spyware', 'Rootkit'],
            'threat_counts': [45, 23, 12, 8, 6, 3]
        }
    
    def add_custom_css(self, css_content: str):
        """Add custom CSS styling to the dashboard."""
        if not DASH_AVAILABLE or not self.app:
            return
        
        # Add CSS as external stylesheet or inline
        self.app.index_string = f'''
        <!DOCTYPE html>
        <html>
            <head>
                {{%metas%}}
                <title>{{%title%}}</title>
                {{%favicon%}}
                {{%css%}}
                <style>
                {css_content}
                
                /* Default dashboard styles */
                .dashboard-container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    font-family: Arial, sans-serif;
                }}
                
                .dashboard-title {{
                    text-align: center;
                    color: #2c3e50;
                    margin-bottom: 30px;
                }}
                
                .dashboard-section {{
                    margin-bottom: 40px;
                    padding: 20px;
                    background: #f8f9fa;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                
                .metrics-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                }}
                
                .metric-card {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                
                .metric-card h3 {{
                    margin: 0;
                    font-size: 2em;
                    color: #2c3e50;
                }}
                
                .metric-card p {{
                    margin: 10px 0 0 0;
                    color: #7f8c8d;
                    font-weight: bold;
                }}
                </style>
            </head>
            <body>
                {{%app_entry%}}
                <footer>
                    {{%config%}}
                    {{%scripts%}}
                    {{%renderer%}}
                </footer>
            </body>
        </html>
        '''
    
    def run(self, host: str = "127.0.0.1"):
        """Run the dashboard server."""
        if not DASH_AVAILABLE or not self.app:
            logger.error("Cannot run dashboard - Dash not available")
            return
        
        # Add default CSS
        self.add_custom_css("")
        
        logger.info(f"Starting analytics dashboard on http://{host}:{self.port}")
        
        try:
            self.app.run_server(
                host=host,
                port=self.port,
                debug=self.debug,
                use_reloader=False  # Avoid issues in production
            )
        except Exception as e:
            logger.error(f"Dashboard startup failed: {e}")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data as JSON."""
        return {
            'system_metrics': self._get_system_metrics(),
            'real_time_data': self._get_real_time_data(),
            'trend_data': self._get_trend_data(),
            'threat_data': self._get_threat_data(),
            'last_updated': datetime.now().isoformat()
        }
    
    def export_dashboard_config(self, filepath: str):
        """Export dashboard configuration."""
        config = {
            'port': self.port,
            'debug': self.debug,
            'dash_available': DASH_AVAILABLE,
            'created_at': datetime.now().isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Dashboard configuration exported to {filepath}")


# Convenience functions
def create_dashboard(port: int = 8050, debug: bool = False) -> AnalyticsDashboard:
    """Create a new analytics dashboard instance."""
    return AnalyticsDashboard(port=port, debug=debug)


def get_dashboard_status() -> Dict[str, Any]:
    """Get dashboard availability status."""
    return {
        'dash_available': DASH_AVAILABLE,
        'can_create_dashboard': DASH_AVAILABLE,
        'required_packages': ['dash', 'plotly'],
        'status': 'available' if DASH_AVAILABLE else 'unavailable'
    }
