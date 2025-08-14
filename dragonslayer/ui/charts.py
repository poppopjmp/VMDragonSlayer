"""
UI Charts
=========

Chart and visualization components for VMDragonSlayer UI.
Provides data visualization widgets with Plotly integration.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logger.warning("Plotly not available. Chart functionality will be limited.")


@dataclass
class ChartConfig:
    """Configuration for chart components."""
    chart_type: str
    title: str
    data: Dict[str, Any]
    layout: Dict[str, Any] = None
    style: Dict[str, Any] = None
    responsive: bool = True
    show_legend: bool = True
    theme: str = 'plotly_white'


class ChartGenerator:
    """
    Chart generator for creating various types of visualizations.
    
    Supports multiple chart types using Plotly for rich interactive charts.
    """
    
    def __init__(self, theme: str = 'plotly_white'):
        self.theme = theme
        self.default_colors = [
            '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
            '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'
        ]
    
    def create_line_chart(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a line chart."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Line Chart", data)
        
        fig = go.Figure()
        
        x_values = data.get('x', [])
        y_series = data.get('y', {})
        
        for i, (series_name, y_values) in enumerate(y_series.items()):
            color = self.default_colors[i % len(self.default_colors)]
            fig.add_trace(go.Scatter(
                x=x_values,
                y=y_values,
                mode='lines+markers',
                name=series_name,
                line=dict(color=color, width=2),
                marker=dict(size=6)
            ))
        
        fig.update_layout(
            title=config.title,
            xaxis_title=data.get('x_label', 'X Axis'),
            yaxis_title=data.get('y_label', 'Y Axis'),
            template=self.theme,
            showlegend=config.show_legend,
            hovermode='x unified'
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'line-chart-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_bar_chart(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a bar chart."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Bar Chart", data)
        
        fig = go.Figure()
        
        x_values = data.get('x', [])
        y_series = data.get('y', {})
        
        for i, (series_name, y_values) in enumerate(y_series.items()):
            color = self.default_colors[i % len(self.default_colors)]
            fig.add_trace(go.Bar(
                x=x_values,
                y=y_values,
                name=series_name,
                marker=dict(color=color)
            ))
        
        fig.update_layout(
            title=config.title,
            xaxis_title=data.get('x_label', 'X Axis'),
            yaxis_title=data.get('y_label', 'Y Axis'),
            template=self.theme,
            showlegend=config.show_legend,
            barmode='group'
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'bar-chart-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_pie_chart(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a pie chart."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Pie Chart", data)
        
        labels = data.get('labels', [])
        values = data.get('values', [])
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=0.3,  # Donut chart
            marker=dict(colors=self.default_colors[:len(labels)])
        )])
        
        fig.update_layout(
            title=config.title,
            template=self.theme,
            showlegend=config.show_legend
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'pie-chart-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_scatter_plot(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a scatter plot."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Scatter Plot", data)
        
        fig = go.Figure()
        
        series_data = data.get('series', {})
        
        for i, (series_name, series_values) in enumerate(series_data.items()):
            x_values = series_values.get('x', [])
            y_values = series_values.get('y', [])
            color = self.default_colors[i % len(self.default_colors)]
            
            fig.add_trace(go.Scatter(
                x=x_values,
                y=y_values,
                mode='markers',
                name=series_name,
                marker=dict(
                    color=color,
                    size=8,
                    opacity=0.7
                )
            ))
        
        fig.update_layout(
            title=config.title,
            xaxis_title=data.get('x_label', 'X Axis'),
            yaxis_title=data.get('y_label', 'Y Axis'),
            template=self.theme,
            showlegend=config.show_legend
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'scatter-plot-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_heatmap(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a heatmap."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Heatmap", data)
        
        z_values = data.get('z', [])
        x_labels = data.get('x_labels', [])
        y_labels = data.get('y_labels', [])
        
        fig = go.Figure(data=go.Heatmap(
            z=z_values,
            x=x_labels,
            y=y_labels,
            colorscale='Viridis',
            showscale=True
        ))
        
        fig.update_layout(
            title=config.title,
            template=self.theme,
            xaxis_title=data.get('x_label', 'X Axis'),
            yaxis_title=data.get('y_label', 'Y Axis')
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'heatmap-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_histogram(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a histogram."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Histogram", data)
        
        fig = go.Figure()
        
        series_data = data.get('series', {})
        
        for i, (series_name, values) in enumerate(series_data.items()):
            color = self.default_colors[i % len(self.default_colors)]
            fig.add_trace(go.Histogram(
                x=values,
                name=series_name,
                marker=dict(color=color),
                opacity=0.7
            ))
        
        fig.update_layout(
            title=config.title,
            xaxis_title=data.get('x_label', 'Value'),
            yaxis_title='Frequency',
            template=self.theme,
            showlegend=config.show_legend,
            barmode='overlay'
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'histogram-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_box_plot(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a box plot."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Box Plot", data)
        
        fig = go.Figure()
        
        series_data = data.get('series', {})
        
        for i, (series_name, values) in enumerate(series_data.items()):
            color = self.default_colors[i % len(self.default_colors)]
            fig.add_trace(go.Box(
                y=values,
                name=series_name,
                marker=dict(color=color)
            ))
        
        fig.update_layout(
            title=config.title,
            yaxis_title=data.get('y_label', 'Values'),
            template=self.theme,
            showlegend=config.show_legend
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'box-plot-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_gauge_chart(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a gauge chart."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Gauge Chart", data)
        
        value = data.get('value', 0)
        min_value = data.get('min', 0)
        max_value = data.get('max', 100)
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=value,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': config.title},
            delta={'reference': data.get('target', value)},
            gauge={
                'axis': {'range': [None, max_value]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [min_value, max_value * 0.5], 'color': "lightgray"},
                    {'range': [max_value * 0.5, max_value * 0.8], 'color': "gray"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': data.get('threshold', max_value * 0.9)
                }
            }
        ))
        
        fig.update_layout(template=self.theme)
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'gauge-chart-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_time_series(self, data: Dict[str, Any], config: ChartConfig) -> Dict[str, Any]:
        """Create a time series chart."""
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Time Series", data)
        
        fig = go.Figure()
        
        timestamps = data.get('timestamps', [])
        series_data = data.get('series', {})
        
        for i, (series_name, values) in enumerate(series_data.items()):
            color = self.default_colors[i % len(self.default_colors)]
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=values,
                mode='lines',
                name=series_name,
                line=dict(color=color, width=2)
            ))
        
        fig.update_layout(
            title=config.title,
            xaxis_title='Time',
            yaxis_title=data.get('y_label', 'Value'),
            template=self.theme,
            showlegend=config.show_legend,
            hovermode='x unified'
        )
        
        # Add range selector
        fig.update_layout(
            xaxis=dict(
                rangeselector=dict(
                    buttons=list([
                        dict(count=1, label="1h", step="hour", stepmode="backward"),
                        dict(count=6, label="6h", step="hour", stepmode="backward"),
                        dict(count=1, label="1d", step="day", stepmode="backward"),
                        dict(count=7, label="7d", step="day", stepmode="backward"),
                        dict(step="all")
                    ])
                ),
                rangeslider=dict(visible=True),
                type="date"
            )
        )
        
        if config.layout:
            fig.update_layout(**config.layout)
        
        return {
            'type': 'div',
            'className': 'time-series-container',
            'children': [{
                'type': 'Graph',
                'figure': fig.to_dict(),
                'config': {'responsive': config.responsive}
            }]
        }
    
    def create_dashboard_chart(self, chart_type: str, data: Dict[str, Any], 
                             config: ChartConfig) -> Dict[str, Any]:
        """Create a chart based on type."""
        chart_creators = {
            'line': self.create_line_chart,
            'bar': self.create_bar_chart,
            'pie': self.create_pie_chart,
            'scatter': self.create_scatter_plot,
            'heatmap': self.create_heatmap,
            'histogram': self.create_histogram,
            'box': self.create_box_plot,
            'gauge': self.create_gauge_chart,
            'timeseries': self.create_time_series
        }
        
        creator = chart_creators.get(chart_type)
        if not creator:
            raise ValueError(f"Unsupported chart type: {chart_type}")
        
        return creator(data, config)
    
    def _create_fallback_chart(self, chart_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a fallback chart when Plotly is not available."""
        return {
            'type': 'div',
            'className': 'chart-fallback',
            'style': {
                'border': '1px solid #ddd',
                'borderRadius': '8px',
                'padding': '20px',
                'textAlign': 'center',
                'backgroundColor': '#f8f9fa'
            },
            'children': [
                {
                    'type': 'h5',
                    'children': chart_type
                },
                {
                    'type': 'p',
                    'children': 'Chart visualization requires Plotly. Install with: pip install plotly'
                },
                {
                    'type': 'pre',
                    'style': {'textAlign': 'left', 'fontSize': '12px'},
                    'children': json.dumps(data, indent=2)
                }
            ]
        }


class AnalyticsCharts:
    """
    Specialized charts for analytics and monitoring.
    
    Provides pre-configured chart types for common analytics use cases.
    """
    
    def __init__(self, generator: ChartGenerator = None):
        self.generator = generator or ChartGenerator()
    
    def create_performance_dashboard(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create a performance monitoring dashboard."""
        charts = []
        
        # CPU Usage Time Series
        if 'cpu_usage' in metrics:
            cpu_config = ChartConfig(
                chart_type='timeseries',
                title='CPU Usage Over Time',
                data=metrics['cpu_usage']
            )
            charts.append(self.generator.create_time_series(metrics['cpu_usage'], cpu_config))
        
        # Memory Usage Gauge
        if 'memory_usage' in metrics:
            memory_config = ChartConfig(
                chart_type='gauge',
                title='Memory Usage',
                data=metrics['memory_usage']
            )
            charts.append(self.generator.create_gauge_chart(metrics['memory_usage'], memory_config))
        
        # Error Rate Histogram
        if 'error_rates' in metrics:
            error_config = ChartConfig(
                chart_type='bar',
                title='Error Rates by Category',
                data=metrics['error_rates']
            )
            charts.append(self.generator.create_bar_chart(metrics['error_rates'], error_config))
        
        return charts
    
    def create_security_dashboard(self, security_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create a security monitoring dashboard."""
        charts = []
        
        # Threat Level Gauge
        if 'threat_level' in security_data:
            threat_config = ChartConfig(
                chart_type='gauge',
                title='Overall Threat Level',
                data=security_data['threat_level']
            )
            charts.append(self.generator.create_gauge_chart(security_data['threat_level'], threat_config))
        
        # Vulnerability Distribution
        if 'vulnerabilities' in security_data:
            vuln_config = ChartConfig(
                chart_type='pie',
                title='Vulnerability Distribution',
                data=security_data['vulnerabilities']
            )
            charts.append(self.generator.create_pie_chart(security_data['vulnerabilities'], vuln_config))
        
        # Attack Timeline
        if 'attack_timeline' in security_data:
            attack_config = ChartConfig(
                chart_type='timeseries',
                title='Security Events Timeline',
                data=security_data['attack_timeline']
            )
            charts.append(self.generator.create_time_series(security_data['attack_timeline'], attack_config))
        
        return charts
    
    def create_analysis_dashboard(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create an analysis results dashboard."""
        charts = []
        
        # Analysis Progress
        if 'progress' in analysis_data:
            progress_config = ChartConfig(
                chart_type='bar',
                title='Analysis Progress by Module',
                data=analysis_data['progress']
            )
            charts.append(self.generator.create_bar_chart(analysis_data['progress'], progress_config))
        
        # Function Complexity Distribution
        if 'complexity' in analysis_data:
            complexity_config = ChartConfig(
                chart_type='histogram',
                title='Function Complexity Distribution',
                data=analysis_data['complexity']
            )
            charts.append(self.generator.create_histogram(analysis_data['complexity'], complexity_config))
        
        # Pattern Detection Heatmap
        if 'patterns' in analysis_data:
            pattern_config = ChartConfig(
                chart_type='heatmap',
                title='Pattern Detection Heatmap',
                data=analysis_data['patterns']
            )
            charts.append(self.generator.create_heatmap(analysis_data['patterns'], pattern_config))
        
        return charts


# Utility functions
def create_chart_generator(theme: str = 'plotly_white') -> ChartGenerator:
    """Create and return a chart generator instance."""
    return ChartGenerator(theme)


def create_analytics_charts(generator: ChartGenerator = None) -> AnalyticsCharts:
    """Create and return an analytics charts instance."""
    return AnalyticsCharts(generator)


def create_chart_config(chart_type: str, title: str, data: Dict[str, Any],
                       **kwargs) -> ChartConfig:
    """Create a chart configuration."""
    return ChartConfig(
        chart_type=chart_type,
        title=title,
        data=data,
        **kwargs
    )
