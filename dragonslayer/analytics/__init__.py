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
Analytics Module
================

Unified analytics and reporting system consolidating enterprise reporting functionality.

This module provides:
- Real-time analytics and dashboards
- Comprehensive reporting in multiple formats
- Threat intelligence analytics
- Performance and compliance reporting
- Business intelligence capabilities
"""

from .dashboard import AnalyticsDashboard
from .intelligence import ThreatIntelligence
from .metrics import MetricsCollector
from .reporting import ReportGenerator, ReportScheduler

__all__ = [
    "ReportGenerator",
    "ReportScheduler",
    "AnalyticsDashboard",
    "ThreatIntelligence",
    "MetricsCollector",
]
