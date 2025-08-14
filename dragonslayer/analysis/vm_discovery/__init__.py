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
VM Discovery Module
==================

Virtual machine detection and structure analysis components.

This module provides comprehensive VM detection capabilities including:
- Bytecode pattern recognition
- Handler identification
- Control flow analysis
- Structure analysis
- Database persistence
"""

from .analyzer import ControlFlowNode, DataDependency, StructureAnalyzer
from .database import VMDatabase
from .detector import HandlerType, VMDetector, VMHandler, VMStructure, VMType

__all__ = [
    "VMDetector",
    "VMType",
    "HandlerType",
    "VMHandler",
    "VMStructure",
    "StructureAnalyzer",
    "ControlFlowNode",
    "DataDependency",
    "VMDatabase",
]
