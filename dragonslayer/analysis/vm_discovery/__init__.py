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

from .detector import VMDetector, VMType, HandlerType, VMHandler, VMStructure
from .analyzer import StructureAnalyzer, ControlFlowNode, DataDependency
from .database import VMDatabase

__all__ = [
    'VMDetector',
    'VMType', 
    'HandlerType',
    'VMHandler',
    'VMStructure',
    'StructureAnalyzer',
    'ControlFlowNode',
    'DataDependency',
    'VMDatabase'
]
