"""
VM Discovery
=============

Heuristic-based detection and analysis of virtual-machine obfuscation.
"""

from __future__ import annotations

try:
    from .detector import VMDetector
    from .analyzer import VMAnalyzer
    from .database import VMSignature, VMSignatureDatabase
    from .dispatcher import DispatcherAnalyzer, DispatchTableResult
except ImportError:
    pass

__all__ = [
    "VMDetector",
    "VMAnalyzer",
    "VMSignature",
    "VMSignatureDatabase",
    "DispatcherAnalyzer",
    "DispatchTableResult",
]
