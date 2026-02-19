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
    from .handler_boundaries import (
        identify_vip_register,
        segment_trace,
        VIPCandidate,
        HandlerBoundary,
        SegmentationResult,
    )
except ImportError:
    pass

__all__ = [
    "VMDetector",
    "VMAnalyzer",
    "VMSignature",
    "VMSignatureDatabase",
    "DispatcherAnalyzer",
    "DispatchTableResult",
    "identify_vip_register",
    "segment_trace",
    "VIPCandidate",
    "HandlerBoundary",
    "SegmentationResult",
]
