"""
Anti-Evasion Analysis Module for VMDragonSlayer
==============================================

This module provides comprehensive anti-analysis detection and bypass capabilities
for analyzing malware that attempts to evade detection in virtual machines,
sandboxes, and debuggers.

Key Components:
    - EnvironmentNormalizer: Detects and normalizes analysis environments
    - DebuggerBypass: Detects and bypasses debugger detection mechanisms
    - SandboxEvasion: Handles sandbox evasion techniques
    - VMDetectionBypass: Bypasses virtual machine detection

Usage:
    from dragonslayer.analysis.anti_evasion import EnvironmentNormalizer
    
    normalizer = EnvironmentNormalizer()
    env, confidence = normalizer.detect_analysis_environment()
    
    if env != AnalysisEnvironment.BARE_METAL:
        success = normalizer.normalize_environment(AnalysisEnvironment.BARE_METAL)
"""

from .environment_normalizer import (
    EnvironmentNormalizer,
    DebuggerDetectionBypass,
    SandboxEvasionBypass,
    VMDetectionBypass,
    SelfModificationTracker,
    AnalysisEnvironment,
    CountermeasureType,
    CountermeasureResult
)

__all__ = [
    'EnvironmentNormalizer',
    'DebuggerDetectionBypass', 
    'SandboxEvasionBypass',
    'VMDetectionBypass',
    'SelfModificationTracker',
    'AnalysisEnvironment',
    'CountermeasureType',
    'CountermeasureResult'
]
