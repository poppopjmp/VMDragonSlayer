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
    AnalysisEnvironment,
    CountermeasureResult,
    CountermeasureType,
    DebuggerDetectionBypass,
    EnvironmentNormalizer,
    SandboxEvasionBypass,
    SelfModificationTracker,
    VMDetectionBypass,
)

__all__ = [
    "EnvironmentNormalizer",
    "DebuggerDetectionBypass",
    "SandboxEvasionBypass",
    "VMDetectionBypass",
    "SelfModificationTracker",
    "AnalysisEnvironment",
    "CountermeasureType",
    "CountermeasureResult",
]
