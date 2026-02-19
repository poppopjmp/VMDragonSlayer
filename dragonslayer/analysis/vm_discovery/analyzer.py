"""
VM Discovery — Analyzer
=======================

Higher-level analysis that combines :class:`VMDetector` results with
pattern analysis data to produce an enriched VM assessment.  This module
bridges the gap between raw detection heuristics and the pipeline's
shared context.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .detector import VMDetector

logger = logging.getLogger(__name__)


class VMAnalyzer:
    """
    Combines VMDetector heuristics with pattern-analysis results.

    Usage::

        analyzer = VMAnalyzer()
        report = analyzer.analyze(binary_data, pattern_matches=[...])
    """

    def __init__(self) -> None:
        self._detector = VMDetector()

    def analyze(
        self,
        data: bytes,
        *,
        pattern_matches: Optional[List[Dict[str, Any]]] = None,
        shared_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full VM analysis combining heuristics + pattern data.

        Parameters
        ----------
        data : bytes
            Raw binary data.
        pattern_matches : list | None
            Pre-computed pattern matches from the pattern analysis stage.
        shared_data : dict | None
            Pipeline shared_data for cross-stage context.

        Returns
        -------
        dict
            Enriched detection result with handler map and recommendations.
        """
        # Run base detection
        detection = self._detector.detect(data)

        # Enrich with pattern matches
        handler_map: List[Dict[str, Any]] = []
        handler_types_seen: set = set()

        for match in (pattern_matches or []):
            handler_type = match.get("handler_type", "unknown")
            handler_types_seen.add(handler_type)
            handler_map.append({
                "name": match.get("name", ""),
                "handler_type": handler_type,
                "operation": match.get("operation", ""),
                "offset": match.get("start_offset", 0),
                "confidence": match.get("confidence", 0.0),
            })

        # Assess protector complexity
        complexity = self._assess_complexity(
            detection=detection,
            handler_types=handler_types_seen,
            pattern_count=len(pattern_matches or []),
        )

        # Build recommendations
        recommendations = self._build_recommendations(
            detection=detection,
            handler_types=handler_types_seen,
            complexity=complexity,
        )

        return {
            **detection,
            "handler_map": handler_map,
            "handler_types": sorted(handler_types_seen),
            "total_handlers_identified": len(handler_map),
            "complexity": complexity,
            "recommendations": recommendations,
        }

    @staticmethod
    def _assess_complexity(
        detection: Dict[str, Any],
        handler_types: set,
        pattern_count: int,
    ) -> str:
        """Estimate obfuscation complexity: low / medium / high / extreme."""
        score = 0

        if detection.get("confidence", 0) > 0.7:
            score += 2
        elif detection.get("confidence", 0) > 0.4:
            score += 1

        if len(handler_types) > 10:
            score += 2
        elif len(handler_types) > 5:
            score += 1

        if pattern_count > 50:
            score += 2
        elif pattern_count > 20:
            score += 1

        entropy = detection.get("entropy", {})
        if entropy.get("ratio", 0) > 0.8:
            score += 2
        elif entropy.get("ratio", 0) > 0.5:
            score += 1

        dispatchers = detection.get("dispatchers", [])
        if len(dispatchers) > 10:
            score += 1

        if score >= 7:
            return "extreme"
        if score >= 5:
            return "high"
        if score >= 3:
            return "medium"
        return "low"

    @staticmethod
    def _build_recommendations(
        detection: Dict[str, Any],
        handler_types: set,
        complexity: str,
    ) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recs: List[str] = []

        protector = detection.get("protector", "unknown")
        if protector == "VMProtect":
            recs.append("Use VMProtect-specific handler tables for devirtualisation.")
            recs.append("Focus on dispatcher identification — look for PUSH/JMP patterns.")
        elif protector == "Themida":
            recs.append("Themida uses multi-layered VM — expect nested interpreters.")
            recs.append("Consider OEP tracing combined with import reconstruction.")
        elif protector == "Code Virtualizer":
            recs.append("Code Virtualizer has simpler handler dispatch — focus on CALL table.")

        if complexity in ("high", "extreme"):
            recs.append("Consider using symbolic execution (z3/triton) for constraint solving.")
            recs.append("Use taint tracking to identify data-flow through VM handlers.")

        if detection.get("dispatchers"):
            recs.append(f"Found {len(detection['dispatchers'])} potential dispatcher sites — "
                        "trace execution from these entry points.")

        if handler_types:
            missing = {"arithmetic", "memory_read", "memory_write", "branch_conditional"} - handler_types
            if missing:
                recs.append(f"Missing handler classifications: {', '.join(sorted(missing))}. "
                            "Consider deeper dynamic analysis.")

        if not recs:
            recs.append("No strong VM indicators found — binary may not be VM-protected.")

        return recs
