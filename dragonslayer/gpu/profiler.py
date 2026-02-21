"""
GPU Profiler
============

Collects timing, memory bandwidth, and kernel-occupancy metrics for
GPU-accelerated analysis tasks.

Stub — requires a GPU backend for real profiling.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List

logger = logging.getLogger(__name__)


@dataclass
class ProfileEntry:
    """A single profiling measurement."""

    name: str = ""
    duration_ms: float = 0.0
    memory_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class GPUProfiler:
    """Collect GPU performance metrics.

    The profiler works in stub mode (CPU-only timing) when no GPU
    backend is available, so it can always be instantiated.
    """

    def __init__(self) -> None:
        self._entries: List[ProfileEntry] = []

    @contextmanager
    def measure(self, name: str) -> Generator[None, None, None]:
        """Context manager that records wall-clock time for *name*."""
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed = (time.perf_counter() - t0) * 1000.0
            self._entries.append(ProfileEntry(name=name, duration_ms=elapsed))

    @property
    def entries(self) -> List[ProfileEntry]:
        return list(self._entries)

    def summary(self) -> Dict[str, Any]:
        """Return aggregate profiling statistics.

        Returns:
            Dict with ``total_ms`` (float), ``count`` (int), and
            ``entries`` (list of name/duration dicts).
        """
        total = sum(e.duration_ms for e in self._entries)
        return {
            "total_ms": round(total, 3),
            "count": len(self._entries),
            "entries": [
                {"name": e.name, "duration_ms": round(e.duration_ms, 3)}
                for e in self._entries
            ],
        }

    def reset(self) -> None:
        self._entries.clear()
