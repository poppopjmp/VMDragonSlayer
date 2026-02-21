"""
Analysis Metrics & Observability
================================

Lightweight instrumentation for timing and counting analysis phases.
Thread-safe via :class:`threading.Lock`.  Attach an :class:`AnalysisMetrics`
instance to the orchestrator or executor run and call :meth:`to_dict` at
the end to export structured telemetry.

Usage::

    metrics = AnalysisMetrics()
    with metrics.phase("vm_discovery"):
        run_vm_discovery(...)
    with metrics.phase("symbolic_execution"):
        run_symbolic(...)
    print(metrics.summary())
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PhaseMetric:
    """Timing + counters for one analysis phase."""

    name: str
    start_ts: float = 0.0
    end_ts: float = 0.0
    elapsed_s: float = 0.0
    item_count: int = 0
    error_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "elapsed_s": round(self.elapsed_s, 4),
            "item_count": self.item_count,
            "error_count": self.error_count,
            "metadata": self.metadata,
        }


class AnalysisMetrics:
    """Accumulate timing metrics across analysis phases.

    Parameters
    ----------
    run_id : str | None
        Optional identifier for the analysis run (e.g. sample hash).
    """

    def __init__(self, run_id: Optional[str] = None) -> None:
        self.run_id = run_id or ""
        self._phases: Dict[str, PhaseMetric] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self._global_start = time.perf_counter()
        self._global_end: Optional[float] = None

    # -- context manager for a named phase -----------------------------------

    @contextmanager
    def phase(self, name: str) -> Generator[PhaseMetric, None, None]:
        """Time a phase as a context manager.

        Example::

            with metrics.phase("taint_tracking") as pm:
                pm.item_count = len(handlers)
                run_taint(handlers)
        """
        pm = PhaseMetric(name=name, start_ts=time.perf_counter())
        try:
            yield pm
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError):
            pm.error_count += 1
            raise
        finally:
            pm.end_ts = time.perf_counter()
            pm.elapsed_s = pm.end_ts - pm.start_ts
            with self._lock:
                if name in self._phases:
                    # Merge into existing (repeated phases)
                    existing = self._phases[name]
                    existing.elapsed_s += pm.elapsed_s
                    existing.item_count += pm.item_count
                    existing.error_count += pm.error_count
                else:
                    self._phases[name] = pm
                    self._order.append(name)

    # -- manual start/stop for non-CM usage ----------------------------------

    def start_phase(self, name: str) -> PhaseMetric:
        pm = PhaseMetric(name=name, start_ts=time.perf_counter())
        with self._lock:
            self._phases[name] = pm
            if name not in self._order:
                self._order.append(name)
        return pm

    def stop_phase(self, name: str, *, item_count: int = 0, error_count: int = 0,
                   **metadata: Any) -> None:
        with self._lock:
            pm = self._phases.get(name)
        if pm:
            pm.end_ts = time.perf_counter()
            pm.elapsed_s = pm.end_ts - pm.start_ts
            if item_count:
                pm.item_count += item_count
            if error_count:
                pm.error_count += error_count
            if metadata:
                pm.metadata.update(metadata)

    # -- finalise ------------------------------------------------------------

    def finalise(self) -> None:
        """Mark the end of the analysis run."""
        self._global_end = time.perf_counter()

    @property
    def total_elapsed_s(self) -> float:
        end = self._global_end or time.perf_counter()
        return end - self._global_start

    @property
    def phase_count(self) -> int:
        return len(self._phases)

    def get_phase(self, name: str) -> Optional[PhaseMetric]:
        return self._phases.get(name)

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "total_elapsed_s": round(self.total_elapsed_s, 4),
            "phase_count": self.phase_count,
            "phases": [self._phases[n].to_dict() for n in self._order
                       if n in self._phases],
        }

    def summary(self) -> str:
        """One-line summary: total time + per-phase breakdown."""
        parts = [f"total={self.total_elapsed_s:.2f}s"]
        for name in self._order:
            pm = self._phases.get(name)
            if pm:
                parts.append(f"{pm.name}={pm.elapsed_s:.2f}s")
        return " | ".join(parts)

    def __repr__(self) -> str:
        return f"<AnalysisMetrics phases={self.phase_count} total={self.total_elapsed_s:.2f}s>"
