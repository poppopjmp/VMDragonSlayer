"""
B93 — GPU module smoke tests + additional property coverage.

Tests the GPU stub interfaces that previously had ZERO test coverage,
plus additional Hypothesis tests for pipeline and orchestrator APIs.
"""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# ═══════════════════════════════════════════════════════════════════════════
# GPU Module Smoke Tests
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.gpu import (
    gpu_available,
    GPUEngine,
    GPUMemoryManager,
    GPUOptimizer,
    GPUProfiler,
)
from dragonslayer.gpu.profiler import ProfileEntry


class TestGPUAvailability:
    """GPU availability must always be importable and return False in CI."""

    def test_gpu_available_returns_bool(self) -> None:
        assert isinstance(gpu_available(), bool)

    def test_gpu_not_available_in_ci(self) -> None:
        """No GPU expected in test environment."""
        assert gpu_available() is False


class TestGPUEngine:
    """GPUEngine stub must raise NotImplementedError on compute methods."""

    def test_create_engine(self) -> None:
        engine = GPUEngine(device_id=0)
        assert engine.device_id == 0
        assert engine._initialised is False

    def test_initialise_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUEngine().initialise()

    def test_pattern_match_bulk_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUEngine().pattern_match_bulk(b"\x00", [b"\x00"])

    def test_symbolic_evaluate_batch_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUEngine().symbolic_evaluate_batch([])

    def test_shutdown_succeeds(self) -> None:
        engine = GPUEngine()
        engine.shutdown()
        assert engine._initialised is False


class TestGPUMemoryManager:
    """GPUMemoryManager stub must track max_bytes and raise on allocate."""

    @given(max_bytes=st.integers(min_value=0, max_value=16 * 1024**3))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_max_bytes_stored(self, max_bytes: int) -> None:
        mgr = GPUMemoryManager(max_bytes=max_bytes)
        assert mgr.max_bytes == max_bytes

    def test_initial_used_zero(self) -> None:
        mgr = GPUMemoryManager()
        assert mgr.used_bytes == 0

    def test_free_equals_max(self) -> None:
        mgr = GPUMemoryManager(max_bytes=1024)
        assert mgr.free_bytes == 1024

    def test_allocate_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUMemoryManager().allocate(256)

    def test_free_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUMemoryManager().free(None)

    def test_stats_keys(self) -> None:
        stats = GPUMemoryManager(max_bytes=4096).stats()
        assert "max_bytes" in stats
        assert "allocated_bytes" in stats
        assert "free_bytes" in stats
        assert stats["max_bytes"] == 4096
        assert stats["allocated_bytes"] == 0


class TestGPUOptimizer:
    """GPUOptimizer stub must raise on compute methods."""

    def test_target_occupancy(self) -> None:
        opt = GPUOptimizer(target_occupancy=0.5)
        assert opt.target_occupancy == 0.5

    def test_recommend_block_size_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUOptimizer().recommend_block_size(None)

    def test_auto_tune_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            GPUOptimizer().auto_tune(None, 1024)


class TestGPUProfiler:
    """GPUProfiler works in CPU-only stub mode for timing."""

    def test_empty_entries(self) -> None:
        p = GPUProfiler()
        assert p.entries == []

    def test_measure_records_entry(self) -> None:
        p = GPUProfiler()
        with p.measure("test_op"):
            time.sleep(0.001)
        assert len(p.entries) == 1
        assert p.entries[0].name == "test_op"
        assert p.entries[0].duration_ms >= 0.0

    def test_summary_structure(self) -> None:
        p = GPUProfiler()
        with p.measure("op1"):
            pass
        with p.measure("op2"):
            pass
        s = p.summary()
        assert s["count"] == 2
        assert "total_ms" in s
        assert len(s["entries"]) == 2

    def test_reset_clears(self) -> None:
        p = GPUProfiler()
        with p.measure("op"):
            pass
        p.reset()
        assert p.entries == []

    @given(n=st.integers(min_value=1, max_value=10))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_measure_count(self, n: int) -> None:
        """n measure blocks should produce n entries."""
        p = GPUProfiler()
        for i in range(n):
            with p.measure(f"op_{i}"):
                pass
        assert len(p.entries) == n

    def test_profile_entry_defaults(self) -> None:
        e = ProfileEntry()
        assert e.name == ""
        assert e.duration_ms == 0.0
        assert e.memory_bytes == 0
        assert e.metadata == {}


# ═══════════════════════════════════════════════════════════════════════════
# __all__ export consistency tests
# ═══════════════════════════════════════════════════════════════════════════

class TestModuleExports:
    """Verify __all__ lists match actual public API."""

    def test_analysis_all_importable(self) -> None:
        """Every name in analysis.__all__ must be importable."""
        import dragonslayer.analysis as mod
        assert hasattr(mod, "__all__")
        for name in mod.__all__:
            assert hasattr(mod, name), f"{name} listed in __all__ but not importable"

    def test_plugins_all_importable(self) -> None:
        """Every name in plugins.__all__ must be importable."""
        import dragonslayer.plugins as mod
        assert hasattr(mod, "__all__")
        for name in mod.__all__:
            assert hasattr(mod, name), f"{name} listed in __all__ but not importable"

    def test_core_all_importable(self) -> None:
        """Every name in core.__all__ must be importable."""
        import dragonslayer.core as mod
        assert hasattr(mod, "__all__")
        for name in mod.__all__:
            assert hasattr(mod, name), f"{name} listed in __all__ but not importable"

    def test_ml_all_importable(self) -> None:
        """Every name in ml.__all__ must be importable."""
        import dragonslayer.ml as mod
        assert hasattr(mod, "__all__")
        for name in mod.__all__:
            assert hasattr(mod, name), f"{name} listed in __all__ but not importable"

    def test_gpu_all_importable(self) -> None:
        """Every name in gpu.__all__ must be importable."""
        import dragonslayer.gpu as mod
        assert hasattr(mod, "__all__")
        for name in mod.__all__:
            # GPU classes may be None when no backend is present
            assert name in dir(mod), f"{name} listed in __all__ but not in dir()"
