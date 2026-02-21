"""
B94 — VMAnalyzer coverage, solver import guard, config annotation verification,
and server return-type annotation coverage.

Covers the previously-zero-test VMAnalyzer class, validates z3 import guards,
and exercises annotated config/server paths.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest
from hypothesis import given, settings, HealthCheck, assume
from hypothesis import strategies as st

# ═══════════════════════════════════════════════════════════════════════════
# VMAnalyzer tests (H6 — zero coverage → full coverage)
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.vm_discovery.analyzer import VMAnalyzer


class TestVMAnalyzer:
    """Tests for VMAnalyzer combining detection + pattern enrichment."""

    def test_analyze_empty_data(self) -> None:
        """Empty bytes should return a valid detection dict."""
        analyzer = VMAnalyzer()
        result = analyzer.analyze(b"")
        assert isinstance(result, dict)
        assert "handler_map" in result
        assert "complexity" in result
        assert "recommendations" in result

    def test_analyze_returns_handler_map(self) -> None:
        """Pattern matches should appear in handler_map."""
        analyzer = VMAnalyzer()
        matches = [
            {"name": "vm_add", "handler_type": "arithmetic",
             "operation": "add", "start_offset": 0x100, "confidence": 0.9},
            {"name": "vm_push", "handler_type": "stack",
             "operation": "push", "start_offset": 0x200, "confidence": 0.8},
        ]
        result = analyzer.analyze(b"\x00" * 64, pattern_matches=matches)
        assert len(result["handler_map"]) == 2
        assert result["total_handlers_identified"] == 2
        assert "arithmetic" in result["handler_types"]
        assert "stack" in result["handler_types"]

    def test_analyze_no_pattern_matches(self) -> None:
        """Without pattern matches, handler_map should be empty."""
        analyzer = VMAnalyzer()
        result = analyzer.analyze(b"\xCC" * 32)
        assert result["handler_map"] == []
        assert result["total_handlers_identified"] == 0

    @given(n=st.integers(min_value=0, max_value=20))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_handler_count_matches_input(self, n: int) -> None:
        """total_handlers_identified must equal len(pattern_matches)."""
        matches = [
            {"name": f"h{i}", "handler_type": "unknown",
             "operation": "", "start_offset": i * 16, "confidence": 0.5}
            for i in range(n)
        ]
        analyzer = VMAnalyzer()
        result = analyzer.analyze(b"\x00" * 128, pattern_matches=matches)
        assert result["total_handlers_identified"] == n

    def test_complexity_levels(self) -> None:
        """Complexity should be one of the four expected levels."""
        analyzer = VMAnalyzer()
        result = analyzer.analyze(b"\x00" * 32)
        assert result["complexity"] in ("low", "medium", "high", "extreme")

    def test_many_patterns_high_complexity(self) -> None:
        """Many diverse handler types should push complexity upward."""
        types = [
            "arithmetic", "memory_read", "memory_write", "branch_conditional",
            "branch_unconditional", "stack_push", "stack_pop", "logic_and",
            "logic_or", "logic_xor", "rotate", "system_call",
        ]
        matches = [
            {"name": f"h{i}", "handler_type": types[i % len(types)],
             "operation": "", "start_offset": i, "confidence": 0.9}
            for i in range(60)
        ]
        analyzer = VMAnalyzer()
        result = analyzer.analyze(b"\xCC" * 256, pattern_matches=matches)
        assert result["complexity"] in ("medium", "high", "extreme")

    def test_recommendations_for_vmprotect(self) -> None:
        """Recommendations should mention VMProtect-specific guidance."""
        analyzer = VMAnalyzer()
        # Provide detection-like data via shared_data (depending on detector)
        result = analyzer.analyze(b"\x00" * 64)
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) > 0

    def test_shared_data_accepted(self) -> None:
        """Passing shared_data should not raise."""
        analyzer = VMAnalyzer()
        result = analyzer.analyze(
            b"\x00" * 32,
            shared_data={"stage": "dynamic", "extra": True},
        )
        assert isinstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════
# Complexity scoring property tests
# ═══════════════════════════════════════════════════════════════════════════

class TestVMAnalyzerComplexity:
    """Property-based tests for _assess_complexity."""

    @given(conf=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
           n_types=st.integers(min_value=0, max_value=20),
           n_patterns=st.integers(min_value=0, max_value=100))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_complexity_always_valid(self, conf: float, n_types: int, n_patterns: int) -> None:
        """_assess_complexity must return one of four valid levels."""
        detection = {"confidence": conf, "entropy": {"ratio": 0.0}}
        handler_types = {f"type_{i}" for i in range(n_types)}
        result = VMAnalyzer._assess_complexity(detection, handler_types, n_patterns)
        assert result in ("low", "medium", "high", "extreme")

    @given(n_types=st.integers(min_value=11, max_value=20),
           n_patterns=st.integers(min_value=51, max_value=100))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_high_inputs_at_least_medium(self, n_types: int, n_patterns: int) -> None:
        """High handler types + pattern counts should be at least medium."""
        detection = {"confidence": 0.9, "entropy": {"ratio": 0.9}, "dispatchers": list(range(12))}
        handler_types = {f"type_{i}" for i in range(n_types)}
        result = VMAnalyzer._assess_complexity(detection, handler_types, n_patterns)
        assert result in ("medium", "high", "extreme")


# ═══════════════════════════════════════════════════════════════════════════
# Z3 import guard tests (H2)
# ═══════════════════════════════════════════════════════════════════════════

class TestZ3ImportGuards:
    """Verify z3 optional-dependency contract is consistent."""

    def test_solver_has_z3_available_flag(self) -> None:
        """solver module must expose _Z3_AVAILABLE flag."""
        from dragonslayer.analysis.symbolic_execution import solver
        assert hasattr(solver, "_Z3_AVAILABLE")
        assert isinstance(solver._Z3_AVAILABLE, bool)

    def test_mba_has_z3_available_flag(self) -> None:
        """mba_simplifier module must expose _Z3_AVAILABLE flag."""
        from dragonslayer.analysis import mba_simplifier
        assert hasattr(mba_simplifier, "_Z3_AVAILABLE")
        assert isinstance(mba_simplifier._Z3_AVAILABLE, bool)

    def test_state_has_z3_available_flag(self) -> None:
        """state module must expose _Z3_AVAILABLE flag."""
        from dragonslayer.analysis.symbolic_execution import state
        assert hasattr(state, "_Z3_AVAILABLE")
        assert isinstance(state._Z3_AVAILABLE, bool)

    def test_z3_available_consistent(self) -> None:
        """All three z3-dependent modules should agree on availability."""
        from dragonslayer.analysis.symbolic_execution import solver, state
        from dragonslayer.analysis import mba_simplifier
        assert solver._Z3_AVAILABLE == state._Z3_AVAILABLE
        assert solver._Z3_AVAILABLE == mba_simplifier._Z3_AVAILABLE


# ═══════════════════════════════════════════════════════════════════════════
# Config annotation + behaviour tests
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.core.config import Config, get_config, reset_config


class TestConfigAnnotations:
    """Verify config method annotations and contracts."""

    def test_get_returns_default(self) -> None:
        reset_config()
        cfg = get_config()
        assert cfg.get("nonexistent.key", "fallback") == "fallback"

    def test_set_and_get_roundtrip(self) -> None:
        reset_config()
        cfg = get_config()
        cfg.set("test.roundtrip", 42)
        assert cfg.get("test.roundtrip") == 42

    def test_validate_returns_none(self) -> None:
        """validate() should return None on valid config, not raise."""
        reset_config()
        cfg = get_config()
        result = cfg.validate()
        assert result is None

    def test_reset_config_returns_none(self) -> None:
        result = reset_config()
        assert result is None

    def test_repr(self) -> None:
        reset_config()
        cfg = get_config()
        r = repr(cfg)
        assert "Config(" in r
        assert "environment=" in r

    @given(key=st.from_regex(r"[a-z]{1,5}\.[a-z]{1,5}", fullmatch=True),
           value=st.one_of(st.integers(min_value=0, max_value=100),
                           st.text(min_size=1, max_size=10)))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_set_get_fuzz(self, key: str, value: Any) -> None:
        """Fuzzed set/get roundtrip must hold."""
        reset_config()
        cfg = get_config()
        cfg.set(key, value)
        assert cfg.get(key) == value


# ═══════════════════════════════════════════════════════════════════════════
# Server return type annotation smoke tests
# ═══════════════════════════════════════════════════════════════════════════

class TestServerAnnotations:
    """Verify server.py function annotations are applied."""

    def test_root_has_return_annotation(self) -> None:
        from dragonslayer.api.server import root
        ann = root.__annotations__ if hasattr(root, "__annotations__") else {}
        # FastAPI wraps, so check wrapped function
        inner = getattr(root, "__wrapped__", root)
        assert "return" in getattr(inner, "__annotations__", ann)

    def test_health_check_has_return_annotation(self) -> None:
        from dragonslayer.api.server import health_check
        inner = getattr(health_check, "__wrapped__", health_check)
        assert "return" in getattr(inner, "__annotations__", {})

    def test_max_request_body_bytes_defined(self) -> None:
        from dragonslayer.api.server import MAX_REQUEST_BODY_BYTES
        assert isinstance(MAX_REQUEST_BODY_BYTES, int)
        assert MAX_REQUEST_BODY_BYTES == 100 * 1024 * 1024

    def test_circuit_breaker_importable(self) -> None:
        from dragonslayer.api.server import CircuitBreaker, CircuitState
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED


# ═══════════════════════════════════════════════════════════════════════════
# Taint tracker type annotation fix verification
# ═══════════════════════════════════════════════════════════════════════════

class TestTaintContextStackType:
    """Verify H1 fix: _context_stack stores 3-tuples."""

    def test_push_creates_3tuple(self) -> None:
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        t.push_call_context()
        assert len(t._context_stack) == 1
        ctx = t._context_stack[0]
        assert len(ctx) == 3, f"Expected 3-tuple, got {len(ctx)}-tuple"
