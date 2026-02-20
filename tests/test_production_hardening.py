"""
Tests for B53 — Production Hardening.

Covers:
  1. New exception types (ResourceLimitError, AnalysisTimeoutError, ValidationError)
  2. Config-driven symbolic execution limits
  3. Comprehensive config validation
  4. Z3Solver memory_limit_mb parameter
  5. SymbolicExecutor.from_config()
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from dragonslayer.core.exceptions import (
    VMDragonSlayerError,
    ConfigurationError,
    AnalysisError,
    ResourceLimitError,
    AnalysisTimeoutError,
    ValidationError,
)
from dragonslayer.core.config import Config, reset_config


# ═══════════════════════════════════════════════════════════════════════════════
# 1. New exception types
# ═══════════════════════════════════════════════════════════════════════════════

class TestExceptionHierarchy:
    """Verify the new B53 exception types and their relationships."""

    def test_resource_limit_is_analysis_error(self):
        assert issubclass(ResourceLimitError, AnalysisError)

    def test_analysis_timeout_is_analysis_error(self):
        assert issubclass(AnalysisTimeoutError, AnalysisError)

    def test_validation_is_configuration_error(self):
        assert issubclass(ValidationError, ConfigurationError)

    def test_resource_limit_error_code(self):
        e = ResourceLimitError("Z3 OOM")
        assert e.error_code == "RESOURCE_LIMIT"
        assert str(e) == "Z3 OOM"

    def test_analysis_timeout_error_code(self):
        e = AnalysisTimeoutError("solver took too long")
        assert e.error_code == "ANALYSIS_TIMEOUT"

    def test_validation_error_fields(self):
        e = ValidationError(
            "bad field",
            field="analysis.timeout",
            constraint="must be > 0",
        )
        assert e.field == "analysis.timeout"
        assert e.constraint == "must be > 0"
        assert e.error_code == "VALIDATION_ERROR"

    def test_validation_error_inherits_details(self):
        e = ValidationError(
            "err",
            field="x",
            constraint="y",
            details={"all_errors": ["a", "b"]},
        )
        assert e.details["all_errors"] == ["a", "b"]

    def test_all_new_exceptions_are_vmds_errors(self):
        for cls in (ResourceLimitError, AnalysisTimeoutError, ValidationError):
            assert issubclass(cls, VMDragonSlayerError)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Config — symbolic_execution defaults
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigDefaults:
    """Config.DEFAULTS includes symbolic_execution section."""

    def test_defaults_has_symbolic_execution(self):
        assert "symbolic_execution" in Config.DEFAULTS

    def test_solver_timeout_default(self):
        assert Config.DEFAULTS["symbolic_execution"]["solver_timeout_ms"] == 10000

    def test_max_paths_default(self):
        assert Config.DEFAULTS["symbolic_execution"]["max_paths"] == 64

    def test_max_depth_default(self):
        assert Config.DEFAULTS["symbolic_execution"]["max_depth"] == 1000

    def test_memory_limit_default(self):
        assert Config.DEFAULTS["symbolic_execution"]["memory_limit_mb"] == 2048

    def test_max_loop_iters_default(self):
        assert Config.DEFAULTS["symbolic_execution"]["max_loop_iters"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Comprehensive config validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigValidation:
    """Test the enhanced Config.validate() method."""

    def _make_config(self, **overrides):
        """Create a Config with overridden values (bypasses YAML loading)."""
        reset_config()
        c = Config.__new__(Config)
        c.environment = "test"
        c.config_dir = None
        c._lock = __import__('threading').RLock()  # B64: required by set()
        import copy
        c._config = copy.deepcopy(Config.DEFAULTS)
        for key, val in overrides.items():
            c.set(key, val)
        return c

    def test_valid_defaults_pass(self):
        c = self._make_config()
        c.validate()  # should not raise

    def test_invalid_analysis_timeout(self):
        c = self._make_config(**{"analysis.timeout": -5})
        with pytest.raises(ValidationError) as exc_info:
            c.validate()
        assert "analysis.timeout" in str(exc_info.value)

    def test_invalid_analysis_timeout_string(self):
        c = self._make_config(**{"analysis.timeout": "fast"})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_api_port_zero(self):
        c = self._make_config(**{"api.port": 0})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_api_port_too_high(self):
        c = self._make_config(**{"api.port": 70000})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_api_workers(self):
        c = self._make_config(**{"api.workers": 0})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_logging_level(self):
        c = self._make_config(**{"logging.level": "VERBOSE"})
        with pytest.raises(ValidationError):
            c.validate()

    def test_valid_logging_levels(self):
        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            c = self._make_config(**{"logging.level": level})
            c.validate()

    def test_invalid_solver_timeout(self):
        c = self._make_config(**{"symbolic_execution.solver_timeout_ms": 50})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_max_paths(self):
        c = self._make_config(**{"symbolic_execution.max_paths": 0})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_max_depth(self):
        c = self._make_config(**{"symbolic_execution.max_depth": -1})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_memory_limit(self):
        c = self._make_config(**{"symbolic_execution.memory_limit_mb": 10})
        with pytest.raises(ValidationError):
            c.validate()

    def test_invalid_validation_threshold(self):
        c = self._make_config(**{"vmprotect.validation_threshold": 1.5})
        with pytest.raises(ValidationError):
            c.validate()

    def test_all_errors_in_details(self):
        """Multiple validation errors are collected in details."""
        c = self._make_config(**{
            "analysis.timeout": -1,
            "api.port": 0,
        })
        with pytest.raises(ValidationError) as exc_info:
            c.validate()
        details = exc_info.value.details
        assert len(details.get("all_errors", [])) >= 2

    def test_unknown_section_warns(self, caplog):
        """Unknown top-level sections produce warnings."""
        import logging
        c = self._make_config()
        c._config["bogus_section"] = {"x": 1}
        with caplog.at_level(logging.WARNING):
            c.validate()
        assert any("bogus_section" in r.message for r in caplog.records)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Z3Solver memory_limit_mb
# ═══════════════════════════════════════════════════════════════════════════════

class TestSolverLimits:
    """Test Z3Solver resource limit parameters."""

    def test_solver_default_no_memory_limit(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        s = Z3Solver()
        assert s.memory_limit_mb == 0

    def test_solver_memory_limit_stored(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        s = Z3Solver(memory_limit_mb=1024)
        assert s.memory_limit_mb == 1024

    def test_solver_timeout_stored(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        s = Z3Solver(timeout_ms=5000)
        assert s.timeout_ms == 5000


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SymbolicExecutor.from_config()
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecutorFromConfig:
    """Test SymbolicExecutor.from_config() factory method."""

    def test_from_config_with_mock(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        mock_config = MagicMock()
        mock_config.get = lambda key, default=None: {
            "symbolic_execution.max_depth": 500,
            "symbolic_execution.max_paths": 32,
            "symbolic_execution.max_loop_iters": 5,
            "symbolic_execution.solver_timeout_ms": 20000,
            "symbolic_execution.memory_limit_mb": 4096,
        }.get(key, default)

        ex = SymbolicExecutor.from_config(mock_config)
        assert ex.max_depth == 500
        assert ex.max_paths == 32
        assert ex.max_loop_iters == 5

    def test_from_config_defaults_on_none(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor.from_config()
        assert ex.max_depth in (1000, 500, 2000)  # any reasonable default
        assert ex.max_paths > 0

    def test_executor_solver_timeout_passthrough(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor(solver_timeout_ms=7777)
        assert ex._solver.timeout_ms == 7777

    def test_executor_memory_limit_passthrough(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        ex = SymbolicExecutor(memory_limit_mb=512)
        assert ex._solver.memory_limit_mb == 512


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Orchestrator pipeline timeout
# ═══════════════════════════════════════════════════════════════════════════════

class TestOrchestratorTimeout:
    """Verify _dispatch_pipeline has a timeout guard."""

    def test_dispatch_pipeline_exists(self):
        """Orchestrator._dispatch_pipeline method exists."""
        from dragonslayer.core.orchestrator import Orchestrator
        assert hasattr(Orchestrator, "_dispatch_pipeline")

    def test_dispatch_pipeline_reads_timeout(self):
        """Pipeline timeout is read from config."""
        from dragonslayer.core.orchestrator import Orchestrator
        import inspect
        src = inspect.getsource(Orchestrator._dispatch_pipeline)
        assert "analysis.timeout" in src
        assert "pipeline_timeout" in src
