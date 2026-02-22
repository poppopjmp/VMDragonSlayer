"""
B64 – Orchestrator Context Manager + Config Thread Safety
=========================================================

Tests for:
  - Orchestrator __enter__/__exit__ protocol
  - Config thread-safe get/set with RLock
  - Config generic VMDS_ env-var mapping
"""

from __future__ import annotations

import os
import threading
from unittest.mock import patch

import pytest

from dragonslayer.core.config import Config
from dragonslayer.core.orchestrator import Orchestrator


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Orchestrator context manager
# ═══════════════════════════════════════════════════════════════════════════════


class TestOrchestratorContextManager:
    def test_enter_returns_self(self):
        orch = Orchestrator()
        with orch as o:
            assert o is orch

    def test_shutdown_called_on_exit(self):
        with Orchestrator() as orch:
            assert orch._executor is not None
        # After with-block, executor should have been shut down
        assert orch._executor._shutdown

    def test_shutdown_on_exception(self):
        """Executor is shut down even if body raises."""
        try:
            with Orchestrator() as orch:
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert orch._executor._shutdown


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Config thread safety
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigThreadSafety:
    def test_has_lock(self):
        cfg = Config(validate_on_load=False)
        assert hasattr(cfg, '_lock')
        assert isinstance(cfg._lock, type(threading.RLock()))

    def test_concurrent_get_set(self):
        """Multiple threads doing get/set should not crash."""
        cfg = Config(validate_on_load=False)
        errors: list[Exception] = []

        def writer():
            try:
                for i in range(200):
                    cfg.set(f"test.key_{i % 10}", i)
            except Exception as exc:
                errors.append(exc)

        def reader():
            try:
                for i in range(200):
                    cfg.get(f"test.key_{i % 10}", "default")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Thread errors: {errors}"

    def test_get_section_is_locked(self):
        cfg = Config(validate_on_load=False)
        cfg.set("mysec.a", 1)
        section = cfg.get_section("mysec")
        assert section == {"a": 1}


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Generic VMDS_ env-var mapping
# ═══════════════════════════════════════════════════════════════════════════════


class TestGenericEnvVarMapping:
    def test_double_underscore_maps_to_dot(self):
        env = {"VMDS_SYMBOLIC_EXECUTION__MAX_PATHS": "128"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config(validate_on_load=False)
        assert cfg.get("symbolic_execution.max_paths") == 128

    def test_int_auto_parse(self):
        env = {"VMDS_ANALYSIS__TIMEOUT": "3600"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config(validate_on_load=False)
        assert cfg.get("analysis.timeout") == 3600

    def test_float_auto_parse(self):
        env = {"VMDS_VMPROTECT__VALIDATION_THRESHOLD": "0.95"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config(validate_on_load=False)
        assert cfg.get("vmprotect.validation_threshold") == 0.95

    def test_string_value_preserved(self):
        env = {"VMDS_TRACING__BACKEND": "triton"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config(validate_on_load=False)
        assert cfg.get("tracing.backend") == "triton"

    def test_single_underscore_ignored(self):
        """Keys without __ in the env var name are skipped by generic mapper."""
        env = {"VMDS_LOGGING_LEVEL": "DEBUG"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config(validate_on_load=False)
        # The legacy handler picks this up, not the generic one
        assert cfg.get("logging.level") == "DEBUG"
