"""
B96 — EngineHandler Protocol, executor TypedDicts, docstring quality,
       deep health check & graceful shutdown.

Tests:
  1. EngineHandler Protocol structural checks
  2. Executor TypedDict shapes validated on actual to_dict() output
  3. Recognizer docstring completeness
  4. Solver docstring completeness
  5. Tracker docstring completeness
  6. Deep health endpoint (components dict)
  7. Graceful shutdown drain constant
"""

from __future__ import annotations

import inspect
import re
from typing import Any, Dict, get_type_hints

import pytest

# ---------------------------------------------------------------------------
# 1. EngineHandler Protocol
# ---------------------------------------------------------------------------


class TestEngineHandlerProtocol:
    """Verify EngineHandler Protocol is importable and structurally correct."""

    def test_import_protocol(self) -> None:
        from dragonslayer.core.orchestrator import EngineHandler
        assert hasattr(EngineHandler, "__call__")

    def test_protocol_is_runtime_checkable(self) -> None:
        from dragonslayer.core.orchestrator import EngineHandler
        # runtime_checkable allows isinstance() checks
        assert hasattr(EngineHandler, "__protocol_attrs__") or hasattr(
            EngineHandler, "_is_runtime_protocol"
        )

    def test_plain_callable_satisfies_protocol(self) -> None:
        from dragonslayer.core.orchestrator import (
            AnalysisRequest,
            EngineHandler,
            EngineResult,
        )

        def handler(request: AnalysisRequest) -> EngineResult:
            return EngineResult(engine="test", success=True)

        # isinstance check on runtime_checkable Protocol
        assert isinstance(handler, EngineHandler)

    def test_engine_handler_exported_from_core(self) -> None:
        from dragonslayer.core import EngineHandler, EngineResult
        assert EngineHandler is not None
        assert EngineResult is not None

    def test_engine_result_in_all(self) -> None:
        import dragonslayer.core as core
        assert "EngineHandler" in core.__all__
        assert "EngineResult" in core.__all__

    def test_get_engine_handler_return_type_annotation(self) -> None:
        from dragonslayer.core.orchestrator import Orchestrator
        sig = inspect.signature(Orchestrator._get_engine_handler)
        ret = sig.return_annotation
        # Should reference EngineHandler (not the old Callable string)
        assert "EngineHandler" in str(ret)


# ---------------------------------------------------------------------------
# 2. Executor TypedDicts
# ---------------------------------------------------------------------------


class TestExecutorTypedDicts:
    """Validate TypedDicts exist and to_dict() output conforms."""

    def test_handler_info_dict_importable(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import HandlerInfoDict
        assert HandlerInfoDict is not None

    def test_execution_result_dict_importable(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import ExecutionResultDict
        assert ExecutionResultDict is not None

    def test_handler_symbolic_summary_dict_importable(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import HandlerSymbolicSummaryDict
        assert HandlerSymbolicSummaryDict is not None

    def test_loop_info_dict_importable(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import LoopInfoDict
        assert LoopInfoDict is not None

    def test_handler_info_to_dict_keys(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import HandlerInfo, HandlerInfoDict
        hi = HandlerInfo(address=0x1000, category="vadd", instruction_count=5)
        d = hi.to_dict()
        expected_keys = set(HandlerInfoDict.__annotations__)
        assert set(d.keys()) == expected_keys

    def test_execution_result_to_dict_keys(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import ExecutionResult, ExecutionResultDict
        er = ExecutionResult(success=True)
        d = er.to_dict()
        td_keys = set(ExecutionResultDict.__annotations__)
        # to_dict() output must be a subset of the TypedDict keys
        assert set(d.keys()).issubset(td_keys)

    def test_handler_symbolic_summary_to_dict_keys(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import (
            HandlerSymbolicSummary,
            HandlerSymbolicSummaryDict,
        )
        hss = HandlerSymbolicSummary(address=0x2000, instruction_count=3)
        d = hss.to_dict()
        td_keys = set(HandlerSymbolicSummaryDict.__annotations__)
        assert set(d.keys()).issubset(td_keys)

    def test_loop_info_to_dict_keys(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import LoopInfo, LoopInfoDict
        li = LoopInfo(header_address=0x3000, back_edge_sources=[0x3010])
        d = li.to_dict()
        expected_keys = set(LoopInfoDict.__annotations__)
        assert set(d.keys()) == expected_keys

    def test_handler_info_to_dict_values(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import HandlerInfo
        hi = HandlerInfo(
            address=0x1000,
            category="vmov",
            instruction_count=3,
            reads=["rax"],
            writes=["rbx"],
            confidence=0.95,
        )
        d = hi.to_dict()
        assert d["address"] == 0x1000
        assert d["category"] == "vmov"
        assert d["reads"] == ["rax"]
        assert d["confidence"] == 0.95

    def test_execution_result_handler_nesting(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import (
            ExecutionResult,
            HandlerInfo,
        )
        hi = HandlerInfo(address=0x100, category="vadd", instruction_count=2)
        er = ExecutionResult(success=True, handlers=[hi])
        d = er.to_dict()
        assert isinstance(d["handlers"], list)
        assert d["handlers"][0]["category"] == "vadd"

    def test_loop_info_hex_addresses(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import LoopInfo
        li = LoopInfo(header_address=0xDEAD, back_edge_sources=[0xBEEF])
        d = li.to_dict()
        assert d["header_address"] == hex(0xDEAD)
        assert d["back_edge_sources"] == [hex(0xBEEF)]


# ---------------------------------------------------------------------------
# 3. Executor dataclass Attributes docstrings
# ---------------------------------------------------------------------------


class TestExecutorDocstrings:
    """Ensure executor dataclass docstrings have Attributes sections."""

    @pytest.mark.parametrize(
        "cls_name",
        ["HandlerInfo", "ExecutionResult", "HandlerSymbolicSummary", "LoopInfo"],
    )
    def test_has_attributes_section(self, cls_name: str) -> None:
        import dragonslayer.analysis.symbolic_execution.executor as mod
        cls = getattr(mod, cls_name)
        doc = cls.__doc__ or ""
        assert "Attributes:" in doc, f"{cls_name} missing Attributes section"


# ---------------------------------------------------------------------------
# 4. Recognizer docstring completeness
# ---------------------------------------------------------------------------


class TestRecognizerDocstrings:
    """All previously-skeleton docstrings must now have Args/Returns."""

    _METHODS = [
        "recognize_single", "_match_pattern", "_try_match",
        "_exact_match", "_regex_match", "_signature_to_regex",
        "_normalize_bytes", "_format_bytes", "get_statistics",
    ]

    @pytest.mark.parametrize("method_name", _METHODS)
    def test_recognizer_docstring_has_body(self, method_name: str) -> None:
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        fn = getattr(PatternRecognizer, method_name)
        doc = fn.__doc__ or ""
        # Must have either Args: or Returns: section
        assert "Args:" in doc or "Returns:" in doc, (
            f"PatternRecognizer.{method_name} still has skeleton docstring"
        )

    _SEQ_METHODS = ["recognize_sequence", "_deduplicate_matches", "_ranges_overlap"]

    @pytest.mark.parametrize("method_name", _SEQ_METHODS)
    def test_sequence_recognizer_docstring(self, method_name: str) -> None:
        from dragonslayer.analysis.pattern_analysis.recognizer import SequenceRecognizer
        fn = getattr(SequenceRecognizer, method_name)
        doc = fn.__doc__ or ""
        assert "Args:" in doc or "Returns:" in doc, (
            f"SequenceRecognizer.{method_name} still has skeleton docstring"
        )


# ---------------------------------------------------------------------------
# 5. Solver docstring completeness
# ---------------------------------------------------------------------------


class TestSolverDocstrings:
    """Solver methods that had single-line docstrings must now have Args/Returns."""

    _METHODS = ["bitvec", "bitvec_val", "add", "push", "pop", "simplify"]

    @pytest.mark.parametrize("method_name", _METHODS)
    def test_solver_docstring_has_body(self, method_name: str) -> None:
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        fn = getattr(Z3Solver, method_name)
        doc = fn.__doc__ or ""
        assert "Args:" in doc or "Returns:" in doc or "Raises:" in doc, (
            f"Z3Solver.{method_name} still has skeleton docstring"
        )


# ---------------------------------------------------------------------------
# 6. Tracker docstring completeness
# ---------------------------------------------------------------------------


class TestTrackerDocstrings:
    """Tracker module functions and MemoryAliasTracker methods."""

    _FUNCS = [
        "is_eflags_producer", "is_eflags_consumer",
        "subreg_canonical", "subreg_aliases", "subreg_info",
    ]

    @pytest.mark.parametrize("func_name", _FUNCS)
    def test_module_func_docstring(self, func_name: str) -> None:
        import dragonslayer.analysis.taint_tracking.tracker as mod
        fn = getattr(mod, func_name)
        doc = fn.__doc__ or ""
        assert "Args:" in doc or "Returns:" in doc, (
            f"tracker.{func_name} still has skeleton docstring"
        )

    _MAT_METHODS = ["bind", "unbind", "resolve", "must_alias", "aliases_of"]

    @pytest.mark.parametrize("method_name", _MAT_METHODS)
    def test_memory_alias_tracker_docstring(self, method_name: str) -> None:
        from dragonslayer.analysis.taint_tracking.tracker import MemoryAliasTracker
        fn = getattr(MemoryAliasTracker, method_name)
        doc = fn.__doc__ or ""
        assert "Args:" in doc or "Returns:" in doc, (
            f"MemoryAliasTracker.{method_name} still has skeleton docstring"
        )


# ---------------------------------------------------------------------------
# 7. Server deep health check & graceful shutdown
# ---------------------------------------------------------------------------


class TestDeepHealthCheck:
    """Verify the enhanced /health endpoint returns dependency probes."""

    @pytest.mark.anyio
    async def test_health_returns_components(self) -> None:
        import httpx
        from dragonslayer.api.server import app
        transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert "components" in body
        assert isinstance(body["components"], dict)

    @pytest.mark.anyio
    async def test_health_components_keys(self) -> None:
        import httpx
        from dragonslayer.api.server import app
        transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/health")
        components = r.json()["components"]
        assert "api" in components
        assert "pattern_db" in components

    @pytest.mark.anyio
    async def test_health_status_values(self) -> None:
        import httpx
        from dragonslayer.api.server import app
        transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/health")
        body = r.json()
        # status should be either 'healthy' or 'degraded'
        assert body["status"] in ("healthy", "degraded")


class TestGracefulShutdown:
    """Check the drain constant and lifespan docstring."""

    def test_shutdown_drain_constant_exists(self) -> None:
        from dragonslayer.api.server import _SHUTDOWN_DRAIN_SECONDS
        assert isinstance(_SHUTDOWN_DRAIN_SECONDS, float)
        assert _SHUTDOWN_DRAIN_SECONDS > 0

    def test_lifespan_mentions_drain(self) -> None:
        from dragonslayer.api.server import lifespan
        doc = lifespan.__doc__ or ""
        assert "drain" in doc.lower() or "in-flight" in doc.lower()

    def test_health_response_model_has_components(self) -> None:
        from dragonslayer.api.server import HealthResponse
        fields = HealthResponse.model_fields
        assert "components" in fields
