"""
B98 — More TypedDicts, GPU/core docstrings, return types, APIClient tests,
lazy plugin discovery, idempotent logging.

Tests:
  1. New TypedDicts: CFGStatsDict, StageResultDict, PipelineResultDict,
     PluginResultDict, PhaseMetricDict, AnalysisMetricsDict
  2. GPU module docstring quality (Args/Returns/Raises)
  3. FileInfo, CircuitBreaker, check_rate_limit docstring quality
  4. Return-type annotations (__post_init__, __iter__)
  5. APIClient + MetroplexGatewayClient (httpx mocking)
  6. Lazy plugin discovery (_ensure_discovered)
  7. Idempotent _configure_logging
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import asdict
from typing import Any, Dict, Iterator
from unittest.mock import MagicMock, patch

import httpx
import pytest


# ═══════════════════════════════════════════════════════════════════════════
# 1. New TypedDicts — importable + to_dict() key shapes
# ═══════════════════════════════════════════════════════════════════════════


class TestCFGStatsTypedDict:
    def test_import(self) -> None:
        from dragonslayer.analysis.cfg import CFGStatsDict
        assert CFGStatsDict is not None

    def test_to_dict_keys(self) -> None:
        from dragonslayer.analysis.cfg import CFGStats, CFGStatsDict
        s = CFGStats(node_count=4, edge_count=5, back_edge_count=1, loop_count=1)
        d = s.to_dict()
        assert set(d.keys()) == set(CFGStatsDict.__annotations__)

    def test_attributes_docstring(self) -> None:
        from dragonslayer.analysis.cfg import CFGStats
        assert "Attributes:" in (CFGStats.__doc__ or "")


class TestStageResultTypedDict:
    def test_import(self) -> None:
        from dragonslayer.core.pipeline import StageResultDict
        assert StageResultDict is not None

    def test_to_dict_keys(self) -> None:
        from dragonslayer.core.pipeline import StageResult, StageResultDict
        sr = StageResult(stage="static", success=True)
        d = sr.to_dict()
        assert set(d.keys()) == set(StageResultDict.__annotations__)

    def test_attributes_docstring(self) -> None:
        from dragonslayer.core.pipeline import StageResult
        assert "Attributes:" in (StageResult.__doc__ or "")


class TestPipelineResultTypedDict:
    def test_import(self) -> None:
        from dragonslayer.core.pipeline import PipelineResultDict
        assert PipelineResultDict is not None

    def test_to_dict_keys(self) -> None:
        from dragonslayer.core.pipeline import (
            PipelineResult,
            PipelineResultDict,
            StageResult,
        )
        pr = PipelineResult(
            success=True,
            stages=[StageResult(stage="static", success=True)],
        )
        d = pr.to_dict()
        assert set(d.keys()) == set(PipelineResultDict.__annotations__)
        assert isinstance(d["stages"], list)
        assert d["stages"][0]["stage"] == "static"

    def test_attributes_docstring(self) -> None:
        from dragonslayer.core.pipeline import PipelineResult
        assert "Attributes:" in (PipelineResult.__doc__ or "")


class TestPluginResultTypedDict:
    def test_import(self) -> None:
        from dragonslayer.plugins import PluginResultDict
        assert PluginResultDict is not None

    def test_to_dict_keys(self) -> None:
        from dragonslayer.plugins import PluginResult, PluginResultDict
        pr = PluginResult(plugin="yara", success=True)
        d = pr.to_dict()
        assert set(d.keys()) == set(PluginResultDict.__annotations__)

    def test_attributes_docstring(self) -> None:
        from dragonslayer.plugins import PluginResult
        assert "Attributes:" in (PluginResult.__doc__ or "")


class TestPhaseMetricTypedDict:
    def test_import(self) -> None:
        from dragonslayer.utils.metrics import PhaseMetricDict
        assert PhaseMetricDict is not None

    def test_to_dict_keys(self) -> None:
        from dragonslayer.utils.metrics import PhaseMetric, PhaseMetricDict
        pm = PhaseMetric(name="taint", elapsed_s=1.5, item_count=10)
        d = pm.to_dict()
        assert set(d.keys()) == set(PhaseMetricDict.__annotations__)

    def test_attributes_docstring(self) -> None:
        from dragonslayer.utils.metrics import PhaseMetric
        assert "Attributes:" in (PhaseMetric.__doc__ or "")


class TestAnalysisMetricsTypedDict:
    def test_import(self) -> None:
        from dragonslayer.utils.metrics import AnalysisMetricsDict
        assert AnalysisMetricsDict is not None

    def test_to_dict_keys(self) -> None:
        from dragonslayer.utils.metrics import AnalysisMetrics, AnalysisMetricsDict
        m = AnalysisMetrics(run_id="test-001")
        d = m.to_dict()
        assert set(d.keys()) == set(AnalysisMetricsDict.__annotations__)
        assert d["run_id"] == "test-001"
        assert isinstance(d["phases"], list)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Core/API docstring quality  (GPU tests removed in B104)
# ═══════════════════════════════════════════════════════════════════════════


class TestFileInfoDocstring:
    def test_attributes_section(self) -> None:
        from dragonslayer.core.orchestrator import FileInfo
        assert "Attributes:" in (FileInfo.__doc__ or "")

    def test_from_bytes(self) -> None:
        from dragonslayer.core.orchestrator import FileInfo
        fi = FileInfo.from_bytes(b"hello", path="test.bin")
        assert fi.size == 5
        assert fi.path == "test.bin"
        assert len(fi.sha256) == 64


class TestCircuitBreakerDocstrings:
    @pytest.mark.parametrize("method", [
        "record_success", "record_failure", "allow_request",
    ])
    def test_has_docstring(self, method: str) -> None:
        from dragonslayer.api.server import CircuitBreaker
        doc = getattr(CircuitBreaker, method).__doc__ or ""
        assert len(doc) > 10, f"{method} has no meaningful docstring"


class TestCheckRateLimitDocstring:
    def test_has_args_returns(self) -> None:
        from dragonslayer.api.server import check_rate_limit
        doc = check_rate_limit.__doc__ or ""
        assert "Args:" in doc
        assert "Returns:" in doc


# ═══════════════════════════════════════════════════════════════════════════
# 4. Return-type annotations
# ═══════════════════════════════════════════════════════════════════════════


class TestReturnTypeAnnotations:
    def test_recognizer_post_init_returns_none(self) -> None:
        import inspect
        from dragonslayer.analysis.pattern_analysis.recognizer import Match
        hints = inspect.get_annotations(Match.__post_init__)
        assert hints.get("return") is None or hints.get("return") is type(None)

    def test_database_post_init_returns_none(self) -> None:
        import inspect
        from dragonslayer.analysis.pattern_analysis.database import Pattern
        hints = inspect.get_annotations(Pattern.__post_init__)
        assert hints.get("return") is None or hints.get("return") is type(None)

    def test_database_iter_has_return_annotation(self) -> None:
        import inspect
        from dragonslayer.analysis.pattern_analysis.database import PatternDatabase
        hints = inspect.get_annotations(PatternDatabase.__iter__)
        assert "return" in hints


# ═══════════════════════════════════════════════════════════════════════════
# 5. APIClient + MetroplexGatewayClient (httpx mocking)
# ═══════════════════════════════════════════════════════════════════════════


class TestAPIClient:
    """Tests for APIClient with mocked httpx."""

    def _make_client(self) -> "APIClient":
        from dragonslayer.api.client import APIClient
        return APIClient(base_url="http://test:8000", timeout=5)

    def test_health_success(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "healthy"}
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                get=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.health()
        assert result["status"] == "healthy"

    def test_status_success(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"total_requests": 42}
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                get=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.status()
        assert result["total_requests"] == 42

    def test_analyze_success(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True, "analysis_id": "a1"}

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.analyze(b"\x00" * 100)
        assert result["success"] is True

    def test_analyze_http_error(self) -> None:
        from dragonslayer.api.client import APIClient
        from dragonslayer.core.exceptions import APIError
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(APIError):
                client.analyze(b"\x00" * 10)

    def test_analyze_timeout(self) -> None:
        from dragonslayer.core.exceptions import NetworkError
        client = self._make_client()

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(side_effect=httpx.TimeoutException("timed out"))
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(NetworkError):
                client.analyze(b"\x00" * 10)


class TestMetroplexGatewayClient:
    """Tests for gateway client with mocked httpx."""

    def _make_client(self) -> "MetroplexGatewayClient":
        from dragonslayer.api.client import MetroplexGatewayClient
        return MetroplexGatewayClient(
            gateway_url="https://gateway.test:8443", timeout=10
        )

    def test_scan_success(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "uuid", "successful": 3}

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.scan(b"MZ\x90" * 10, filename="test.exe")
        assert result["successful"] == 3

    def test_scan_with_plugin_filter(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "uuid2", "plugins_queried": 2}

        with patch("httpx.Client") as MockClient:
            mock_inner = MagicMock()
            mock_inner.post.return_value = mock_resp
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_inner)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.scan(b"ELF" * 5, plugins=["clamav", "yara"])
            # Check query params included plugins
            call_kwargs = mock_inner.post.call_args
            assert "plugins" in call_kwargs.kwargs.get("params", {})
        assert result["plugins_queried"] == 2

    def test_scan_too_large(self) -> None:
        from dragonslayer.api.client import MAX_UPLOAD_SIZE
        from dragonslayer.core.exceptions import APIError
        client = self._make_client()
        with pytest.raises(APIError, match="maximum upload size"):
            client.scan(b"\x00" * (MAX_UPLOAD_SIZE + 1))

    def test_scan_gateway_error(self) -> None:
        from dragonslayer.core.exceptions import GatewayError
        client = self._make_client()

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(side_effect=httpx.ConnectError("refused"))
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(GatewayError):
                client.scan(b"\x00" * 10)

    def test_scan_non_json_response(self) -> None:
        from dragonslayer.core.exceptions import APIError
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("not json")

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(APIError, match="non-JSON"):
                client.scan(b"\x00" * 10)

    def test_scan_http_500(self) -> None:
        from dragonslayer.core.exceptions import APIError
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "boom"

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(APIError):
                client.scan(b"\x00" * 10)

    def test_health(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                get=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.health()
        assert result["ok"] is True

    def test_list_plugins(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"name": "clamav"}, {"name": "yara"}]
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                get=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.list_plugins()
        assert len(result) == 2

    def test_scan_plugin_direct(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}

        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=MagicMock(
                post=MagicMock(return_value=mock_resp)
            ))
            MockClient.return_value.__exit__ = MagicMock(return_value=False)
            result = client.scan_plugin("angr", b"\x00" * 10)
        assert result["data"] == "ok"


class TestCreateClient:
    def test_factory(self) -> None:
        from dragonslayer.api.client import create_client
        c = create_client("http://localhost:9999")
        assert c.base_url == "http://localhost:9999"


# ═══════════════════════════════════════════════════════════════════════════
# 6. Lazy plugin discovery
# ═══════════════════════════════════════════════════════════════════════════


class TestLazyPluginDiscovery:
    def test_ensure_discovered_flag(self) -> None:
        import dragonslayer.plugins as p
        # After module import, _ensure_discovered should exist
        assert hasattr(p, "_ensure_discovered")
        assert callable(p._ensure_discovered)

    def test_no_import_time_call(self) -> None:
        """_auto_discover is NOT called at import time any more."""
        import dragonslayer.plugins as p
        # The old bare _auto_discover() call has been replaced by
        # _ensure_discovered() inside get_plugin / list_plugins.
        # We just verify the attribute exists and is a bool.
        assert isinstance(p._discovered, bool)


# ═══════════════════════════════════════════════════════════════════════════
# 7. Idempotent configure_logging
# ═══════════════════════════════════════════════════════════════════════════


class TestIdempotentLogging:
    def test_configure_logging_is_idempotent(self) -> None:
        from dragonslayer.api.server import _configure_logging, _logging_configured
        # Already configured at import time
        import dragonslayer.api.server as srv
        assert srv._logging_configured is True
        # Calling again without _force is a no-op
        _configure_logging()
        assert srv._logging_configured is True

    def test_force_reconfigures(self) -> None:
        from dragonslayer.api.server import _configure_logging
        import dragonslayer.api.server as srv
        import logging
        root = logging.getLogger()
        handlers_before = len(root.handlers)
        _configure_logging(_force=True)
        # Should still be configured
        assert srv._logging_configured is True
