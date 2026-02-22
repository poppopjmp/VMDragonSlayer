"""
B95 – End-to-end API tests using ``httpx.AsyncClient`` with ``ASGITransport``.

These tests exercise the **actual** FastAPI routes through a real ASGI call
stack (middleware → exception handlers → route handlers) without starting a
server process.  This is the gold-standard approach for testing FastAPI apps.

Coverage targets:
  - GET  /           → root info
  - GET  /health     → HealthResponse
  - GET  /status     → StatusResponse
  - GET  /metrics    → metric counters
  - GET  /analysis-types → supported types
  - POST /analyze    → base64 analysis flow
  - POST /analyze    → invalid base64 → 422
  - POST /analyze    → oversized body → 413
  - POST /upload-analyze → multipart upload
  - Rate limiting    → 429 after burst
  - API key auth     → 401 when key is wrong
  - Request-ID       → X-Request-ID header propagation
  - Circuit breaker  → state check
  - Body size limit  → middleware rejects oversized Content-Length
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from typing import Any, Dict
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

# ---------------------------------------------------------------------------
# httpx + ASGITransport (requires httpx ≥ 0.23)
# ---------------------------------------------------------------------------
httpx = pytest.importorskip("httpx")
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Import the FastAPI app + server-level objects
# ---------------------------------------------------------------------------
from dragonslayer.api.server import (
    app,
    server_state,
    circuit_breaker,
    CircuitState,
    MAX_REQUEST_BODY_BYTES,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW,
    _counter_lock,
    _rate_lock,
    AnalysisRequest as ServerAnalysisRequest,
    AnalysisResponse,
    HealthResponse,
    StatusResponse,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _reset_server_state():
    """Reset mutable server state between tests so they are independent."""
    def _reset() -> None:
        server_state.start_time = time.time()
        server_state.total_requests = 0
        server_state.active_requests = 0
        server_state.analysis_count = 0
        server_state.api = None
        server_state.rate_limiter.clear()

    _reset()
    # Reset circuit breaker to CLOSED
    circuit_breaker._state = CircuitState.CLOSED
    circuit_breaker._failure_count = 0
    circuit_breaker._last_failure_time = 0.0
    yield
    _reset()


def _make_mock_api() -> MagicMock:
    """Return a mock VMDragonSlayerAPI that returns a valid result dict."""
    mock = MagicMock()
    mock.get_supported_analysis_types.return_value = [
        "hybrid", "pattern_analysis", "vm_discovery",
    ]
    _result = {
        "success": True,
        "analysis_id": "test-id-1234",
        "timestamp": "2025-01-01T00:00:00Z",
        "file_info": {"size": 4, "sha256": "abc"},
        "analysis_type": "hybrid",
        "results": {"pattern_analysis": {}},
        "execution_time": 0.01,
        "errors": [],
    }
    mock.analyze_binary_data.return_value = _result
    # Server endpoints now use the async variant
    mock.analyze_binary_data_async = AsyncMock(return_value=_result)
    # Pipeline endpoint
    _pipeline_result: Dict[str, Any] = {
        "success": True,
        "stages": [],
        "shared_data": {},
        "llm_insights": {},
        "total_duration": 0.05,
        "errors": [],
    }
    mock.run_pipeline_async = AsyncMock(return_value=_pipeline_result)
    mock.shutdown.return_value = None
    return mock


@pytest.fixture()
def mock_api():
    """Inject a mock API into server_state for route tests."""
    mock = _make_mock_api()
    server_state.api = mock
    yield mock
    server_state.api = None


# ---------------------------------------------------------------------------
# Transport helper
# ---------------------------------------------------------------------------

def _client(**kwargs: Any) -> AsyncClient:
    """Create an ``AsyncClient`` wired to the FastAPI ASGI app."""
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    return AsyncClient(transport=transport, base_url="http://testserver", **kwargs)


# ═══════════════════════════════════════════════════════════════════════════════
# Route tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRootEndpoint:
    """GET /"""

    @pytest.mark.anyio
    async def test_root_returns_api_info(self):
        async with _client() as c:
            resp = await c.get("/")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "VMDragonSlayer API"
        assert "endpoints" in body

    @pytest.mark.anyio
    async def test_root_lists_all_endpoints(self):
        async with _client() as c:
            resp = await c.get("/")
        endpoints = resp.json()["endpoints"]
        for key in ("health", "status", "metrics", "analyze", "docs"):
            assert key in endpoints


class TestHealthEndpoint:
    """GET /health"""

    @pytest.mark.anyio
    async def test_health_returns_healthy(self):
        async with _client() as c:
            resp = await c.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] in ("healthy", "degraded")
        assert "timestamp" in body
        assert body["version"] == "2025.10"

    @pytest.mark.anyio
    async def test_health_matches_response_model(self):
        async with _client() as c:
            resp = await c.get("/health")
        # Validate against the Pydantic model
        h = HealthResponse(**resp.json())
        assert h.status in ("healthy", "degraded")


class TestStatusEndpoint:
    """GET /status"""

    @pytest.mark.anyio
    async def test_status_operational(self, mock_api):
        async with _client() as c:
            resp = await c.get("/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "operational"
        assert body["version"] == "2025.10"
        assert "uptime_seconds" in body
        assert isinstance(body["supported_types"], list)

    @pytest.mark.anyio
    async def test_status_without_api(self):
        """When API is None, supported_types should be an empty list."""
        server_state.api = None
        async with _client() as c:
            resp = await c.get("/status")
        assert resp.status_code == 200
        assert resp.json()["supported_types"] == []


class TestMetricsEndpoint:
    """GET /metrics"""

    @pytest.mark.anyio
    async def test_metrics_returns_counters(self, mock_api):
        async with _client() as c:
            resp = await c.get("/metrics")
        assert resp.status_code == 200
        body = resp.json()
        assert "vmds_uptime_seconds" in body
        assert "vmds_total_requests" in body
        assert "vmds_active_requests" in body
        assert "vmds_analysis_count" in body

    @pytest.mark.anyio
    async def test_metrics_uptime_positive(self, mock_api):
        async with _client() as c:
            resp = await c.get("/metrics")
        assert resp.json()["vmds_uptime_seconds"] >= 0


class TestAnalysisTypesEndpoint:
    """GET /analysis-types"""

    @pytest.mark.anyio
    async def test_analysis_types_list(self, mock_api):
        async with _client() as c:
            resp = await c.get("/analysis-types")
        assert resp.status_code == 200
        body = resp.json()
        assert "supported_types" in body
        assert "descriptions" in body
        assert "hybrid" in body["descriptions"]


class TestAnalyzeEndpoint:
    """POST /analyze"""

    @pytest.mark.anyio
    async def test_analyze_valid_base64(self, mock_api):
        payload = {
            "sample_data": base64.b64encode(b"\x4d\x5a\x90\x00").decode(),
            "analysis_type": "hybrid",
            "options": {},
            "metadata": {},
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["analysis_id"] == "test-id-1234"
        mock_api.analyze_binary_data_async.assert_called_once()

    @pytest.mark.anyio
    async def test_analyze_invalid_base64_rejected(self, mock_api):
        payload = {
            "sample_data": "!!!not-base64!!!",
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        # Pydantic validation rejects bad base64 → 422
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_analyze_missing_sample_data(self, mock_api):
        payload = {"analysis_type": "hybrid"}
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_analyze_counts_requests(self, mock_api):
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            await c.post("/analyze", json=payload)
        assert server_state.analysis_count >= 1


class TestUploadAnalyzeEndpoint:
    """POST /upload-analyze"""

    @pytest.mark.anyio
    async def test_upload_analyze_valid_file(self, mock_api):
        binary_data = b"\x4d\x5a\x90\x00"
        async with _client() as c:
            resp = await c.post(
                "/upload-analyze",
                files={"file": ("test.exe", binary_data, "application/octet-stream")},
                params={"analysis_type": "hybrid"},
            )
        assert resp.status_code == 200
        mock_api.analyze_binary_data_async.assert_called_once()
        call_kwargs = mock_api.analyze_binary_data_async.call_args
        # Verify metadata propagated filename
        meta = call_kwargs.kwargs.get("metadata") or call_kwargs[1].get("metadata", {})
        if meta:
            assert meta.get("filename") == "test.exe"

    @pytest.mark.anyio
    async def test_upload_missing_file_rejected(self, mock_api):
        async with _client() as c:
            resp = await c.post("/upload-analyze")
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline endpoint tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPipelineEndpoint:
    """POST /pipeline — configurable analysis pipeline."""

    @pytest.mark.anyio
    async def test_pipeline_default_stages(self, mock_api):
        """Full pipeline with default stage list."""
        payload = {
            "sample_data": base64.b64encode(b"\x4d\x5a\x90\x00").decode(),
        }
        async with _client() as c:
            resp = await c.post("/pipeline", json=payload)
        assert resp.status_code == 200
        mock_api.run_pipeline_async.assert_called_once()
        body = resp.json()
        assert body["success"] is True

    @pytest.mark.anyio
    async def test_pipeline_custom_stages(self, mock_api):
        """Subset of stages with custom timeout."""
        payload = {
            "sample_data": base64.b64encode(b"\x4d\x5a").decode(),
            "stages": ["pattern_analysis", "static", "reporting"],
            "timeout": 120,
            "max_workers": 2,
            "llm_enabled": False,
        }
        async with _client() as c:
            resp = await c.post("/pipeline", json=payload)
        assert resp.status_code == 200
        call_kwargs = mock_api.run_pipeline_async.call_args
        assert call_kwargs.kwargs["stages"] == [
            "pattern_analysis", "static", "reporting",
        ]
        assert call_kwargs.kwargs["llm_enabled"] is False
        assert call_kwargs.kwargs["max_workers"] == 2
        assert call_kwargs.kwargs["timeout"] == 120

    @pytest.mark.anyio
    async def test_pipeline_invalid_stage_rejected(self, mock_api):
        """Invalid stage name triggers 422."""
        payload = {
            "sample_data": base64.b64encode(b"\x00").decode(),
            "stages": ["pattern_analysis", "not_a_real_stage"],
        }
        async with _client() as c:
            resp = await c.post("/pipeline", json=payload)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_pipeline_invalid_base64_rejected(self, mock_api):
        payload = {"sample_data": "!!!not-base64!!!"}
        async with _client() as c:
            resp = await c.post("/pipeline", json=payload)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_pipeline_metadata_forwarded(self, mock_api):
        payload = {
            "sample_data": base64.b64encode(b"\xDE\xAD").decode(),
            "metadata": {"source": "unit-test", "tag": "phase2c"},
        }
        async with _client() as c:
            resp = await c.post("/pipeline", json=payload)
        assert resp.status_code == 200
        call_kwargs = mock_api.run_pipeline_async.call_args
        assert call_kwargs.kwargs["metadata"] == {
            "source": "unit-test",
            "tag": "phase2c",
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Middleware tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRequestIDMiddleware:
    """X-Request-ID propagation."""

    @pytest.mark.anyio
    async def test_request_id_generated(self):
        async with _client() as c:
            resp = await c.get("/health")
        assert "x-request-id" in resp.headers

    @pytest.mark.anyio
    async def test_request_id_echoed(self):
        custom_id = "my-custom-trace-id-999"
        async with _client() as c:
            resp = await c.get("/health", headers={"x-request-id": custom_id})
        assert resp.headers["x-request-id"] == custom_id


class TestBodySizeLimitMiddleware:
    """Content-Length rejection middleware."""

    @pytest.mark.anyio
    async def test_oversized_content_length_rejected(self, mock_api):
        # Send a request with Content-Length > MAX_REQUEST_BODY_BYTES
        huge_size = str(MAX_REQUEST_BODY_BYTES + 1)
        async with _client() as c:
            resp = await c.post(
                "/analyze",
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "content-length": huge_size,
                },
            )
        assert resp.status_code == 413


class TestRateLimiting:
    """Rate-limit enforcement."""

    @pytest.mark.anyio
    async def test_rate_limit_triggers_429(self, mock_api):
        """Burst more than RATE_LIMIT_REQUESTS → 429."""
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            # We need to exceed the rate limit
            got_429 = False
            for _ in range(RATE_LIMIT_REQUESTS + 5):
                resp = await c.post("/analyze", json=payload)
                if resp.status_code == 429:
                    got_429 = True
                    break
            assert got_429, "Expected 429 after exceeding rate limit"


class TestAPIKeyAuth:
    """API key middleware."""

    @pytest.mark.anyio
    async def test_no_key_required_when_unset(self, mock_api):
        """When VMDS_API_KEY is empty, all routes are accessible."""
        async with _client() as c:
            resp = await c.get("/analysis-types")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_public_paths_bypass_auth(self, mock_api):
        """Public paths (/health, /) should never require a key."""
        # Temporarily set the API_KEY
        import dragonslayer.api.server as srv
        old_key = srv.API_KEY
        srv.API_KEY = "secret-test-key-123"
        try:
            async with _client() as c:
                resp = await c.get("/health")
            assert resp.status_code == 200
            async with _client() as c:
                resp = await c.get("/")
            assert resp.status_code == 200
        finally:
            srv.API_KEY = old_key

    @pytest.mark.anyio
    async def test_protected_route_rejects_bad_key(self, mock_api):
        """Non-public route should return 401 with wrong key."""
        import dragonslayer.api.server as srv
        old_key = srv.API_KEY
        srv.API_KEY = "secret-test-key-123"
        try:
            async with _client() as c:
                resp = await c.get("/analysis-types", headers={"x-api-key": "wrong"})
            assert resp.status_code == 401
        finally:
            srv.API_KEY = old_key

    @pytest.mark.anyio
    async def test_protected_route_accepts_correct_key(self, mock_api):
        """Non-public route should succeed with the correct key."""
        import dragonslayer.api.server as srv
        old_key = srv.API_KEY
        srv.API_KEY = "secret-test-key-123"
        try:
            async with _client() as c:
                resp = await c.get(
                    "/analysis-types",
                    headers={"x-api-key": "secret-test-key-123"},
                )
            assert resp.status_code == 200
        finally:
            srv.API_KEY = old_key


class TestCircuitBreaker:
    """Circuit breaker middleware."""

    @pytest.mark.anyio
    async def test_circuit_closed_by_default(self):
        assert circuit_breaker.state == CircuitState.CLOSED

    @pytest.mark.anyio
    async def test_circuit_open_rejects_requests(self, mock_api):
        """When circuit is open, non-health routes get 503."""
        circuit_breaker._state = CircuitState.OPEN
        circuit_breaker._last_failure_time = time.time()  # recent failure
        async with _client() as c:
            resp = await c.get("/analysis-types")
        assert resp.status_code == 503
        body = resp.json()
        assert "circuit breaker" in body["detail"].lower()

    @pytest.mark.anyio
    async def test_circuit_open_allows_health(self, mock_api):
        """Health / status / metrics bypass the circuit breaker."""
        circuit_breaker._state = CircuitState.OPEN
        circuit_breaker._last_failure_time = time.time()
        async with _client() as c:
            resp = await c.get("/health")
        assert resp.status_code == 200


class TestRequestCounting:
    """Request counting middleware."""

    @pytest.mark.anyio
    async def test_total_requests_incremented(self):
        async with _client() as c:
            await c.get("/health")
            await c.get("/health")
        assert server_state.total_requests >= 2

    @pytest.mark.anyio
    async def test_active_requests_returns_to_zero(self):
        async with _client() as c:
            await c.get("/health")
        assert server_state.active_requests == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Exception handler tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestExceptionHandlers:
    """Verify custom exception handlers produce correct HTTP responses."""

    @pytest.mark.anyio
    async def test_invalid_data_error_returns_400(self, mock_api):
        from dragonslayer.core.exceptions import InvalidDataError
        mock_api.analyze_binary_data_async.side_effect = InvalidDataError("bad input")
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 400
        assert resp.json()["error"] == "Invalid data"

    @pytest.mark.anyio
    async def test_analysis_error_returns_500(self, mock_api):
        from dragonslayer.core.exceptions import AnalysisError
        mock_api.analyze_binary_data_async.side_effect = AnalysisError("engine crash")
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 500
        assert resp.json()["error"] == "Analysis failed"

    @pytest.mark.anyio
    async def test_configuration_error_returns_500(self, mock_api):
        from dragonslayer.core.exceptions import ConfigurationError
        mock_api.analyze_binary_data_async.side_effect = ConfigurationError("bad config")
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 500
        assert resp.json()["error"] == "Configuration error"

    @pytest.mark.anyio
    async def test_resource_limit_returns_503(self, mock_api):
        from dragonslayer.core.exceptions import ResourceLimitError
        mock_api.analyze_binary_data_async.side_effect = ResourceLimitError("oom")
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 503

    @pytest.mark.anyio
    async def test_analysis_timeout_returns_504(self, mock_api):
        from dragonslayer.core.exceptions import AnalysisTimeoutError
        mock_api.analyze_binary_data_async.side_effect = AnalysisTimeoutError("too slow")
        payload = {
            "sample_data": base64.b64encode(b"\x00" * 4).decode(),
            "analysis_type": "hybrid",
        }
        async with _client() as c:
            resp = await c.post("/analyze", json=payload)
        assert resp.status_code == 504


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic model validation tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPydanticModels:
    """Verify request/response model constraints."""

    def test_analysis_request_valid(self):
        req = ServerAnalysisRequest(
            sample_data=base64.b64encode(b"\x00").decode(),
            analysis_type="hybrid",
        )
        assert req.analysis_type == "hybrid"

    def test_analysis_request_rejects_bad_base64(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            ServerAnalysisRequest(sample_data="!!!invalid!!!", analysis_type="hybrid")

    def test_analysis_response_requires_fields(self):
        resp = AnalysisResponse(
            success=True,
            analysis_id="x",
            timestamp="t",
            file_info={},
            analysis_type="hybrid",
            results={},
            execution_time=0.0,
        )
        assert resp.success is True

    def test_health_response_schema(self):
        h = HealthResponse(status="ok", timestamp="t", version="v")
        assert h.status == "ok"

    def test_status_response_schema(self):
        s = StatusResponse(
            status="op",
            version="v",
            uptime_seconds=1.0,
            total_requests=0,
            active_requests=0,
            analysis_count=0,
            supported_types=[],
        )
        assert s.uptime_seconds == 1.0
