"""
B62 – Production Middleware
===========================

Tests for:
  - Request-ID middleware (X-Request-ID header)
  - Per-request timeout middleware
  - API-key authentication middleware
  - Circuit breaker (states, transitions, middleware integration)
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from dragonslayer.api.server import (
    API_KEY,
    CircuitBreaker,
    CircuitState,
    REQUEST_TIMEOUT_SECONDS,
    app,
    circuit_breaker,
    server_state,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """AsyncClient bound to the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
async def _reset_circuit():
    """Reset circuit breaker between tests."""
    await circuit_breaker.record_success()
    assert circuit_breaker.state == CircuitState.CLOSED


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Request-ID middleware
# ═══════════════════════════════════════════════════════════════════════════════


class TestRequestID:
    @pytest.mark.anyio
    async def test_response_has_request_id(self, client: AsyncClient):
        resp = await client.get("/health")
        assert "x-request-id" in resp.headers

    @pytest.mark.anyio
    async def test_echoes_provided_request_id(self, client: AsyncClient):
        custom_id = "my-custom-id-123"
        resp = await client.get("/health", headers={"x-request-id": custom_id})
        assert resp.headers["x-request-id"] == custom_id

    @pytest.mark.anyio
    async def test_generates_uuid_when_absent(self, client: AsyncClient):
        resp = await client.get("/health")
        rid = resp.headers["x-request-id"]
        # UUID4 has 36 chars  (8-4-4-4-12)
        assert len(rid) == 36 and rid.count("-") == 4


# ═══════════════════════════════════════════════════════════════════════════════
# 2. API-key authentication
# ═══════════════════════════════════════════════════════════════════════════════


class TestAPIKeyAuth:
    @pytest.mark.anyio
    async def test_public_paths_always_allowed(self, client: AsyncClient):
        """Public paths work even when API_KEY is set."""
        with patch("dragonslayer.api.server.API_KEY", "secret-key"):
            for path in ("/", "/health", "/status", "/metrics"):
                resp = await client.get(path)
                assert resp.status_code != 401, f"{path} should be public"

    @pytest.mark.anyio
    async def test_protected_endpoint_rejected_without_key(self, client: AsyncClient):
        with patch("dragonslayer.api.server.API_KEY", "secret-key"):
            resp = await client.get("/analysis-types")
            assert resp.status_code == 401

    @pytest.mark.anyio
    async def test_protected_endpoint_allowed_with_header_key(self, client: AsyncClient):
        with patch("dragonslayer.api.server.API_KEY", "secret-key"):
            resp = await client.get(
                "/analysis-types",
                headers={"x-api-key": "secret-key"},
            )
            assert resp.status_code != 401

    @pytest.mark.anyio
    async def test_protected_endpoint_allowed_with_query_key(self, client: AsyncClient):
        with patch("dragonslayer.api.server.API_KEY", "secret-key"):
            resp = await client.get("/analysis-types?api_key=secret-key")
            assert resp.status_code != 401

    @pytest.mark.anyio
    async def test_no_auth_when_api_key_unset(self, client: AsyncClient):
        """When API_KEY is empty, all endpoints are open."""
        with patch("dragonslayer.api.server.API_KEY", ""):
            resp = await client.get("/analysis-types")
            assert resp.status_code != 401


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Circuit Breaker (unit)
# ═══════════════════════════════════════════════════════════════════════════════


class TestCircuitBreakerUnit:
    @pytest.mark.anyio
    async def test_starts_closed(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.anyio
    async def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        for _ in range(3):
            await cb.record_failure()
        assert cb.state == CircuitState.OPEN

    @pytest.mark.anyio
    async def test_rejects_when_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=60.0)
        await cb.record_failure()
        await cb.record_failure()
        assert await cb.allow_request() is False

    @pytest.mark.anyio
    async def test_half_open_after_recovery(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)
        await cb.record_failure()
        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        await asyncio.sleep(0.06)
        assert await cb.allow_request() is True
        assert cb.state == CircuitState.HALF_OPEN

    @pytest.mark.anyio
    async def test_closes_on_success_after_half_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)
        await cb.record_failure()
        await cb.record_failure()
        await asyncio.sleep(0.06)
        await cb.allow_request()  # transitions to HALF_OPEN
        await cb.record_success()
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.anyio
    async def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        await cb.record_failure()
        await cb.record_failure()
        await cb.record_success()
        # One more failure should NOT open (counter reset)
        await cb.record_failure()
        assert cb.state == CircuitState.CLOSED


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Circuit Breaker middleware integration
# ═══════════════════════════════════════════════════════════════════════════════


class TestCircuitBreakerMiddleware:
    @pytest.mark.anyio
    async def test_health_bypasses_open_circuit(self, client: AsyncClient):
        """Health endpoint works even when circuit is open."""
        # Force open
        for _ in range(circuit_breaker.failure_threshold):
            await circuit_breaker.record_failure()
        assert circuit_breaker.state == CircuitState.OPEN

        resp = await client.get("/health")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_503_when_circuit_open(self, client: AsyncClient):
        """Non-health endpoints return 503 when circuit is open."""
        for _ in range(circuit_breaker.failure_threshold):
            await circuit_breaker.record_failure()

        resp = await client.get("/analysis-types")
        assert resp.status_code == 503
        assert "circuit breaker" in resp.json()["detail"].lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Timeout middleware (unit-level)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTimeoutConstant:
    def test_default_timeout_value(self):
        assert REQUEST_TIMEOUT_SECONDS == 300.0
