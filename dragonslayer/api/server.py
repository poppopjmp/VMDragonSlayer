"""
VMDragonSlayer API Server

FastAPI-based REST API server for binary analysis operations.
"""

import asyncio
import base64
import json as _json
import logging
import os as _os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Dict, Any, Optional, List
from collections import defaultdict
import tempfile

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field, field_validator

from ..core.orchestrator import Orchestrator
from ..core.api import VMDragonSlayerAPI
from ..core.exceptions import (
    AnalysisError,
    AnalysisTimeoutError,
    ConfigurationError,
    InvalidDataError,
    ResourceLimitError,
    VMDragonSlayerError,
)
from ..core.config import get_config


# ---------------------------------------------------------------------------
# B68: Structured JSON log formatter for production log aggregation
# ---------------------------------------------------------------------------

class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line.

    Output example::

        {"ts":"2025-01-15T12:00:00Z","level":"INFO","logger":"dragonslayer.api.server","msg":"..."}

    Activate via the ``VMDS_LOG_FORMAT`` environment variable::

        VMDS_LOG_FORMAT=json  →  JSON lines
        VMDS_LOG_FORMAT=text  →  human-readable (default)
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            payload["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "request_id"):
            payload["request_id"] = record.request_id  # type: ignore[attr-defined]
        return _json.dumps(payload, default=str)


_logging_configured = False


def _configure_logging(*, _force: bool = False) -> None:
    """Set up root handler with text or JSON formatting based on env.

    Idempotent — subsequent calls are no-ops unless *_force* is ``True``.
    The guard prevents import-time mutation of the root logger from
    polluting test collection.

    Args:
        _force: When ``True``, reconfigure even if already done
            (used by tests that need to switch format).
    """
    global _logging_configured  # noqa: PLW0603
    if _logging_configured and not _force:
        return
    log_format = _os.environ.get("VMDS_LOG_FORMAT", "text").lower()
    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(_JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
    root = logging.getLogger()
    # Avoid duplicate handlers on reimport
    root.handlers = [h for h in root.handlers if not isinstance(h, logging.StreamHandler)]
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    _logging_configured = True


_configure_logging()
logger = logging.getLogger(__name__)


# Pydantic Models for Request/Response

class AnalysisRequest(BaseModel):
    """Request model for binary analysis."""
    sample_data: str = Field(..., description="Base64-encoded binary data")
    analysis_type: str = Field(default='hybrid', description="Type of analysis to perform")
    options: Dict[str, Any] = Field(default_factory=dict, description="Additional analysis options")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional metadata")
    
    @field_validator('sample_data')
    @classmethod
    def validate_base64(cls, v) -> str:
        """Validate base64 encoding."""
        try:
            base64.b64decode(v)
        except (ValueError, TypeError):
            raise ValueError("Invalid base64 encoding")
        return v


class AnalysisResponse(BaseModel):
    """Response model for analysis results."""
    success: bool
    analysis_id: str
    timestamp: str
    file_info: Dict[str, Any]
    analysis_type: str
    results: Dict[str, Any]
    execution_time: float
    errors: List[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """Health check response with optional dependency probes."""
    status: str
    timestamp: str
    version: str
    components: Dict[str, str] = Field(
        default_factory=dict,
        description="Per-component health status (e.g. api, pattern_db).",
    )


class StatusResponse(BaseModel):
    """Server status response."""
    status: str
    version: str
    uptime_seconds: float
    total_requests: int
    active_requests: int
    analysis_count: int
    supported_types: List[str]


# ---------------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event)
# ---------------------------------------------------------------------------

_SHUTDOWN_DRAIN_SECONDS: float = float(
    _os.environ.get("VMDS_SHUTDOWN_DRAIN_SECONDS", "5")
)
"""Seconds to wait for in-flight requests before forced shutdown."""


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:  # type: ignore[override]
    """Startup / shutdown lifecycle for the FastAPI app.

    On shutdown the server waits up to ``_SHUTDOWN_DRAIN_SECONDS`` for
    in-flight requests to complete before calling ``api.shutdown()``.
    """
    logger.info("Starting VMDragonSlayer API server...")
    try:
        server_state.api = VMDragonSlayerAPI()
        logger.info("API server started successfully")
    except (ValueError, TypeError, RuntimeError, OSError, ImportError) as exc:
        logger.error("Failed to start API server: %s", exc)
        raise
    yield
    # --- graceful drain ---
    logger.info("Shutting down VMDragonSlayer API server (drain=%.1fs)...",
                _SHUTDOWN_DRAIN_SECONDS)
    deadline = time.monotonic() + _SHUTDOWN_DRAIN_SECONDS
    while server_state.active_requests > 0 and time.monotonic() < deadline:
        await asyncio.sleep(0.1)
    remaining = server_state.active_requests
    if remaining:
        logger.warning("Shutdown forced with %d active request(s)", remaining)
    api = server_state.api
    if api is not None:
        api.shutdown()
    server_state.api = None


# Initialize FastAPI app
app = FastAPI(
    title="VMDragonSlayer API",
    description="Advanced Virtual Machine Detection and Analysis Framework",
    version="2025.10",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
# B66: allow_origins configurable via VMDS_CORS_ORIGINS env-var (comma-separated).
# Defaults to ["*"] for development; set explicitly in production.
_cors_origins_raw = _os.environ.get("VMDS_CORS_ORIGINS", "*")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
_cors_credentials = _cors_origins != ["*"]  # spec forbids credentials with wildcard

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# B97: Response compression for large JSON payloads (min 1 KB).
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ═══════════════════════════════════════════════════════════════════════════════
# B62: Production middleware
# ═══════════════════════════════════════════════════════════════════════════════

# --- B66: Request body size limit middleware ---------------------------------

MAX_REQUEST_BODY_BYTES: int = 100 * 1024 * 1024  # 100 MB


@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next) -> Response:
    """Reject requests with Content-Length exceeding MAX_REQUEST_BODY_BYTES.

    This catches oversized uploads *before* the body is fully read, avoiding
    unnecessary memory allocation.
    """
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Request too large",
                        "detail": f"Body exceeds {MAX_REQUEST_BODY_BYTES} byte limit",
                    },
                )
        except ValueError:
            pass
    return await call_next(request)


# --- Request-ID middleware ---------------------------------------------------

@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    """Attach a unique X-Request-ID header to every request/response.

    B70: Also injects ``request_id`` into all log records emitted during
    the request via a logging filter, so that JSON log lines include
    the correlation ID automatically.
    """
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    # Store on request state so downstream handlers can access it
    request.state.request_id = req_id

    # B70: Inject request_id into logging context for correlation
    _rid_filter = _RequestIDFilter(req_id)
    logging.getLogger().addFilter(_rid_filter)
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response
    finally:
        logging.getLogger().removeFilter(_rid_filter)


class _RequestIDFilter(logging.Filter):
    """Inject ``request_id`` attribute into every log record."""

    __slots__ = ("_request_id",)

    def __init__(self, request_id: str) -> None:
        super().__init__()
        self._request_id = request_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = self._request_id  # type: ignore[attr-defined]
        return True


# --- Per-request timeout middleware ------------------------------------------

REQUEST_TIMEOUT_SECONDS: float = 300.0  # 5 minutes default


@app.middleware("http")
async def timeout_middleware(request: Request, call_next) -> Response:
    """Cancel requests that exceed REQUEST_TIMEOUT_SECONDS."""
    try:
        response = await asyncio.wait_for(
            call_next(request),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return response
    except asyncio.TimeoutError:
        req_id = getattr(request.state, "request_id", "unknown")
        logger.warning("Request %s timed out after %ss", req_id, REQUEST_TIMEOUT_SECONDS)
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={
                "error": "Request timed out",
                "detail": f"Request exceeded {REQUEST_TIMEOUT_SECONDS}s limit",
                "request_id": req_id,
            },
        )


# --- API-key authentication middleware ---------------------------------------

# Set VMDS_API_KEY env-var (or config) to enable; empty/unset = no auth.
import hmac as _hmac

API_KEY: str = _os.environ.get("VMDS_API_KEY", "")

# Paths that never require authentication
_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/", "/health", "/status", "/metrics", "/docs", "/redoc", "/openapi.json",
})


@app.middleware("http")
async def api_key_middleware(request: Request, call_next) -> Response:
    """Reject requests without a valid API key (when API_KEY is set)."""
    if API_KEY and request.url.path not in _PUBLIC_PATHS:
        provided = (
            request.headers.get("x-api-key")
            or request.query_params.get("api_key")
            or ""
        )
        if not _hmac.compare_digest(provided, API_KEY):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "Unauthorized",
                    "detail": "Missing or invalid API key",
                },
            )
    return await call_next(request)


# --- Circuit breaker ---------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "closed"      # normal operation
    OPEN = "open"          # rejecting requests
    HALF_OPEN = "half_open"  # testing recovery


class CircuitBreaker:
    """Simple circuit breaker to prevent cascade failures.

    After *failure_threshold* consecutive failures the circuit **opens**
    and all requests are rejected for *recovery_timeout* seconds.  After
    that window the circuit moves to **half-open** and lets one request
    through.  If it succeeds the circuit closes; if it fails the circuit
    re-opens.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def record_success(self) -> None:
        """Record a successful request and reset the failure counter."""
        async with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    async def record_failure(self) -> None:
        """Record a failed request; opens the circuit after *failure_threshold*."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "Circuit breaker OPENED after %d failures",
                    self._failure_count,
                )

    async def allow_request(self) -> bool:
        """Return ``True`` if a new request may proceed.

        Returns:
            ``True`` when the circuit is closed or half-open,
            ``False`` when the circuit is open and the recovery
            timeout has not elapsed.
        """
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            if self._state == CircuitState.OPEN:
                if time.time() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    logger.info("Circuit breaker moved to HALF_OPEN")
                    return True
                return False
            # HALF_OPEN: allow a single probe
            return True


circuit_breaker = CircuitBreaker()


@app.middleware("http")
async def circuit_breaker_middleware(request: Request, call_next) -> Response:
    """Reject requests when the circuit breaker is open."""
    # Health/status endpoints bypass the circuit breaker
    if request.url.path in ("/health", "/status", "/metrics"):
        return await call_next(request)

    if not await circuit_breaker.allow_request():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "Service temporarily unavailable",
                "detail": "Circuit breaker is open — too many recent failures",
            },
        )

    try:
        response = await call_next(request)
        if response.status_code < 500:
            await circuit_breaker.record_success()
        else:
            await circuit_breaker.record_failure()
        return response
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, ConnectionError):
        await circuit_breaker.record_failure()
        raise


# ═══════════════════════════════════════════════════════════════════════════════

# Global state
@dataclass
class ServerState:
    """Typed container for global API server runtime state.

    Attributes:
        start_time: Epoch timestamp when the server was initialised.
        total_requests: Cumulative number of HTTP requests handled.
        active_requests: Number of requests currently being processed.
        analysis_count: Total binary analyses completed.
        api: The :class:`VMDragonSlayerAPI` instance (set during lifespan).
        rate_limiter: Per-IP sliding-window timestamp lists.
    """

    start_time: float = field(default_factory=time.time)
    total_requests: int = 0
    active_requests: int = 0
    analysis_count: int = 0
    api: Optional[Any] = None
    rate_limiter: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))


server_state = ServerState()

# Async lock protects rate_limiter dict against concurrent ASGI requests
_rate_lock = asyncio.Lock()

# Separate lock for request counters (avoids contention with rate limiter)
_counter_lock = asyncio.Lock()

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 10  # requests per window
RATE_LIMIT_WINDOW = 60  # seconds


async def check_rate_limit(request: Request) -> bool:
    """Check if *request* exceeds the per-IP rate limit.

    Args:
        request: Incoming Starlette/FastAPI request.

    Returns:
        ``True`` if the request is within the rate limit and a
        timestamp has been recorded, ``False`` if the limit is
        exceeded and the request should be rejected.

    B57: Also evicts stale IPs that have no recent requests to prevent
    unbounded memory growth in ``server_state.rate_limiter``.
    """
    client_ip = request.client.host
    now = time.time()

    async with _rate_lock:
        # Ensure the IP has an entry before filtering
        timestamps = server_state.rate_limiter.get(client_ip, [])
        server_state.rate_limiter[client_ip] = [
            t for t in timestamps
            if now - t < RATE_LIMIT_WINDOW
        ]

        # B57: Evict IPs with no recent requests (cheap periodic sweep).
        if server_state.total_requests % 100 == 0:
            stale_ips = [
                ip for ip, ts in server_state.rate_limiter.items()
                if not ts or (now - max(ts)) > RATE_LIMIT_WINDOW * 2
            ]
            for ip in stale_ips:
                del server_state.rate_limiter[ip]

        # Check limit
        if len(server_state.rate_limiter[client_ip]) >= RATE_LIMIT_REQUESTS:
            return False

        # Add current request
        server_state.rate_limiter[client_ip].append(now)
        return True


# Startup / shutdown now handled by the ``lifespan`` context manager above.


# Middleware for request counting
@app.middleware("http")
async def count_requests(request: Request, call_next) -> Response:
    """Count active and total requests (async-safe)."""
    async with _counter_lock:
        server_state.total_requests += 1
        server_state.active_requests += 1

    try:
        response = await call_next(request)
        return response
    finally:
        async with _counter_lock:
            server_state.active_requests -= 1


# Exception Handlers

@app.exception_handler(InvalidDataError)
async def invalid_data_handler(request: Request, exc: InvalidDataError) -> JSONResponse:
    """Handle invalid data errors."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            'error': 'Invalid data',
            'detail': str(exc),
            'error_code': exc.error_code if hasattr(exc, 'error_code') else 'INVALID_DATA'
        }
    )


@app.exception_handler(AnalysisError)
async def analysis_error_handler(request: Request, exc: AnalysisError) -> JSONResponse:
    """Handle analysis errors."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            'error': 'Analysis failed',
            'detail': str(exc),
            'error_code': exc.error_code if hasattr(exc, 'error_code') else 'ANALYSIS_ERROR'
        }
    )


# B57: Additional exception handlers ----------------------------------------

@app.exception_handler(ConfigurationError)
async def configuration_error_handler(request: Request, exc: ConfigurationError) -> JSONResponse:
    """Handle configuration errors (e.g. invalid config at startup)."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            'error': 'Configuration error',
            'detail': str(exc),
            'error_code': getattr(exc, 'error_code', 'CONFIGURATION_ERROR'),
        }
    )


@app.exception_handler(ResourceLimitError)
async def resource_limit_handler(request: Request, exc: ResourceLimitError) -> JSONResponse:
    """Handle resource-limit exceeded (memory, paths, loop iterations)."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            'error': 'Resource limit exceeded',
            'detail': str(exc),
            'error_code': getattr(exc, 'error_code', 'RESOURCE_LIMIT'),
        }
    )


@app.exception_handler(AnalysisTimeoutError)
async def analysis_timeout_handler(request: Request, exc: AnalysisTimeoutError) -> JSONResponse:
    """Handle analysis-timeout exceeded."""
    return JSONResponse(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        content={
            'error': 'Analysis timed out',
            'detail': str(exc),
            'error_code': getattr(exc, 'error_code', 'ANALYSIS_TIMEOUT'),
        }
    )


@app.exception_handler(VMDragonSlayerError)
async def generic_vmds_error_handler(request: Request, exc: VMDragonSlayerError) -> JSONResponse:
    """Catch-all for any VMDragonSlayerError subclass not handled above."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            'error': 'Internal error',
            'detail': str(exc),
            'error_code': getattr(exc, 'error_code', 'VMDS_ERROR'),
        }
    )


# Routes

@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """Root endpoint with API information."""
    return {
        'name': 'VMDragonSlayer API',
        'version': '2025.10',
        'description': 'Advanced Virtual Machine Detection and Analysis Framework',
        'endpoints': {
            'health': '/health',
            'status': '/status',
            'metrics': '/metrics',
            'analysis_types': '/analysis-types',
            'analyze': '/analyze',
            'upload_analyze': '/upload-analyze',
            'docs': '/docs',
            'redoc': '/redoc'
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Health check endpoint with dependency probing.

    Returns per-component status so orchestration layers can distinguish
    between *liveness* (process is running) and *readiness* (dependencies
    are functional).  The top-level ``status`` is ``"healthy"`` only when
    every probed component is ``"ok"``.
    """
    components: Dict[str, str] = {}

    # Probe 1 — VMDragonSlayerAPI instance
    api = server_state.api
    if api is not None:
        components['api'] = 'ok'
    else:
        components['api'] = 'unavailable'

    # Probe 2 — Pattern database
    try:
        if api is not None and hasattr(api, 'pattern_db') and api.pattern_db is not None:
            components['pattern_db'] = 'ok'
        else:
            components['pattern_db'] = 'unavailable'
    except (AttributeError, RuntimeError):
        components['pattern_db'] = 'error'

    overall = 'healthy' if all(v == 'ok' for v in components.values()) else 'degraded'

    return HealthResponse(
        status=overall,
        timestamp=datetime.now().isoformat(),
        version='2025.10',
        components=components,
    )


@app.get("/status", response_model=StatusResponse, tags=["Health"])
async def get_status() -> StatusResponse:
    """
    Get detailed server status.
    
    Returns server metrics and statistics.
    """
    api = server_state.api
    uptime = time.time() - server_state.start_time
    
    return StatusResponse(
        status='operational',
        version='2025.10',
        uptime_seconds=uptime,
        total_requests=server_state.total_requests,
        active_requests=server_state.active_requests,
        analysis_count=server_state.analysis_count,
        supported_types=api.get_supported_analysis_types() if api else []
    )


@app.get("/metrics", tags=["Health"])
async def get_metrics() -> Dict[str, Any]:
    """
    Get server metrics in Prometheus format.
    
    Returns performance and usage metrics.
    """
    uptime = time.time() - server_state.start_time
    
    return {
        'vmds_uptime_seconds': uptime,
        'vmds_total_requests': server_state.total_requests,
        'vmds_active_requests': server_state.active_requests,
        'vmds_analysis_count': server_state.analysis_count,
        'vmds_timestamp': time.time()
    }


@app.get("/analysis-types", tags=["Analysis"])
async def get_analysis_types() -> Dict[str, Any]:
    """
    Get list of supported analysis types.
    
    Returns all available analysis types and their descriptions.
    """
    api = server_state.api
    
    types_info = {
        'vm_discovery': 'VM dispatcher and handler detection',
        'vm_detection': 'Alias for vm_discovery',
        'pattern_analysis': 'Pattern matching and classification',
        'taint_tracking': 'Dynamic taint tracking analysis',
        'symbolic_execution': 'Symbolic execution analysis',
        'vmprotect_devirt': 'VMProtect devirtualization',
        'anti_evasion': 'Anti-evasion technique detection',
        'hybrid': 'Combined VM discovery and pattern analysis',
        'full_analysis': 'Comprehensive analysis with all engines',
        'unified': 'Alias for full_analysis',
        'extended_patterns': 'Enhanced pattern analysis',
        'ml_detection': 'Machine learning based detection',
        'multi_arch': 'Multi-architecture analysis',
        'security_extensions': 'Security-focused analysis',
        'realtime': 'Real-time analysis mode'
    }
    
    return {
        'supported_types': api.get_supported_analysis_types() if api else [],
        'descriptions': types_info
    }


@app.post("/analyze", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze_binary(
    request: Request,
    analysis_request: AnalysisRequest
) -> AnalysisResponse:
    """
    Analyze binary data.
    
    Accepts base64-encoded binary data and performs the requested analysis.
    
    Args:
        analysis_request: Analysis request with binary data and options
        
    Returns:
        Analysis results with success status and findings
    """
    # Rate limiting
    if not await check_rate_limit(request):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

    api = server_state.api

    try:
        # Decode binary data
        binary_data = base64.b64decode(analysis_request.sample_data)

        # Check size limit
        max_size = MAX_REQUEST_BODY_BYTES
        if len(binary_data) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {max_size / (1024*1024)}MB"
            )

        # Perform analysis (async to avoid blocking the ASGI event loop)
        result = await api.analyze_binary_data_async(
            binary_data,
            analysis_type=analysis_request.analysis_type,
            metadata=analysis_request.metadata,
            **analysis_request.options
        )

        async with _counter_lock:
            server_state.analysis_count += 1

        return AnalysisResponse(**result)

    except InvalidDataError as exc:
        # Let the global exception_handler handle it by re-raising
        raise
    except HTTPException:
        raise
    except VMDragonSlayerError:
        # B57: Let registered exception handlers process framework errors.
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
        logger.error("Analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(exc)}"
        )


@app.post("/upload-analyze", tags=["Analysis"])
async def upload_and_analyze(
    request: Request,
    file: UploadFile = File(...),
    analysis_type: str = 'hybrid'
) -> Dict[str, Any]:
    """
    Upload and analyze a binary file.
    
    Accepts multipart form data with binary file upload.
    
    Args:
        file: Binary file to analyze
        analysis_type: Type of analysis to perform
        
    Returns:
        Analysis results
    """
    # Rate limiting
    if not await check_rate_limit(request):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

    api = server_state.api

    try:
        # Read file data
        binary_data = await file.read()

        # Check size limit
        max_size = MAX_REQUEST_BODY_BYTES
        if len(binary_data) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {max_size / (1024*1024)}MB"
            )

        # Prepare metadata
        metadata = {
            'filename': file.filename,
            'content_type': file.content_type,
            'size': len(binary_data)
        }

        # Perform analysis (async to avoid blocking the ASGI event loop)
        result = await api.analyze_binary_data_async(
            binary_data,
            analysis_type=analysis_type,
            metadata=metadata
        )

        async with _counter_lock:
            server_state.analysis_count += 1

        return result

    except HTTPException:
        raise
    except VMDragonSlayerError:
        # B57: Let registered exception handlers process framework errors.
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
        logger.error("Upload analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(exc)}"
        )
    finally:
        await file.close()


# Entry point for direct execution
if __name__ == "__main__":
    import uvicorn
    
    config = get_config()
    host = config.get('api.host', 'localhost')
    port = config.get('api.port', 8000)
    
    logger.info("Starting server on %s:%s", host, port)
    
    uvicorn.run(
        "dragonslayer.api.server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
