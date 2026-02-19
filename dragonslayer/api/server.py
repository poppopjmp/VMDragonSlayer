"""
VMDragonSlayer API Server

FastAPI-based REST API server for binary analysis operations.
"""

import asyncio
import base64
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from collections import defaultdict
import tempfile

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

from ..core.orchestrator import Orchestrator
from ..core.api import VMDragonSlayerAPI
from ..core.exceptions import AnalysisError, InvalidDataError, ConfigurationError
from ..core.config import get_config


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Pydantic Models for Request/Response

class AnalysisRequest(BaseModel):
    """Request model for binary analysis."""
    sample_data: str = Field(..., description="Base64-encoded binary data")
    analysis_type: str = Field(default='hybrid', description="Type of analysis to perform")
    options: Dict[str, Any] = Field(default_factory=dict, description="Additional analysis options")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional metadata")
    
    @validator('sample_data')
    def validate_base64(cls, v):
        """Validate base64 encoding."""
        try:
            base64.b64decode(v)
        except Exception:
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
    """Health check response."""
    status: str
    timestamp: str
    version: str


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

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup / shutdown lifecycle for the FastAPI app."""
    logger.info("Starting VMDragonSlayer API server...")
    try:
        server_state['api'] = VMDragonSlayerAPI()
        logger.info("API server started successfully")
    except Exception as exc:
        logger.error("Failed to start API server: %s", exc)
        raise
    yield
    # --- shutdown ---
    logger.info("Shutting down VMDragonSlayer API server...")
    api = server_state.get('api')
    if api is not None:
        api.shutdown()
    server_state['api'] = None


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
# NOTE: allow_origins=["*"] and allow_credentials=True is invalid per the
# CORS spec; browsers will reject the response.  Use explicit origins in
# production and set allow_credentials=True only with a restricted list.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately in production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
server_state: Dict[str, Any] = {
    'start_time': time.time(),
    'total_requests': 0,
    'active_requests': 0,
    'analysis_count': 0,
    'api': None,
    'rate_limiter': defaultdict(list),  # IP -> [timestamps]
}

# Async lock protects rate_limiter dict against concurrent ASGI requests
_rate_lock = asyncio.Lock()

# Separate lock for request counters (avoids contention with rate limiter)
_counter_lock = asyncio.Lock()

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 10  # requests per window
RATE_LIMIT_WINDOW = 60  # seconds


async def check_rate_limit(request: Request) -> bool:
    """Check if request exceeds rate limit (async-safe)."""
    client_ip = request.client.host
    now = time.time()

    async with _rate_lock:
        # Clean old entries
        server_state['rate_limiter'][client_ip] = [
            t for t in server_state['rate_limiter'][client_ip]
            if now - t < RATE_LIMIT_WINDOW
        ]

        # Check limit
        if len(server_state['rate_limiter'][client_ip]) >= RATE_LIMIT_REQUESTS:
            return False

        # Add current request
        server_state['rate_limiter'][client_ip].append(now)
        return True


# Startup / shutdown now handled by the ``lifespan`` context manager above.


# Middleware for request counting
@app.middleware("http")
async def count_requests(request: Request, call_next):
    """Count active and total requests (async-safe)."""
    async with _counter_lock:
        server_state['total_requests'] += 1
        server_state['active_requests'] += 1

    try:
        response = await call_next(request)
        return response
    finally:
        async with _counter_lock:
            server_state['active_requests'] -= 1


# Exception Handlers

@app.exception_handler(InvalidDataError)
async def invalid_data_handler(request: Request, exc: InvalidDataError):
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
async def analysis_error_handler(request: Request, exc: AnalysisError):
    """Handle analysis errors."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            'error': 'Analysis failed',
            'detail': str(exc),
            'error_code': exc.error_code if hasattr(exc, 'error_code') else 'ANALYSIS_ERROR'
        }
    )


# Routes

@app.get("/", tags=["Root"])
async def root():
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
async def health_check():
    """
    Health check endpoint.
    
    Returns basic server health status.
    """
    return HealthResponse(
        status='healthy',
        timestamp=datetime.now().isoformat(),
        version='2025.10'
    )


@app.get("/status", response_model=StatusResponse, tags=["Health"])
async def get_status():
    """
    Get detailed server status.
    
    Returns server metrics and statistics.
    """
    api = server_state['api']
    uptime = time.time() - server_state['start_time']
    
    return StatusResponse(
        status='operational',
        version='2025.10',
        uptime_seconds=uptime,
        total_requests=server_state['total_requests'],
        active_requests=server_state['active_requests'],
        analysis_count=server_state['analysis_count'],
        supported_types=api.get_supported_analysis_types() if api else []
    )


@app.get("/metrics", tags=["Health"])
async def get_metrics():
    """
    Get server metrics in Prometheus format.
    
    Returns performance and usage metrics.
    """
    uptime = time.time() - server_state['start_time']
    
    return {
        'vmds_uptime_seconds': uptime,
        'vmds_total_requests': server_state['total_requests'],
        'vmds_active_requests': server_state['active_requests'],
        'vmds_analysis_count': server_state['analysis_count'],
        'vmds_timestamp': time.time()
    }


@app.get("/analysis-types", tags=["Analysis"])
async def get_analysis_types():
    """
    Get list of supported analysis types.
    
    Returns all available analysis types and their descriptions.
    """
    api = server_state['api']
    
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
):
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

    api = server_state['api']

    try:
        # Decode binary data
        binary_data = base64.b64decode(analysis_request.sample_data)

        # Check size limit (default 100MB)
        max_size = 100 * 1024 * 1024  # 100MB
        if len(binary_data) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {max_size / (1024*1024)}MB"
            )

        # Perform analysis
        result = api.analyze_binary_data(
            binary_data,
            analysis_type=analysis_request.analysis_type,
            metadata=analysis_request.metadata,
            **analysis_request.options
        )

        async with _counter_lock:
            server_state['analysis_count'] += 1

        return AnalysisResponse(**result)

    except InvalidDataError as exc:
        # Let the global exception_handler handle it by re-raising
        raise
    except HTTPException:
        raise
    except Exception as exc:
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
):
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

    api = server_state['api']

    try:
        # Read file data
        binary_data = await file.read()

        # Check size limit
        max_size = 100 * 1024 * 1024  # 100MB
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

        # Perform analysis
        result = api.analyze_binary_data(
            binary_data,
            analysis_type=analysis_type,
            metadata=metadata
        )

        async with _counter_lock:
            server_state['analysis_count'] += 1

        return result

    except HTTPException:
        raise
    except Exception as exc:
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
    host = getattr(config, 'api_host', 'localhost')
    port = getattr(config, 'api_port', 8000)
    
    logger.info("Starting server on %s:%s", host, port)
    
    uvicorn.run(
        "dragonslayer.api.server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
