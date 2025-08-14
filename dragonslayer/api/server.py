"""
VMDragonSlayer REST API Server
=============================

Unified REST API server that consolidates functionality from multiple
API implementations into a single, clean, production-ready service.

Features:
- Binary analysis endpoints
- Authentication and authorization
- WebSocket support for real-time updates
- File upload handling
- Comprehensive error handling
- Rate limiting and security
"""

import asyncio
import logging
import json
import uuid
import time
import hmac
import hashlib
import base64
import os
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
from collections import deque, defaultdict

# Handle FastAPI import gracefully
try:
    from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    # Create mock classes for environments without FastAPI
    class BaseModel:
        pass
    class Field:
        def __init__(self, *args, **kwargs):
            pass
    HTTPException = Exception

from ..core.api import VMDragonSlayerAPI
from ..core.config import get_api_config
from ..core.exceptions import (
    VMDragonSlayerError, APIError, AuthenticationError, ValidationError,
    create_error_response
)

logger = logging.getLogger(__name__)


# Request/Response Models
class AnalysisRequest(BaseModel):
    """Analysis request model"""
    sample_data: str = Field(..., description="Base64 encoded binary data", max_length=100000000)
    analysis_type: str = Field(default="hybrid", description="Analysis type")
    options: Dict[str, Any] = Field(default_factory=dict, description="Analysis options")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sample metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "sample_data": "UEsDBAoAAAAAAA==",
                "analysis_type": "hybrid",
                "options": {"timeout": 300},
                "metadata": {"filename": "sample.exe"}
            }
        }


class AnalysisResponse(BaseModel):
    """Analysis response model"""
    request_id: str = Field(..., description="Unique request identifier")
    success: bool = Field(..., description="Analysis success status")
    results: Dict[str, Any] = Field(default_factory=dict, description="Analysis results")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")
    execution_time: float = Field(..., description="Execution time in seconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Response metadata")


class StatusResponse(BaseModel):
    """Status response model"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    active_analyses: int = Field(..., description="Number of active analyses")
    total_analyses: int = Field(..., description="Total analyses performed")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")


@dataclass
class ConnectionManager:
    """WebSocket connection manager"""
    active_connections: List[WebSocket] = field(default_factory=list)
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected WebSockets"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            self.disconnect(connection)


class RateLimiter:
    """Simple rate limiter for API endpoints"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed for client"""
        now = time.time()
        client_requests = self.requests[client_id]
        
        # Remove old requests outside the window
        while client_requests and client_requests[0] < now - self.window_seconds:
            client_requests.popleft()
        
        # Check if under limit
        if len(client_requests) < self.max_requests:
            client_requests.append(now)
            return True
        
        return False


class APIServer:
    """
    Unified REST API server for VMDragonSlayer.
    
    Provides a comprehensive HTTP API for all VMDragonSlayer functionality
    with authentication, rate limiting, and WebSocket support.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize API server"""
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for the API server")
        
        self.config = get_api_config()
        self.logger = logging.getLogger(f"{__name__}.APIServer")
        
        # Initialize core API
        self.vmds_api = VMDragonSlayerAPI(config_path)
        
        # Initialize FastAPI app
        self.app = FastAPI(
            title="VMDragonSlayer API",
            description="REST API for virtual machine analysis and pattern detection",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Security and middleware
        self.security = HTTPBearer() if self.config.enable_auth else None
        self.rate_limiter = RateLimiter()
        self.connection_manager = ConnectionManager()
        
        # Service state
        self.start_time = time.time()
        self.total_analyses = 0
        self.active_analyses = 0
        self.analysis_lock = threading.RLock()
        
        # Setup middleware and routes
        self._setup_middleware()
        self._setup_routes()
        
        self.logger.info("API server initialized")
    
    def _setup_middleware(self):
        """Setup FastAPI middleware"""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Custom middleware for logging and rate limiting
        @self.app.middleware("http")
        async def custom_middleware(request, call_next):
            start_time = time.time()
            client_ip = request.client.host
            
            # Rate limiting
            if not self.rate_limiter.is_allowed(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"}
                )
            
            # Process request
            response = await call_next(request)
            
            # Log request
            process_time = time.time() - start_time
            self.logger.info(
                f"{request.method} {request.url.path} - "
                f"{response.status_code} - {process_time:.3f}s - {client_ip}"
            )
            
            return response
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/", response_model=Dict[str, str])
        async def root():
            """Root endpoint"""
            return {
                "service": "VMDragonSlayer API",
                "version": "1.0.0",
                "status": "active",
                "docs": "/docs"
            }
        
        @self.app.get("/health", response_model=Dict[str, Any])
        async def health_check():
            """Health check endpoint"""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": time.time() - self.start_time
            }
        
        @self.app.get("/status", response_model=StatusResponse)
        async def get_status():
            """Get service status"""
            try:
                vmds_status = self.vmds_api.get_status()
                
                return StatusResponse(
                    status="active",
                    version="1.0.0",
                    active_analyses=self.active_analyses,
                    total_analyses=self.total_analyses,
                    uptime_seconds=time.time() - self.start_time
                )
            except Exception as e:
                self.logger.error(f"Status check failed: {e}")
                raise HTTPException(status_code=500, detail="Status check failed")
        
        @self.app.post("/analyze", response_model=AnalysisResponse)
        async def analyze_binary(
            request: AnalysisRequest,
            background_tasks: BackgroundTasks,
            credentials: HTTPAuthorizationCredentials = Depends(self.security) if self.config.enable_auth else None
        ):
            """Analyze binary data"""
            try:
                # Authentication check
                if self.config.enable_auth and credentials:
                    self._verify_token(credentials.credentials)
                
                # Decode binary data
                try:
                    binary_data = base64.b64decode(request.sample_data)
                except Exception as e:
                    raise ValidationError("Invalid base64 encoded data", cause=e)
                
                # Update active analysis count
                with self.analysis_lock:
                    self.active_analyses += 1
                
                try:
                    # Perform analysis
                    result = await self.vmds_api.analyze_binary_data_async(
                        binary_data=binary_data,
                        analysis_type=request.analysis_type,
                        metadata=request.metadata,
                        **request.options
                    )
                    
                    # Convert to response model
                    response = AnalysisResponse(
                        request_id=result.request_id,
                        success=result.success,
                        results=result.results,
                        errors=result.errors,
                        warnings=result.warnings,
                        execution_time=result.execution_time,
                        metadata=result.metadata
                    )
                    
                    # Update counters
                    with self.analysis_lock:
                        self.total_analyses += 1
                    
                    # Broadcast status update via WebSocket
                    background_tasks.add_task(
                        self._broadcast_analysis_complete,
                        result.request_id,
                        result.success
                    )
                    
                    return response
                    
                finally:
                    # Decrement active analysis count
                    with self.analysis_lock:
                        self.active_analyses = max(0, self.active_analyses - 1)
                
            except VMDragonSlayerError as e:
                self.logger.error(f"Analysis failed: {e}")
                error_response = create_error_response(e)
                raise HTTPException(status_code=400, detail=error_response)
            except Exception as e:
                self.logger.error(f"Unexpected analysis error: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.post("/upload-analyze")
        async def upload_and_analyze(
            file: UploadFile = File(...),
            analysis_type: str = "hybrid",
            background_tasks: BackgroundTasks = None,
            credentials: HTTPAuthorizationCredentials = Depends(self.security) if self.config.enable_auth else None
        ):
            """Upload file and analyze"""
            try:
                # Authentication check
                if self.config.enable_auth and credentials:
                    self._verify_token(credentials.credentials)
                
                # Check file size
                if file.size > self.config.max_file_size_mb * 1024 * 1024:
                    raise ValidationError(f"File too large: {file.size} bytes")
                
                # Read file data
                binary_data = await file.read()
                
                # Create analysis request
                request = AnalysisRequest(
                    sample_data=base64.b64encode(binary_data).decode(),
                    analysis_type=analysis_type,
                    metadata={"filename": file.filename, "content_type": file.content_type}
                )
                
                # Delegate to analyze endpoint
                return await analyze_binary(request, background_tasks, credentials)
                
            except VMDragonSlayerError as e:
                error_response = create_error_response(e)
                raise HTTPException(status_code=400, detail=error_response)
            except Exception as e:
                self.logger.error(f"Upload analysis failed: {e}")
                raise HTTPException(status_code=500, detail="Upload analysis failed")
        
        @self.app.get("/analysis-types")
        async def get_analysis_types():
            """Get supported analysis types"""
            return {
                "analysis_types": self.vmds_api.get_supported_analysis_types(),
                "workflow_strategies": self.vmds_api.get_supported_workflow_strategies()
            }
        
        @self.app.get("/metrics")
        async def get_metrics():
            """Get performance metrics"""
            try:
                metrics = self.vmds_api.get_metrics()
                
                # Add API server metrics
                metrics.update({
                    "api_total_analyses": self.total_analyses,
                    "api_active_analyses": self.active_analyses,
                    "api_uptime_seconds": time.time() - self.start_time,
                    "websocket_connections": len(self.connection_manager.active_connections)
                })
                
                return metrics
                
            except Exception as e:
                self.logger.error(f"Failed to get metrics: {e}")
                raise HTTPException(status_code=500, detail="Failed to get metrics")
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await self.connection_manager.connect(websocket)
            try:
                while True:
                    # Send periodic status updates
                    status = {
                        "type": "status_update",
                        "active_analyses": self.active_analyses,
                        "total_analyses": self.total_analyses,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    await self.connection_manager.send_personal_message(
                        json.dumps(status), websocket
                    )
                    
                    # Wait for next update or client message
                    try:
                        data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                        # Handle client messages if needed
                    except asyncio.TimeoutError:
                        # Continue with periodic updates
                        pass
                    
            except WebSocketDisconnect:
                self.connection_manager.disconnect(websocket)
            except Exception as e:
                self.logger.error(f"WebSocket error: {e}")
                self.connection_manager.disconnect(websocket)
    
    def _verify_token(self, token: str) -> None:
        """Verify authentication token"""
        # Simple token verification - in production, use proper JWT verification
        if not token or len(token) < 10:
            raise AuthenticationError("Invalid authentication token")
        
        # For now, accept any token longer than 10 characters
        # In production, implement proper JWT verification
    
    async def _broadcast_analysis_complete(self, request_id: str, success: bool):
        """Broadcast analysis completion via WebSocket"""
        message = {
            "type": "analysis_complete",
            "request_id": request_id,
            "success": success,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.connection_manager.broadcast(json.dumps(message))
    
    def start_server(self, host: str = None, port: int = None, workers: int = None):
        """
        Start the API server.
        
        Args:
            host: Host to bind to (defaults to config)
            port: Port to bind to (defaults to config)
            workers: Number of worker processes (defaults to config)
        """
        host = host or self.config.host
        port = port or self.config.port
        workers = workers or self.config.workers
        
        self.logger.info(f"Starting API server on {host}:{port} with {workers} workers")
        
        try:
            uvicorn.run(
                self.app,
                host=host,
                port=port,
                workers=workers if workers > 1 else None,
                log_level="info",
                access_log=True
            )
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            raise APIError(
                "Failed to start API server",
                error_code="SERVER_START_FAILED",
                cause=e
            )
    
    async def shutdown(self):
        """Shutdown API server"""
        try:
            self.logger.info("Shutting down API server...")
            
            # Disconnect all WebSocket connections
            for connection in self.connection_manager.active_connections[:]:
                try:
                    await connection.close()
                except Exception:
                    pass
            
            # Shutdown core API
            await self.vmds_api.shutdown()
            
            self.logger.info("API server shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during API server shutdown: {e}")
            raise APIError(
                "Failed to shutdown API server",
                error_code="SERVER_SHUTDOWN_FAILED",
                cause=e
            )


def create_app(config_path: Optional[str] = None) -> FastAPI:
    """Create FastAPI application instance"""
    server = APIServer(config_path)
    return server.app


def run_server(host: str = "127.0.0.1", port: int = 8000, 
               workers: int = 1, config_path: Optional[str] = None):
    """Run API server with specified configuration"""
    server = APIServer(config_path)
    server.start_server(host=host, port=port, workers=workers)


if __name__ == "__main__":
    # Run server if executed directly
    run_server()
