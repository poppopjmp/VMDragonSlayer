#!/usr/bin/env python3
# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Enterprise API Integration System for VMDragonSlayer
==================================================

Provides comprehensive API integration capabilities including:
    - REST and GraphQL API management
    - Webhook processing and management
    - Third-party service connectors
    - API authentication and authorization
    - Rate limiting and throttling
    - Request/response transformation
    - Integration monitoring and analytics

This module consolidates enterprise API integration functionality
from the original enterprise modules.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

# Core dependencies
try:
    import aiohttp
    import httpx

    ASYNC_HTTP_AVAILABLE = True
except ImportError:
    ASYNC_HTTP_AVAILABLE = False

try:
    from fastapi import (
        BackgroundTasks,
        Depends,
        FastAPI,
        HTTPException,
        Request,
        Security,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    import graphene
    from graphene import Field, ObjectType, Schema, String
    from graphene import List as GrapheneList

    GRAPHENE_AVAILABLE = True
except ImportError:
    GRAPHENE_AVAILABLE = False

try:
    import jwt
    from cryptography.hazmat.primitives import hashes, serialization

    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import pydantic
    from pydantic import BaseModel, validator
    from pydantic import Field as PydanticField

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Types of integrations"""

    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    WEBHOOK = "webhook"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    MESSAGE_QUEUE = "message_queue"
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    CLOUD_SERVICE = "cloud_service"


class APIMethod(Enum):
    """HTTP API methods"""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class WebhookEvent(Enum):
    """Webhook event types"""

    ANALYSIS_COMPLETE = "analysis_complete"
    THREAT_DETECTED = "threat_detected"
    ALERT_TRIGGERED = "alert_triggered"
    SYSTEM_STATUS = "system_status"
    USER_ACTION = "user_action"
    DATA_UPDATED = "data_updated"
    ERROR_OCCURRED = "error_occurred"


@dataclass
class APIEndpoint:
    """API endpoint configuration"""

    url: str
    method: APIMethod
    headers: Dict[str, str] = None
    auth_required: bool = True
    rate_limit: int = 100  # requests per minute
    timeout: int = 30
    retry_count: int = 3
    description: str = ""


@dataclass
class WebhookConfig:
    """Webhook configuration"""

    url: str
    events: List[WebhookEvent]
    secret: str = ""
    headers: Dict[str, str] = None
    retry_count: int = 3
    timeout: int = 10
    active: bool = True


@dataclass
class IntegrationResult:
    """Result of an integration operation"""

    success: bool
    status_code: Optional[int] = None
    response_data: Any = None
    error_message: str = ""
    execution_time: float = 0.0
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class RateLimiter:
    """Rate limiting for API calls"""

    def __init__(self):
        self.requests = {}  # endpoint -> [(timestamp, count), ...]
        self.lock = threading.Lock()

    def is_allowed(self, endpoint: str, limit: int, window: int = 60) -> bool:
        """Check if request is allowed under rate limit"""
        with self.lock:
            now = time.time()

            if endpoint not in self.requests:
                self.requests[endpoint] = []

            # Clean old requests outside window
            self.requests[endpoint] = [
                (ts, count)
                for ts, count in self.requests[endpoint]
                if now - ts < window
            ]

            # Count current requests
            current_count = sum(count for _, count in self.requests[endpoint])

            if current_count >= limit:
                return False

            # Add current request
            self.requests[endpoint].append((now, 1))
            return True


class APIConnector:
    """Generic API connector for various services"""

    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.session = None
        self.rate_limiter = RateLimiter()

    async def _get_session(self):
        """Get or create aiohttp session"""
        if not ASYNC_HTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available for async operations")

        if self.session is None:
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            self.session = aiohttp.ClientSession(
                headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            )
        return self.session

    async def make_request(
        self, endpoint: APIEndpoint, data: Any = None
    ) -> IntegrationResult:
        """Make API request"""
        start_time = time.time()

        try:
            # Rate limiting check
            if not self.rate_limiter.is_allowed(endpoint.url, endpoint.rate_limit):
                return IntegrationResult(
                    success=False,
                    error_message="Rate limit exceeded",
                    execution_time=time.time() - start_time,
                )

            if ASYNC_HTTP_AVAILABLE:
                return await self._make_async_request(endpoint, data, start_time)
            else:
                return self._make_sync_request(endpoint, data, start_time)

        except Exception as e:
            return IntegrationResult(
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )

    async def _make_async_request(
        self, endpoint: APIEndpoint, data: Any, start_time: float
    ) -> IntegrationResult:
        """Make async API request"""
        session = await self._get_session()

        url = f"{self.base_url}{endpoint.url}"
        headers = endpoint.headers or {}

        try:
            async with session.request(
                endpoint.method.value,
                url,
                json=data if data else None,
                headers=headers,
                timeout=endpoint.timeout,
            ) as response:

                response_data = None
                try:
                    response_data = await response.json()
                except Exception:
                    response_data = await response.text()

                return IntegrationResult(
                    success=response.status < 400,
                    status_code=response.status,
                    response_data=response_data,
                    execution_time=time.time() - start_time,
                )

        except asyncio.TimeoutError:
            return IntegrationResult(
                success=False,
                error_message="Request timeout",
                execution_time=time.time() - start_time,
            )

    def _make_sync_request(
        self, endpoint: APIEndpoint, data: Any, start_time: float
    ) -> IntegrationResult:
        """Make synchronous API request using httpx"""
        try:
            import requests
        except ImportError:
            return IntegrationResult(
                success=False,
                error_message="No HTTP library available (install aiohttp or requests)",
                execution_time=time.time() - start_time,
            )

        url = f"{self.base_url}{endpoint.url}"
        headers = endpoint.headers or {}

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            response = requests.request(
                endpoint.method.value,
                url,
                json=data if data else None,
                headers=headers,
                timeout=endpoint.timeout,
            )

            response_data = None
            try:
                response_data = response.json()
            except Exception:
                response_data = response.text

            return IntegrationResult(
                success=response.status_code < 400,
                status_code=response.status_code,
                response_data=response_data,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            return IntegrationResult(
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )

    async def close(self):
        """Close session"""
        if self.session:
            await self.session.close()


class WebhookManager:
    """Webhook management and processing"""

    def __init__(self):
        self.webhooks: Dict[str, WebhookConfig] = {}
        self.event_handlers: Dict[WebhookEvent, List[Callable]] = {}
        self.delivery_queue = []
        self.processing = False

    def register_webhook(self, name: str, config: WebhookConfig):
        """Register a webhook"""
        self.webhooks[name] = config
        logger.info(f"Registered webhook: {name} -> {config.url}")

    def add_event_handler(self, event: WebhookEvent, handler: Callable):
        """Add event handler"""
        if event not in self.event_handlers:
            self.event_handlers[event] = []
        self.event_handlers[event].append(handler)

    async def trigger_event(self, event: WebhookEvent, data: Dict[str, Any]):
        """Trigger webhook event"""
        # Call local handlers
        if event in self.event_handlers:
            for handler in self.event_handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event, data)
                    else:
                        handler(event, data)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

        # Send to registered webhooks
        for name, webhook in self.webhooks.items():
            if webhook.active and event in webhook.events:
                await self._deliver_webhook(name, webhook, event, data)

    async def _deliver_webhook(
        self,
        name: str,
        webhook: WebhookConfig,
        event: WebhookEvent,
        data: Dict[str, Any],
    ):
        """Deliver webhook"""
        payload = {
            "event": event.value,
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }

        headers = webhook.headers or {}
        headers["Content-Type"] = "application/json"

        # Add signature if secret provided
        if webhook.secret:
            signature = hmac.new(
                webhook.secret.encode(), json.dumps(payload).encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        connector = APIConnector(webhook.url)
        endpoint = APIEndpoint(
            url="",
            method=APIMethod.POST,
            headers=headers,
            timeout=webhook.timeout,
            retry_count=webhook.retry_count,
            auth_required=False,
        )

        try:
            result = await connector.make_request(endpoint, payload)
            if result.success:
                logger.info(f"Webhook delivered: {name}")
            else:
                logger.error(
                    f"Webhook delivery failed: {name} - {result.error_message}"
                )
        finally:
            await connector.close()


class GraphQLResolver:
    """GraphQL resolver for analysis data"""

    def __init__(self):
        self.schema = None
        self._init_schema()

    def _init_schema(self):
        """Initialize GraphQL schema"""
        if not GRAPHENE_AVAILABLE:
            logger.warning("GraphQL not available - install graphene")
            return

        class AnalysisQuery(graphene.ObjectType):
            analysis_results = graphene.List(graphene.String)
            threat_indicators = graphene.List(graphene.String)

            def resolve_analysis_results(self, info):
                # In a real implementation, this would query the database
                return ["result1", "result2", "result3"]

            def resolve_threat_indicators(self, info):
                # In a real implementation, this would query threat data
                return ["indicator1", "indicator2"]

        self.schema = graphene.Schema(query=AnalysisQuery)


class IntegrationAPISystem:
    """Main integration API system"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.connectors: Dict[str, APIConnector] = {}
        self.webhook_manager = WebhookManager()
        self.graphql_resolver = GraphQLResolver()
        self.app = None
        self.rate_limiter = RateLimiter()

        if FASTAPI_AVAILABLE:
            self._init_fastapi()

    def _init_fastapi(self):
        """Initialize FastAPI application"""
        self.app = FastAPI(
            title="VMDragonSlayer Integration API",
            description="Enterprise integration API for VMDragonSlayer",
            version="1.0.0",
        )

        # Add middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        self.app.add_middleware(GZipMiddleware, minimum_size=1000)

        # Add routes
        self._add_api_routes()

    def _add_api_routes(self):
        """Add API routes"""
        if not self.app:
            return

        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "timestamp": datetime.now().isoformat()}

        @self.app.post("/webhook/{name}")
        async def receive_webhook(name: str, request: Request):
            await request.json()
            # Process incoming webhook
            logger.info(f"Received webhook: {name}")
            return {"status": "received"}

        @self.app.get("/integrations")
        async def list_integrations():
            return {
                "connectors": list(self.connectors.keys()),
                "webhooks": list(self.webhook_manager.webhooks.keys()),
            }

    def add_connector(self, name: str, base_url: str, auth_token: str = None):
        """Add API connector"""
        self.connectors[name] = APIConnector(base_url, auth_token)
        logger.info(f"Added connector: {name}")

    def register_webhook(self, name: str, config: WebhookConfig):
        """Register webhook"""
        self.webhook_manager.register_webhook(name, config)

    async def call_api(
        self, connector_name: str, endpoint: APIEndpoint, data: Any = None
    ) -> IntegrationResult:
        """Call API through connector"""
        if connector_name not in self.connectors:
            return IntegrationResult(
                success=False, error_message=f"Connector '{connector_name}' not found"
            )

        connector = self.connectors[connector_name]
        return await connector.make_request(endpoint, data)

    async def trigger_webhook_event(self, event: WebhookEvent, data: Dict[str, Any]):
        """Trigger webhook event"""
        await self.webhook_manager.trigger_event(event, data)

    def run_server(self, host: str = "127.0.0.1", port: int = 8000):
        """Run FastAPI server"""
        if not FASTAPI_AVAILABLE:
            logger.error("FastAPI not available - install fastapi and uvicorn")
            return

        try:
            import uvicorn

            uvicorn.run(self.app, host=host, port=port)
        except ImportError:
            logger.error("uvicorn not available - install uvicorn to run server")

    async def close_all_connections(self):
        """Close all connector sessions"""
        for connector in self.connectors.values():
            await connector.close()


# Example usage and testing
async def main():
    """Example usage of the integration system"""

    # Initialize integration system
    integration_system = IntegrationAPISystem()

    # Add API connector
    integration_system.add_connector(
        "analysis_api", "https://api.example.com", "your-auth-token"
    )

    # Register webhook
    # Note: Do not hardcode secrets in production code. Example uses placeholder only.
    webhook_config = WebhookConfig(
        url="https://your-webhook.com/endpoint",
        events=[WebhookEvent.ANALYSIS_COMPLETE, WebhookEvent.THREAT_DETECTED],
        secret="",
    )
    integration_system.register_webhook("main_webhook", webhook_config)

    # Make API call
    endpoint = APIEndpoint(
        url="/analysis/results",
        method=APIMethod.GET,
        description="Get analysis results",
    )

    result = await integration_system.call_api("analysis_api", endpoint)
    print(f"API call result: {result.success}")

    # Trigger webhook event
    await integration_system.trigger_webhook_event(
        WebhookEvent.ANALYSIS_COMPLETE,
        {"analysis_id": "12345", "results": "threat detected"},
    )

    # Clean up
    await integration_system.close_all_connections()


if __name__ == "__main__":
    asyncio.run(main())
