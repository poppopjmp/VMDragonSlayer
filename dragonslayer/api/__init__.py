"""
VMDragonSlayer API Module

"""

try:
    from .server import app, CircuitBreaker, circuit_breaker, CircuitState
except Exception:  # server has heavy deps (fastapi)
    app = None  # type: ignore[assignment]
    CircuitBreaker = None  # type: ignore[assignment,misc]
    circuit_breaker = None  # type: ignore[assignment]
    CircuitState = None  # type: ignore[assignment,misc]

try:
    from .client import APIClient, MetroplexGatewayClient, create_client
except (ImportError, AttributeError):
    APIClient = None  # type: ignore[assignment,misc]
    MetroplexGatewayClient = None  # type: ignore[assignment,misc]
    create_client = None  # type: ignore[assignment,misc]

__all__ = [
    'app',
    'APIClient',
    'MetroplexGatewayClient',
    'create_client',
]
