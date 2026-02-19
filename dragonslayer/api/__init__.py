"""
VMDragonSlayer API Module

"""

try:
    from .server import app
except Exception:  # server has heavy deps (fastapi)
    app = None  # type: ignore[assignment]

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
