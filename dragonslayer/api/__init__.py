"""
API Module
==========

REST API components for VMDragonSlayer.

This module provides a complete REST API implementation including:
- HTTP server with FastAPI
- API client for remote access
- Endpoint definitions
- Binary data transfer utilities
"""

from .server import APIServer, create_app, run_server
from .client import APIClient, create_client
from .endpoints import EndpointRegistry, Endpoint
from .transfer import BinaryTransfer, get_transfer_util, encode_binary, decode_binary

__all__ = [
    'APIServer',
    'create_app',
    'run_server',
    'APIClient',
    'create_client',
    'EndpointRegistry',
    'Endpoint',
    'BinaryTransfer',
    'get_transfer_util',
    'encode_binary',
    'decode_binary'
]
