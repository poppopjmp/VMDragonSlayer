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
API Module
==========

REST API components for VMDragonSlayer.

This module provides a complete REST API implementation including:
- HTTP server with FastAPI
- API client for remote access
- Endpoint definitions
- Binary data transfer utilities
"""

from .client import APIClient, create_client
from .endpoints import Endpoint, EndpointRegistry
from .server import APIServer, create_app, run_server
from .transfer import BinaryTransfer, decode_binary, encode_binary, get_transfer_util

__all__ = [
    "APIServer",
    "create_app",
    "run_server",
    "APIClient",
    "create_client",
    "EndpointRegistry",
    "Endpoint",
    "BinaryTransfer",
    "get_transfer_util",
    "encode_binary",
    "decode_binary",
]
