"""
VMDragonSlayer Exception Hierarchy

Centralised exception classes used across every module.
Each exception carries an ``error_code`` for structured API responses
and an optional ``details`` dict for diagnostics.
"""

from __future__ import annotations


class VMDragonSlayerError(Exception):
    """Base exception for the entire framework."""

    error_code: str = "VMDS_ERROR"

    def __init__(self, message: str = "", *, error_code: str | None = None, details: dict | None = None):
        super().__init__(message)
        if error_code is not None:
            self.error_code = error_code
        self.details = details or {}


# ---------------------------------------------------------------------------
# Core errors
# ---------------------------------------------------------------------------

class ConfigurationError(VMDragonSlayerError):
    """Raised when a configuration value is missing or invalid."""
    error_code = "CONFIGURATION_ERROR"


class InvalidDataError(VMDragonSlayerError):
    """Raised when input data fails validation."""
    error_code = "INVALID_DATA"


# ---------------------------------------------------------------------------
# Analysis errors
# ---------------------------------------------------------------------------

class AnalysisError(VMDragonSlayerError):
    """Raised when an analysis engine encounters an unrecoverable error."""
    error_code = "ANALYSIS_ERROR"


class DevirtualizationError(AnalysisError):
    """Raised when VM devirtualization fails."""
    error_code = "DEVIRTUALIZATION_ERROR"


# ---------------------------------------------------------------------------
# Network / API errors
# ---------------------------------------------------------------------------

class NetworkError(VMDragonSlayerError):
    """Raised on transport-level failures (timeouts, DNS, TLS …)."""
    error_code = "NETWORK_ERROR"


class APIError(VMDragonSlayerError):
    """Raised when an upstream HTTP API returns a non-success status."""
    error_code = "API_ERROR"

    def __init__(
        self,
        message: str = "",
        *,
        status_code: int | None = None,
        error_code: str | None = None,
        details: dict | None = None,
    ):
        super().__init__(message, error_code=error_code, details=details)
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Plugin / Gateway errors
# ---------------------------------------------------------------------------

class PluginError(AnalysisError):
    """Raised when a Metroplex plugin returns an error or times out."""
    error_code = "PLUGIN_ERROR"

    def __init__(
        self,
        message: str = "",
        *,
        plugin_name: str = "",
        error_code: str | None = None,
        details: dict | None = None,
    ):
        super().__init__(message, error_code=error_code, details=details)
        self.plugin_name = plugin_name


class GatewayError(NetworkError):
    """Raised when the Metroplex API gateway is unreachable or misbehaves."""
    error_code = "GATEWAY_ERROR"
