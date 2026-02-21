"""
VMDragonSlayer API Clients
==========================

Two clients live here:

1. **APIClient** — talks to the VMDragonSlayer FastAPI server (``/analyze``,
   ``/health``, ``/status``).
2. **MetroplexGatewayClient** — talks to the Metroplex Traefik gateway
   (``POST /scan``) or to individual plugin containers
   (``POST https://<plugin>.plugins.localhost:8443/scan``).

The gateway client reproduces — in Python — the fan-out behaviour of
``repos/gateway/main.go:handleScan``: upload a sample via multipart form,
optionally filter by plugin list or stage, honour a per-request timeout,
and return the aggregated ``GatewayResponse`` JSON.
"""

from __future__ import annotations

import io
import logging
from typing import Any, Dict, List, Optional

import httpx

from ..core.exceptions import APIError, GatewayError, NetworkError

logger = logging.getLogger(__name__)

# Max upload size mirrors ``utils.MaxUploadSize`` in Go (512 MiB)
MAX_UPLOAD_SIZE = 512 * 1024 * 1024


# ---------------------------------------------------------------------------
# Metroplex Gateway Client
# ---------------------------------------------------------------------------

class MetroplexGatewayClient:
    """
    HTTP client for the Metroplex plugin gateway.

    The gateway exposes a single ``POST /scan`` endpoint that fans out the
    uploaded binary to every registered plugin (or a filtered subset).

    Query parameters (mirrors ``gateway/main.go``):
      - ``plugins=clamav,yara``  — CSV list of plugin names
      - ``stage=4``              — select only plugins of the given stage
      - ``timeout=120s``         — per-request timeout

    The response is a ``GatewayResponse`` JSON::

        {
          "id":              "<uuid>",
          "total_time":      "12.34s",
          "plugins_queried": 9,
          "successful":      8,
          "failed":          1,
          "results": [
            {
              "plugin":   "angr",
              "status":   200,
              "duration": "5.6s",
              "data":     { ... },
              "error":    ""
            },
            ...
          ]
        }
    """

    def __init__(
        self,
        gateway_url: str = "https://gateway.plugins.localhost:8443",
        timeout: float = 120,
        verify_ssl: bool = False,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    # ---- public -----------------------------------------------------------

    def scan(
        self,
        file_bytes: bytes,
        filename: str = "sample.bin",
        *,
        plugins: Optional[List[str]] = None,
        stage: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Upload *file_bytes* to the gateway and return the aggregated result.

        Mirrors ``scanPlugin()`` in ``gateway/main.go``.
        """
        if len(file_bytes) > MAX_UPLOAD_SIZE:
            raise APIError(
                f"File exceeds maximum upload size ({MAX_UPLOAD_SIZE} bytes)",
                status_code=413,
            )

        params: Dict[str, str] = {}
        if plugins:
            params["plugins"] = ",".join(plugins)
        if stage is not None:
            params["stage"] = str(stage)
        effective_timeout = timeout or self.timeout
        if effective_timeout:
            params["timeout"] = f"{int(effective_timeout)}s"

        url = f"{self.gateway_url}/scan"

        files = {"malware": (filename, io.BytesIO(file_bytes), "application/octet-stream")}

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=effective_timeout + 10) as client:
                resp = client.post(url, files=files, params=params)
        except httpx.TimeoutException as exc:
            raise GatewayError(f"Gateway request timed out after {effective_timeout}s: {exc}")
        except httpx.ConnectError as exc:
            raise GatewayError(f"Cannot connect to gateway at {url}: {exc}")
        except httpx.HTTPError as exc:
            raise NetworkError(f"HTTP error communicating with gateway: {exc}")

        if resp.status_code != 200:
            raise APIError(
                f"Gateway returned HTTP {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
            )

        try:
            return resp.json()
        except (ValueError, TypeError) as exc:
            raise APIError(f"Gateway returned non-JSON response: {exc}")

    def scan_plugin(
        self,
        plugin_name: str,
        file_bytes: bytes,
        filename: str = "sample.bin",
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Send a sample directly to one plugin, bypassing the gateway.

        Each plugin listens on ``https://<plugin>.plugins.localhost:8443/scan``
        behind Traefik (or ``http://localhost:3993/scan`` inside Docker).
        """
        url = f"https://{plugin_name}.plugins.localhost:8443/scan"
        effective_timeout = timeout or self.timeout
        files = {"malware": (filename, io.BytesIO(file_bytes), "application/octet-stream")}

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=effective_timeout + 10) as client:
                resp = client.post(url, files=files)
        except httpx.TimeoutException as exc:
            raise GatewayError(f"Plugin {plugin_name} timed out: {exc}")
        except httpx.ConnectError as exc:
            raise GatewayError(f"Cannot connect to plugin {plugin_name} at {url}: {exc}")
        except httpx.HTTPError as exc:
            raise NetworkError(f"HTTP error talking to {plugin_name}: {exc}")

        if resp.status_code != 200:
            raise APIError(
                f"Plugin {plugin_name} returned HTTP {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
            )

        try:
            return resp.json()
        except (ValueError, TypeError) as exc:
            raise APIError(f"Plugin {plugin_name} returned non-JSON response: {exc}")

    def list_plugins(self) -> List[Dict[str, Any]]:
        """``GET /plugins`` — list all registered plugin endpoints."""
        url = f"{self.gateway_url}/plugins"
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=10) as client:
                resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
        except (ConnectionError, ValueError, TypeError, RuntimeError, OSError, TimeoutError) as exc:
            raise GatewayError(f"Failed to list plugins: {exc}")

    def health(self) -> Dict[str, Any]:
        """``GET /health`` — gateway health check."""
        url = f"{self.gateway_url}/health"
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=5) as client:
                resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
        except (ConnectionError, ValueError, TypeError, RuntimeError, OSError, TimeoutError) as exc:
            raise GatewayError(f"Gateway health check failed: {exc}")


# ---------------------------------------------------------------------------
# VMDragonSlayer API Client
# ---------------------------------------------------------------------------

class APIClient:
    """
    Client for the VMDragonSlayer FastAPI server.

    Usage::

        client = create_client("http://localhost:8000")
        result = client.analyze(open("sample.exe", "rb").read())
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float = 300,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def analyze(
        self,
        binary_data: bytes,
        analysis_type: str = "hybrid",
        **options: Any,
    ) -> Dict[str, Any]:
        """``POST /upload-analyze`` — multipart file upload."""
        url = f"{self.base_url}/upload-analyze"
        files = {"file": ("sample.bin", io.BytesIO(binary_data), "application/octet-stream")}
        params = {"analysis_type": analysis_type}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, files=files, params=params)
        except httpx.TimeoutException as exc:
            raise NetworkError(f"Timed out connecting to {url}: {exc}")
        except httpx.HTTPError as exc:
            raise NetworkError(f"HTTP error: {exc}")

        if resp.status_code != 200:
            raise APIError(
                f"Server returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        return resp.json()

    def health(self) -> Dict[str, Any]:
        """``GET /health``."""
        url = f"{self.base_url}/health"
        with httpx.Client(timeout=5) as client:
            resp = client.get(url)
        resp.raise_for_status()
        return resp.json()

    def status(self) -> Dict[str, Any]:
        """``GET /status``."""
        url = f"{self.base_url}/status"
        with httpx.Client(timeout=5) as client:
            resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def create_client(base_url: str = "http://127.0.0.1:8000", **kwargs: Any) -> APIClient:
    """Factory helper."""
    return APIClient(base_url=base_url, **kwargs)

