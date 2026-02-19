"""Tests for the API clients.

These tests exercise the client classes without hitting a real server.
We mock ``httpx.Client`` to verify correct request construction.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dragonslayer.api.client import (
    APIClient,
    MetroplexGatewayClient,
    MAX_UPLOAD_SIZE,
    create_client,
)
from dragonslayer.core.exceptions import APIError, GatewayError


class TestMetroplexGatewayClient:

    def test_defaults(self):
        c = MetroplexGatewayClient()
        assert "gateway.plugins.localhost" in c.gateway_url

    def test_scan_rejects_oversized_file(self):
        c = MetroplexGatewayClient()
        with pytest.raises(APIError, match="maximum upload size"):
            c.scan(b"\x00" * (MAX_UPLOAD_SIZE + 1))

    @patch("dragonslayer.api.client.httpx.Client")
    def test_scan_sends_multipart(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "id": "abc",
            "total_time": "1s",
            "plugins_queried": 1,
            "successful": 1,
            "failed": 0,
            "results": [],
        }
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_resp)))
        ctx.__exit__ = MagicMock(return_value=False)
        MockClient.return_value = ctx

        c = MetroplexGatewayClient(gateway_url="https://gw.test:8443", timeout=30)
        result = c.scan(b"\xCC", filename="test.bin", plugins=["angr", "triton"], stage=4)

        assert result["successful"] == 1
        # Verify httpx.Client was called with verify=False and proper timeout
        MockClient.assert_called_once()

    @patch("dragonslayer.api.client.httpx.Client")
    def test_scan_raises_on_non_200(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_resp)))
        ctx.__exit__ = MagicMock(return_value=False)
        MockClient.return_value = ctx

        c = MetroplexGatewayClient()
        with pytest.raises(APIError, match="HTTP 500"):
            c.scan(b"\x00")


class TestAPIClient:

    def test_factory(self):
        c = create_client("http://localhost:9999")
        assert isinstance(c, APIClient)
        assert c.base_url == "http://localhost:9999"

    @patch("dragonslayer.api.client.httpx.Client")
    def test_analyze_calls_upload_analyze(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True}
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_resp)))
        ctx.__exit__ = MagicMock(return_value=False)
        MockClient.return_value = ctx

        c = APIClient()
        result = c.analyze(b"\x90\x90")
        assert result["success"] is True
