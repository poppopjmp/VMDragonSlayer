"""Tests for the exception hierarchy."""

from dragonslayer.core.exceptions import (
    AnalysisError,
    APIError,
    ConfigurationError,
    DevirtualizationError,
    GatewayError,
    InvalidDataError,
    NetworkError,
    PluginError,
    VMDragonSlayerError,
)


class TestExceptionHierarchy:
    """Verify inheritance chains and custom attributes."""

    def test_base_inherits_from_exception(self):
        assert issubclass(VMDragonSlayerError, Exception)

    def test_configuration_error(self):
        exc = ConfigurationError("bad key")
        assert isinstance(exc, VMDragonSlayerError)
        assert exc.error_code == "CONFIGURATION_ERROR"

    def test_invalid_data_error(self):
        exc = InvalidDataError("empty")
        assert isinstance(exc, VMDragonSlayerError)
        assert exc.error_code == "INVALID_DATA"

    def test_analysis_error(self):
        exc = AnalysisError("boom")
        assert isinstance(exc, VMDragonSlayerError)

    def test_devirtualization_is_analysis(self):
        exc = DevirtualizationError("fail")
        assert isinstance(exc, AnalysisError)
        assert exc.error_code == "DEVIRTUALIZATION_ERROR"

    def test_network_error(self):
        exc = NetworkError("timeout")
        assert isinstance(exc, VMDragonSlayerError)

    def test_api_error_status_code(self):
        exc = APIError("not found", status_code=404)
        assert exc.status_code == 404
        assert isinstance(exc, VMDragonSlayerError)

    def test_plugin_error_name(self):
        exc = PluginError("died", plugin_name="angr")
        assert exc.plugin_name == "angr"
        assert isinstance(exc, AnalysisError)

    def test_gateway_error_is_network(self):
        exc = GatewayError("unreachable")
        assert isinstance(exc, NetworkError)
        assert exc.error_code == "GATEWAY_ERROR"

    def test_details_dict(self):
        exc = VMDragonSlayerError("test", details={"key": "val"})
        assert exc.details == {"key": "val"}

    def test_custom_error_code(self):
        exc = VMDragonSlayerError("test", error_code="CUSTOM_001")
        assert exc.error_code == "CUSTOM_001"
