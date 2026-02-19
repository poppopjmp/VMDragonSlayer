"""Tests for config.py."""

import os

import pytest

from dragonslayer.core.config import Config, get_config, reset_config
from dragonslayer.core.exceptions import ConfigurationError


class TestConfig:
    """Verify configuration loading and dot-notation access."""

    def setup_method(self):
        reset_config()

    def teardown_method(self):
        reset_config()

    def test_defaults_loaded(self):
        cfg = Config()
        assert cfg.get("analysis.timeout") == 1800
        assert cfg.get("api.port") == 8000
        assert cfg.get("api.host") == "127.0.0.1"

    def test_dot_notation_get(self):
        cfg = Config()
        assert cfg.get("logging.level") == "INFO"

    def test_missing_key_returns_default(self):
        cfg = Config()
        assert cfg.get("nonexistent.key", "fallback") == "fallback"

    def test_set_and_get(self):
        cfg = Config()
        cfg.set("custom.key", 42)
        assert cfg.get("custom.key") == 42

    def test_get_section(self):
        cfg = Config()
        section = cfg.get_section("api")
        assert "port" in section

    def test_singleton_get_config(self):
        c1 = get_config()
        c2 = get_config()
        assert c1 is c2

    def test_reset_clears_singleton(self):
        c1 = get_config()
        reset_config()
        c2 = get_config()
        assert c1 is not c2

    def test_validate_rejects_bad_port(self):
        cfg = Config()
        cfg.set("api.port", -1)
        with pytest.raises(ConfigurationError):
            cfg.validate()

    def test_validate_rejects_bad_timeout(self):
        cfg = Config()
        cfg.set("analysis.timeout", 0)
        with pytest.raises(ConfigurationError):
            cfg.validate()

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("VMDS_LOGGING_LEVEL", "DEBUG")
        reset_config()
        cfg = Config()
        assert cfg.get("logging.level") == "DEBUG"
