"""
Tests for the plugin framework: registry, storage backends, and plugin execution.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from dragonslayer.plugins import (
    Plugin,
    PluginContext,
    PluginResult,
    Stage,
    get_all_plugins,
    get_plugin,
    list_plugins,
    register_plugin,
    _REGISTRY,
)
from dragonslayer.plugins._storage import (
    MemoryBackend,
    LocalFileBackend,
    create_storage,
)


# ---------------------------------------------------------------------------
# Registry & base class
# ---------------------------------------------------------------------------


class TestPluginRegistry:
    """Tests for the global plugin registry and registration decorator."""

    def test_registry_not_empty(self):
        """Auto-discovery should have loaded at least the always-available plugins."""
        assert len(_REGISTRY) > 0

    def test_frankenstrings_registered(self):
        """FrankenStrings uses only stdlib – it's always available."""
        assert "frankenstrings" in _REGISTRY

    def test_list_plugins_all(self):
        names = list_plugins(available_only=False)
        assert isinstance(names, list)
        assert len(names) > 0

    def test_list_plugins_by_stage_static(self):
        static = list_plugins(stage=Stage.STATIC, available_only=False)
        assert "pe_analyzer" in static
        assert "elf_analyzer" in static
        assert "macho_analyzer" in static
        assert "cert_analyzer" in static
        assert "frankenstrings" in static

    def test_list_plugins_by_stage_dynamic(self):
        dynamic = list_plugins(stage=Stage.DYNAMIC, available_only=False)
        assert "angr" in dynamic
        assert "triton" in dynamic
        assert "qiling" in dynamic
        assert "strelka" in dynamic

    def test_list_plugins_by_stage_enrichment(self):
        enrichment = list_plugins(stage=Stage.ENRICHMENT, available_only=False)
        assert "similarity" in enrichment
        assert "function_similarity" in enrichment
        assert "vector_share" in enrichment

    def test_list_plugins_by_stage_reporting(self):
        reporting = list_plugins(stage=Stage.REPORTING, available_only=False)
        assert "reporter" in reporting
        assert "network_graph" in reporting

    def test_get_plugin_returns_instance(self):
        p = get_plugin("frankenstrings")
        assert p is not None
        assert isinstance(p, Plugin)
        assert p.name == "frankenstrings"

    def test_get_plugin_unknown(self):
        assert get_plugin("nonexistent_plugin_xyz") is None


# ---------------------------------------------------------------------------
# PluginResult / PluginContext
# ---------------------------------------------------------------------------


class TestPluginDataClasses:
    def test_result_to_dict(self):
        r = PluginResult(plugin="test", success=True, data={"key": "val"})
        d = r.to_dict()
        assert d["plugin"] == "test"
        assert d["success"] is True
        assert d["data"]["key"] == "val"

    def test_context_defaults(self):
        ctx = PluginContext()
        assert ctx.shared_data == {}
        assert ctx.sample_hash == ""
        assert ctx.work_dir == ""

    def test_context_shared_data_mutable(self):
        ctx = PluginContext()
        ctx.shared_data["foo"] = 42
        assert ctx.shared_data["foo"] == 42


# ---------------------------------------------------------------------------
# Storage backends
# ---------------------------------------------------------------------------


class TestMemoryBackend:
    def test_store_and_get(self):
        be = MemoryBackend()
        be.store("idx", "doc1", {"hello": "world"})
        doc = be.get("idx", "doc1")
        assert doc is not None
        assert doc["hello"] == "world"

    def test_get_missing(self):
        be = MemoryBackend()
        assert be.get("idx", "missing") is None

    def test_delete(self):
        be = MemoryBackend()
        be.store("idx", "d1", {"a": 1})
        be.delete("idx", "d1")
        assert be.get("idx", "d1") is None

    def test_query_match(self):
        be = MemoryBackend()
        be.store("idx", "d1", {"name": "alice", "age": 30})
        be.store("idx", "d2", {"name": "bob", "age": 25})
        results = be.query("idx", {"match": {"name": "alice"}})
        assert len(results) == 1
        assert results[0]["name"] == "alice"

    def test_ensure_index_idempotent(self):
        be = MemoryBackend()
        be.ensure_index("new_idx")
        be.ensure_index("new_idx")  # no-op

    def test_store_bulk(self):
        be = MemoryBackend()
        docs = [{"id": str(i), "val": i} for i in range(5)]
        be.store_bulk("idx", docs, id_field="id")
        assert be.get("idx", "0") is not None
        assert be.get("idx", "4") is not None


class TestLocalFileBackend:
    def test_roundtrip(self, tmp_path):
        be = LocalFileBackend(base_dir=str(tmp_path))
        be.store("myindex", "doc1", {"key": "value"})
        doc = be.get("myindex", "doc1")
        assert doc is not None
        assert doc["key"] == "value"

    def test_delete(self, tmp_path):
        be = LocalFileBackend(base_dir=str(tmp_path))
        be.store("myindex", "doc1", {"key": "value"})
        be.delete("myindex", "doc1")
        assert be.get("myindex", "doc1") is None

    def test_query(self, tmp_path):
        be = LocalFileBackend(base_dir=str(tmp_path))
        be.store("idx", "d1", {"name": "alice"})
        be.store("idx", "d2", {"name": "bob"})
        results = be.query("idx", {"match": {"name": "bob"}})
        assert len(results) == 1
        assert results[0]["name"] == "bob"


class TestCreateStorage:
    def test_memory(self):
        be = create_storage("memory")
        assert isinstance(be, MemoryBackend)

    def test_local(self, tmp_path):
        be = create_storage("local", base_dir=str(tmp_path))
        assert isinstance(be, LocalFileBackend)

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            create_storage("oracle_db")


# ---------------------------------------------------------------------------
# FrankenStrings (always available — uses only stdlib)
# ---------------------------------------------------------------------------


class TestFrankenStringsPlugin:
    """FrankenStrings is always available (stdlib only) — good integration test."""

    def _get_plugin(self):
        p = get_plugin("frankenstrings")
        assert p is not None
        return p

    def test_available(self):
        p = self._get_plugin()
        assert p.available()
        assert p.stage == Stage.STATIC

    def test_empty_file_fails(self):
        p = self._get_plugin()
        ctx = PluginContext()
        result = p.safe_execute("", b"", ctx)
        assert result.success is False

    def test_pe_detection(self):
        # Minimal MZ header
        pe_data = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00"
        pe_data += b"\x00" * 200  # padding
        p = self._get_plugin()
        ctx = PluginContext()
        result = p.safe_execute("", pe_data, ctx)
        assert result.success is True
        assert result.data["metadata"]["format"] == "PE"
        assert "frankenstrings" in ctx.shared_data

    def test_ascii_string_extraction(self):
        data = b"\x00" * 100 + b"Hello World This Is A Test String!" + b"\x00" * 100
        p = self._get_plugin()
        ctx = PluginContext()
        result = p.safe_execute("", data, ctx)
        assert result.success is True
        assert result.data["statistics"]["ascii_strings"] >= 1

    def test_ioc_detection_url(self):
        data = b"\x00" * 50 + b"https://evil.example.com/malware/payload.exe" + b"\x00" * 50
        p = self._get_plugin()
        ctx = PluginContext()
        result = p.safe_execute("", data, ctx)
        assert result.success is True
        assert "url" in result.data["iocs"]


# ---------------------------------------------------------------------------
# Strelka Scanner (always available for basic analysis)
# ---------------------------------------------------------------------------


class TestStrelkaScanner:
    def _get_plugin(self):
        p = get_plugin("strelka")
        if p is None:
            pytest.skip("strelka plugin not available")
        return p

    def test_basic_analysis(self):
        s = self._get_plugin()
        ctx = PluginContext()
        data = b"Hello world this is some test data" * 100
        result = s.safe_execute("", data, ctx)
        assert result.success is True
        assert "size" in result.data
        assert "entropy" in result.data


# ---------------------------------------------------------------------------
# Orchestrator local-plugin integration
# ---------------------------------------------------------------------------


class TestOrchestratorLocalPlugins:
    """Test that the orchestrator can dispatch to local plugins."""

    def test_local_static_type_resolves(self):
        from dragonslayer.core.orchestrator import Orchestrator, AnalysisType, _COMPOSITE_TYPES
        engines = Orchestrator._resolve_engines(AnalysisType.LOCAL_STATIC)
        assert engines == ["local_static"]

    def test_local_all_resolves(self):
        from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
        engines = Orchestrator._resolve_engines(AnalysisType.LOCAL_ALL)
        assert "local_static" in engines
        assert "local_dynamic" in engines
        assert "local_enrichment" in engines
        assert "local_reporting" in engines

    def test_local_static_runs(self):
        from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
        orch = Orchestrator()
        try:
            # Minimal binary to trigger at least the frankenstrings plugin
            data = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00"
            data += b"\x00" * 500
            result = orch.analyze_binary(data, AnalysisType.LOCAL_STATIC)
            assert result.success is True
            # Should have at least run frankenstrings
            local_data = result.results.get("local_static", {})
            assert local_data.get("plugins_run", 0) > 0
        finally:
            orch.shutdown()
