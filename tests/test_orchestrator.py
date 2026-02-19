"""Tests for the orchestrator (local engines only — no gateway needed)."""

from __future__ import annotations

import pytest

from dragonslayer.core.config import reset_config
from dragonslayer.core.orchestrator import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisType,
    EngineResult,
    FileInfo,
    Orchestrator,
    STAGE4_PLUGINS,
    STAGE5_PLUGINS,
    VMDragonSlayerAPI,
)
from dragonslayer.core.exceptions import InvalidDataError


class TestFileInfo:

    def test_from_bytes(self):
        data = b"hello world"
        fi = FileInfo.from_bytes(data, path="test.bin")
        assert fi.size == 11
        assert fi.path == "test.bin"
        assert len(fi.md5) == 32
        assert len(fi.sha256) == 64


class TestAnalysisRequest:

    def test_auto_creates_file_info(self):
        req = AnalysisRequest(binary_data=b"\x90\x90")
        assert req.file_info is not None
        assert req.file_info.size == 2

    def test_rejects_empty_data(self):
        with pytest.raises(InvalidDataError, match="must not be empty"):
            AnalysisRequest(binary_data=b"")

    def test_string_analysis_type_coerced(self):
        req = AnalysisRequest(binary_data=b"\xCC", analysis_type="hybrid")
        assert req.analysis_type is AnalysisType.HYBRID


class TestAnalysisResult:

    def test_to_dict(self):
        er = EngineResult(engine="test", success=True, data={"key": "val"})
        ar = AnalysisResult(success=True, engine_results=[er])
        d = ar.to_dict()
        assert d["success"] is True
        assert d["engine_results"][0]["engine"] == "test"


class TestOrchestrator:

    def setup_method(self):
        reset_config()

    def teardown_method(self):
        reset_config()

    def test_pattern_analysis(self, sample_binary_with_pattern: bytes):
        """Run a PATTERN_ANALYSIS dispatch against a binary with an embedded VMP signature."""
        orch = Orchestrator()
        try:
            result = orch.analyze_binary(
                sample_binary_with_pattern,
                AnalysisType.PATTERN_ANALYSIS,
            )
            assert isinstance(result, AnalysisResult)
            assert result.analysis_type == "pattern_analysis"
            # The engine should have run (success or graceful failure)
            assert len(result.engine_results) >= 1
        finally:
            orch.shutdown()

    def test_vm_discovery_pe(self, sample_pe_header: bytes):
        """VM discovery should detect the .vmp0 section in a PE-like binary."""
        orch = Orchestrator()
        try:
            result = orch.analyze_binary(
                sample_pe_header,
                AnalysisType.VM_DISCOVERY,
            )
            assert result.success
            vm_data = result.results.get("vm_discovery", {})
            assert vm_data.get("vm_detected") is True
            assert vm_data.get("file_type") == "PE"
        finally:
            orch.shutdown()

    def test_vm_discovery_no_vm(self):
        """A plain-text buffer should NOT be flagged as VM-protected."""
        orch = Orchestrator()
        try:
            result = orch.analyze_binary(
                b"This is just a plain text file with no VM indicators at all." * 10,
                AnalysisType.VM_DISCOVERY,
            )
            assert result.success
            vm_data = result.results.get("vm_discovery", {})
            assert vm_data.get("vm_detected") is False
        finally:
            orch.shutdown()

    def test_hybrid_runs_two_engines(self, sample_pe_header: bytes):
        """HYBRID should expand to pattern_analysis + vm_discovery."""
        orch = Orchestrator()
        try:
            result = orch.analyze_binary(sample_pe_header, AnalysisType.HYBRID)
            engines = {er.engine for er in result.engine_results}
            assert "vm_discovery" in engines
            assert "pattern_analysis" in engines
        finally:
            orch.shutdown()

    def test_resolve_engines_composite(self):
        engines = Orchestrator._resolve_engines(AnalysisType.FULL_ANALYSIS)
        assert "pattern_analysis" in engines
        assert "vm_discovery" in engines
        assert "local_static" in engines
        assert "local_dynamic" in engines
        assert "local_enrichment" in engines
        assert "local_reporting" in engines

    def test_supported_analysis_types(self):
        types = Orchestrator.get_supported_analysis_types()
        assert "hybrid" in types
        assert "full_analysis" in types
        assert "vm_discovery" in types


class TestPluginLists:
    """Verify the stage-4 / stage-5 plugin name lists are consistent."""

    def test_stage4_contains_angr(self):
        assert "angr" in STAGE4_PLUGINS

    def test_stage4_contains_triton(self):
        assert "triton" in STAGE4_PLUGINS

    def test_stage5_contains_similarity(self):
        assert "similarity" in STAGE5_PLUGINS


class TestVMDragonSlayerAPI:
    """Test the high-level façade used by server.py."""

    def setup_method(self):
        reset_config()

    def teardown_method(self):
        reset_config()

    def test_analyze_binary_data(self, sample_pe_header: bytes):
        api = VMDragonSlayerAPI()
        result = api.analyze_binary_data(sample_pe_header, analysis_type="hybrid")
        assert isinstance(result, dict)
        assert "success" in result
        assert "engine_results" in result

    def test_get_types(self):
        types = VMDragonSlayerAPI.get_supported_analysis_types()
        assert "hybrid" in types
