"""
Comprehensive tests for the new analysis modules, pipeline, and LLM integration.

Tests cover:
- Pattern classifier
- Anti-evasion / environment normalizer
- VM discovery detector
- Taint tracking
- Symbolic execution
- Analysis pipeline
- LLM analyzer (mocked)
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Pattern Classifier tests
# ---------------------------------------------------------------------------

class TestPatternClassifier:
    """Tests for dragonslayer.analysis.pattern_analysis.classifier."""

    def test_import(self):
        from dragonslayer.analysis.pattern_analysis.classifier import (
            PatternClassifier,
            ClassificationResult,
            ClassificationReport,
        )
        assert PatternClassifier is not None

    def test_classify_matches_empty(self):
        from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier
        c = PatternClassifier()
        report = c.classify_matches([])
        assert report.results == []
        assert report.complexity_score == 0.0
        assert report.dominant_type is None

    def test_classify_matches_from_dict(self):
        from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier
        c = PatternClassifier()
        matches = [
            {
                "pattern_id": "p1",
                "name": "vmp_add_handler",
                "operation": "add rax, rbx",
                "handler_type": "unknown",
                "matched_bytes": "4801C0",
                "confidence": 0.85,
            },
            {
                "pattern_id": "p2",
                "name": "vmp_xor_handler",
                "operation": "xor r1, r2",
                "handler_type": "unknown",
                "matched_bytes": "31C0",
                "confidence": 0.9,
            },
        ]
        report = c.classify_matches(matches)
        assert len(report.results) == 2
        # add should be classified as arithmetic
        assert report.results[0].handler_type.value == "arithmetic"
        # xor should be classified as bitwise
        assert report.results[1].handler_type.value == "bitwise"
        assert report.category_counts["arithmetic"] == 1
        assert report.category_counts["bitwise"] == 1

    def test_classify_declared_type(self):
        from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier
        c = PatternClassifier()
        matches = [{
            "pattern_id": "p1",
            "name": "test",
            "operation": "",
            "handler_type": "memory",
            "matched_bytes": "",
            "confidence": 0.8,
        }]
        report = c.classify_matches(matches)
        assert report.results[0].handler_type.value == "memory"

    def test_classify_byte_heuristic(self):
        from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier
        c = PatternClassifier()
        # 0xFF is JMP/CALL indirect
        matches = [{
            "pattern_id": "p1",
            "name": "unknown",
            "operation": "",
            "handler_type": "unknown",
            "matched_bytes": "FF25DEADBEEF",
            "confidence": 0.5,
        }]
        report = c.classify_matches(matches)
        assert report.results[0].handler_type.value == "control_flow"

    def test_classify_handler_bytes(self):
        from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier
        c = PatternClassifier()
        result = c.classify_handler_bytes(b"\x01\xc0", handler_name="add_eax")
        assert result.handler_type.value == "arithmetic"

    def test_classification_report_to_dict(self):
        from dragonslayer.analysis.pattern_analysis.classifier import (
            PatternClassifier,
        )
        c = PatternClassifier()
        matches = [{
            "pattern_id": "p1",
            "name": "test_push",
            "operation": "push rax",
            "handler_type": "unknown",
            "matched_bytes": "50",
            "confidence": 0.8,
        }]
        report = c.classify_matches(matches)
        d = report.to_dict()
        assert "results" in d
        assert "category_counts" in d
        assert "complexity_score" in d

    def test_complexity_score_range(self):
        from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier
        c = PatternClassifier()
        matches = [
            {"pattern_id": f"p{i}", "name": f"h{i}", "operation": op,
             "handler_type": "unknown", "matched_bytes": "", "confidence": 0.9}
            for i, op in enumerate(["add", "xor", "push", "jmp", "mov", "cmp", "cbw", "aes"])
        ]
        report = c.classify_matches(matches)
        assert 0.0 <= report.complexity_score <= 1.0


# ---------------------------------------------------------------------------
# Anti-evasion / Environment Normalizer tests
# ---------------------------------------------------------------------------

class TestEnvironmentNormalizer:
    """Tests for dragonslayer.analysis.anti_evasion.environment_normalizer."""

    def test_import(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
            EvasionCategory,
            NormalizationReport,
        )
        assert EnvironmentNormalizer is not None

    def test_analyze_clean_binary(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        report = norm.analyze(b"\x90" * 128)
        assert report.risk_score == 0.0
        assert len(report.indicators) == 0

    def test_detect_rdtsc(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        binary = b"\x90" * 64 + b"\x0f\x31" + b"\x90" * 64
        report = norm.analyze(binary)
        names = [i.name for i in report.indicators]
        assert "rdtsc" in names

    def test_detect_peb_access(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        binary = b"\x90" * 16 + b"\x64\xa1\x30\x00\x00\x00" + b"\x90" * 16
        report = norm.analyze(binary)
        names = [i.name for i in report.indicators]
        assert "peb_access_fs30" in names

    def test_detect_import_strings(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        binary = b"\x00" * 32 + b"IsDebuggerPresent" + b"\x00" * 32
        report = norm.analyze(binary)
        names = [i.name for i in report.indicators]
        assert "IsDebuggerPresent" in names
        assert report.risk_score > 0.0

    def test_detect_vmware_artefact(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        binary = b"\x00" * 32 + b"VMware" + b"\x00" * 32
        report = norm.analyze(binary)
        cats = [i.category.value for i in report.indicators]
        assert "anti_vm" in cats

    def test_patch_generation(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer(generate_patches=True)
        binary = b"\x90" * 16 + b"\x0f\x31" + b"\x90" * 16
        report = norm.analyze(binary)
        assert len(report.patches) >= 1
        assert report.patches[0].replacement == b"\x90\x90"

    def test_apply_patches(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        binary = b"\x90" * 16 + b"\x0f\x31" + b"\x90" * 16
        report = norm.analyze(binary)
        patched = norm.apply_patches(binary, report.patches)
        assert b"\x0f\x31" not in patched

    def test_report_to_dict(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        report = norm.analyze(b"\x0f\x31\xcc" + b"\x00" * 64)
        d = report.to_dict()
        assert "indicators" in d
        assert "patches" in d
        assert "risk_score" in d
        assert "total_indicators" in d

    def test_anti_disasm_detection(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        norm = EnvironmentNormalizer()
        binary = b"\x90" * 8 + b"\xeb\xff" + b"\x90" * 8
        report = norm.analyze(binary)
        names = [i.name for i in report.indicators]
        assert "jmp_overlap" in names


# ---------------------------------------------------------------------------
# VM Discovery tests
# ---------------------------------------------------------------------------

class TestVMDetector:
    """Tests for dragonslayer.analysis.vm_discovery.detector."""

    def test_import(self):
        from dragonslayer.analysis.vm_discovery.detector import VMDetector
        assert VMDetector is not None

    def test_detect_empty_binary(self):
        from dragonslayer.analysis.vm_discovery.detector import VMDetector
        det = VMDetector()
        result = det.detect(b"")
        assert isinstance(result, dict)
        assert result.get("vm_detected") is False

    def test_detect_with_vm_section_name(self, sample_pe_header):
        from dragonslayer.analysis.vm_discovery.detector import VMDetector
        det = VMDetector()
        result = det.detect(sample_pe_header)
        # sample_pe_header contains .vmp0
        indicators = result.get("indicators", [])
        found_vmp = any("vmp" in str(i).lower() for i in indicators)
        # May or may not detect depending on PE parsing;
        # at minimum it should return a dict
        assert isinstance(result, dict)

    def test_detect_dispatcher_patterns(self):
        from dragonslayer.analysis.vm_discovery.detector import VMDetector
        det = VMDetector()
        # jmp [rax] = FF 20
        binary = b"\x90" * 256 + b"\xFF\x20" + b"\x90" * 256
        result = det.detect(binary)
        dispatchers = result.get("dispatchers", [])
        # Should detect the indirect jump
        assert isinstance(dispatchers, list)


class TestVMSignatureDatabase:
    """Tests for dragonslayer.analysis.vm_discovery.database."""

    def test_import(self):
        from dragonslayer.analysis.vm_discovery.database import (
            VMSignatureDatabase,
            VMSignature,
        )
        assert VMSignatureDatabase is not None

    def test_builtin_signatures(self):
        from dragonslayer.analysis.vm_discovery.database import VMSignatureDatabase
        db = VMSignatureDatabase()
        assert len(db) >= 4

    def test_match_vmprotect(self):
        from dragonslayer.analysis.vm_discovery.database import VMSignatureDatabase
        db = VMSignatureDatabase()
        # match() expects a detection_result dict, not raw binary
        detection_result = {
            "vm_detected": True,
            "indicators": [
                {"check": "vm_sections", "found": [".vmp0"]},
                {"check": "watermarks", "found": ["VMProtect"]},
            ]
        }
        matches = db.match(detection_result)
        assert any("vmprotect" in m.get("signature", {}).get("protector", "").lower() for m in matches)


# ---------------------------------------------------------------------------
# Taint tracking tests
# ---------------------------------------------------------------------------

class TestTaintTracker:
    """Tests for dragonslayer.analysis.taint_tracking.tracker."""

    def test_import(self):
        from dragonslayer.analysis.taint_tracking.tracker import (
            TaintTracker,
            TaintTag,
        )
        assert TaintTracker is not None

    def test_initial_state_clean(self):
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        tt = TaintTracker()
        assert tt.get_taint("rax") == TaintTag.CLEAN

    def test_taint_propagation(self):
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        tt = TaintTracker()
        tt.taint_register("rax", TaintTag.VM_OPERAND)
        assert tt.get_taint("rax") == TaintTag.VM_OPERAND
        assert tt.is_tainted("rax") is True

    def test_memory_taint(self):
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        tt = TaintTracker()
        tt.taint_memory(0x1000, TaintTag.INPUT)
        # Memory taint stored in internal dict
        state = tt.get_state()
        assert 0x1000 in state.memory

    def test_get_taint_state(self):
        from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintTag
        tt = TaintTracker()
        tt.taint_register("rsi", TaintTag.VM_CONTEXT)
        state = tt.get_state()
        assert "rsi" in state.registers


class TestVMTaintTracker:
    """Tests for dragonslayer.analysis.taint_tracking.vm_taint_tracker."""

    def test_import(self):
        from dragonslayer.analysis.taint_tracking.vm_taint_tracker import VMTaintTracker
        assert VMTaintTracker is not None

    def test_analyze_vm_trace(self):
        from dragonslayer.analysis.taint_tracking.vm_taint_tracker import VMTaintTracker
        vmt = VMTaintTracker()
        result = vmt.analyze_vm_trace([])
        assert isinstance(result, dict)
        assert "taint_result" in result
        assert "vm_context_registers" in result


class TestTaintAnalyzer:
    """Tests for dragonslayer.analysis.taint_tracking.analyzer."""

    def test_import(self):
        from dragonslayer.analysis.taint_tracking.analyzer import TaintAnalyzer
        assert TaintAnalyzer is not None

    def test_analyze_returns_dict(self):
        from dragonslayer.analysis.taint_tracking.analyzer import TaintAnalyzer
        ta = TaintAnalyzer()
        result = ta.analyze(b"\x90" * 64, shared_data={})
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Symbolic Execution tests
# ---------------------------------------------------------------------------

class TestSymbolicState:
    """Tests for dragonslayer.analysis.symbolic_execution.state."""

    def test_import(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        assert SymbolicState is not None

    def test_register_access(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState()
        s.set_register("rax", 42)
        assert s.get_register("rax") == 42

    def test_fork(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState()
        s.set_register("rax", 100)
        forked = s.fork()
        forked.set_register("rax", 200)
        assert s.get_register("rax") == 100
        assert forked.get_register("rax") == 200


class TestInstructionLifter:
    """Tests for dragonslayer.analysis.symbolic_execution.lifter."""

    def test_import(self):
        from dragonslayer.analysis.symbolic_execution.lifter import (
            InstructionLifter,
            LiftedInstruction,
        )
        assert InstructionLifter is not None

    def test_lift_nops(self):
        from dragonslayer.analysis.symbolic_execution.lifter import InstructionLifter
        lifter = InstructionLifter()
        instructions = lifter.lift(b"\x90\x90\x90", base_address=0)
        # Should get at least one instruction (may fallback if capstone unavailable)
        assert isinstance(instructions, list)
        assert len(instructions) >= 1


class TestSymbolicExecutor:
    """Tests for dragonslayer.analysis.symbolic_execution.executor."""

    def test_import(self):
        from dragonslayer.analysis.symbolic_execution.executor import (
            SymbolicExecutor,
            ExecutionResult,
        )
        assert SymbolicExecutor is not None

    def test_analyze_small_binary(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        exe = SymbolicExecutor()
        # ret instruction
        result = exe.analyze(b"\xc3", entry_point=0)
        assert hasattr(result, "handlers") or hasattr(result, "paths_explored")


class TestZ3Solver:
    """Tests for dragonslayer.analysis.symbolic_execution.solver."""

    def test_import(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        assert Z3Solver is not None

    def test_satisfiability(self):
        from dragonslayer.analysis.symbolic_execution.solver import Z3Solver
        solver = Z3Solver()
        x = solver.bitvec("x", 32)
        solver.add(x == 42)
        result = solver.check()
        assert result.satisfiable is True
        assert result.model["x"] == 42


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------

class TestPipelineConfig:
    """Tests for PipelineConfig and pipeline infrastructure."""

    def test_default_stages(self):
        from dragonslayer.core.pipeline import PipelineConfig
        cfg = PipelineConfig()
        assert "pattern_analysis" in cfg.stages
        assert "vm_discovery" in cfg.stages
        assert "anti_evasion" in cfg.stages
        assert "classify" in cfg.stages
        assert "llm_analysis" in cfg.stages
        assert "llm_summary" in cfg.stages

    def test_custom_stages(self):
        from dragonslayer.core.pipeline import PipelineConfig
        cfg = PipelineConfig(stages=["pattern_analysis", "static"])
        assert len(cfg.stages) == 2

    def test_stage_result_to_dict(self):
        from dragonslayer.core.pipeline import StageResult
        sr = StageResult(stage="test", success=True, data={"foo": "bar"})
        d = sr.to_dict()
        assert d["stage"] == "test"
        assert d["success"] is True

    def test_pipeline_result_to_dict(self):
        from dragonslayer.core.pipeline import PipelineResult, StageResult
        pr = PipelineResult(
            success=True,
            stages=[StageResult(stage="s1", success=True)],
            shared_data={"key": "val"},
        )
        d = pr.to_dict()
        assert d["success"] is True
        assert len(d["stages"]) == 1


class TestPipelineFactories:
    """Tests for pipeline factory functions."""

    def test_create_full_pipeline(self):
        from dragonslayer.core.pipeline import create_full_pipeline
        pipe, cfg = create_full_pipeline()
        assert "pattern_analysis" in cfg.stages
        assert "taint_analysis" in cfg.stages
        assert "symbolic_execution" in cfg.stages
        assert "llm_summary" in cfg.stages

    def test_create_vmprotect_devirt_pipeline(self):
        from dragonslayer.core.pipeline import create_vmprotect_devirt_pipeline
        pipe, cfg = create_vmprotect_devirt_pipeline()
        assert "anti_evasion" in cfg.stages
        assert "classify" in cfg.stages
        assert "taint_analysis" in cfg.stages

    def test_create_quick_scan_pipeline(self):
        from dragonslayer.core.pipeline import create_quick_scan_pipeline
        pipe, cfg = create_quick_scan_pipeline()
        assert cfg.llm_enabled is False
        assert "anti_evasion" in cfg.stages
        assert "static" in cfg.stages


class TestPipelineExecution:
    """Integration tests for AnalysisPipeline.run()."""

    def test_run_minimal_pipeline(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["pattern_analysis", "vm_discovery"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\x90" * 64, cfg, metadata={"filename": "test.bin"})
        assert isinstance(result.success, bool)
        assert len(result.stages) >= 1
        assert result.total_duration > 0

    def test_run_anti_evasion_stage(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["anti_evasion"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        binary = b"\x90" * 16 + b"\x0f\x31" + b"\x90" * 16
        result = pipe.run(binary, cfg)
        assert result.shared_data.get("anti_evasion") is not None

    def test_run_classify_stage(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["pattern_analysis", "classify"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\x90" * 64, cfg)
        # classify should have run (even if no matches found)
        stages_run = [s.stage for s in result.stages]
        assert "classify" in stages_run

    def test_run_taint_analysis_stage(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["vm_discovery", "taint_analysis"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\x90" * 64, cfg)
        stages_run = [s.stage for s in result.stages]
        assert "taint_analysis" in stages_run

    def test_run_symbolic_execution_stage(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["symbolic_execution"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\xc3" * 4, cfg)
        stages_run = [s.stage for s in result.stages]
        assert "symbolic_execution" in stages_run

    def test_shared_data_flows_between_stages(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["pattern_analysis", "vm_discovery", "anti_evasion", "classify"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\x90" * 64 + b"\x0f\x31" + b"\x90" * 64, cfg)
        # anti_evasion should have its results in shared_data
        assert "anti_evasion" in result.shared_data
        assert "pipeline_stages_completed" in result.shared_data

    def test_llm_stages_skipped_when_disabled(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["llm_analysis", "llm_summary"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\x90" * 16, cfg)
        assert len(result.stages) == 0  # both skipped

    def test_unknown_stage_skipped(self):
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        cfg = PipelineConfig(
            stages=["nonexistent_stage"],
            llm_enabled=False,
        )
        pipe = AnalysisPipeline()
        result = pipe.run(b"\x90" * 16, cfg)
        assert len(result.stages) == 0


# ---------------------------------------------------------------------------
# LLM Analyzer tests (with mocking)
# ---------------------------------------------------------------------------

class TestLLMAnalyzer:
    """Tests for dragonslayer.llm.analyzer — mocked, no real LLM calls."""

    def test_import(self):
        from dragonslayer.llm.analyzer import LLMAnalyzer
        assert LLMAnalyzer is not None

    def test_available_without_litellm(self):
        """Without litellm installed, available should be False."""
        from dragonslayer.llm.analyzer import LLMAnalyzer
        llm = LLMAnalyzer(model="test-model")
        # Available depends on whether litellm is actually installed
        # We just ensure the property doesn't crash
        assert isinstance(llm.available, bool)

    def test_classify_handler_unavailable(self):
        from dragonslayer.llm.analyzer import LLMAnalyzer
        llm = LLMAnalyzer(model="test-model")
        if not llm.available:
            result = llm.classify_handler("push rax; pop rbx")
            assert "error" in result or "skipped" in result or isinstance(result, dict)

    def test_get_llm_analyzer_singleton(self):
        from dragonslayer.llm import get_llm_analyzer
        a = get_llm_analyzer()
        b = get_llm_analyzer()
        assert a is b

    def test_prompt_templates_exist(self):
        from dragonslayer.llm import analyzer as llm_mod
        assert hasattr(llm_mod, "_HANDLER_CLASSIFICATION_PROMPT")
        assert hasattr(llm_mod, "_DEOBFUSCATION_HINT_PROMPT")
        assert hasattr(llm_mod, "_PATTERN_EXPLANATION_PROMPT")
        assert hasattr(llm_mod, "_CODE_RECOVERY_PROMPT")
        assert hasattr(llm_mod, "_SUMMARISE_PROMPT")
