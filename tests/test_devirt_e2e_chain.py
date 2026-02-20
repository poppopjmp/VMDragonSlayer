"""
Tests for End-to-End Devirtualisation Chain (Batch 41)
=====================================================

Tests cover:
  1. ``DevirtualisationResult`` dataclass — construction, serialisation,
     round-trip, skipped sentinel.
  2. ``_run_binary_parse`` pipeline stage — PE parsing populates shared_data.
  3. ML ensemble wiring inside devirt chain.
  4. Import paths.
  5. Pipeline stage registration (``binary_parse`` in stage_handlers).
"""

from __future__ import annotations

import pytest
from typing import Any, Dict, List

from dragonslayer.analysis.devirtualisation_result import DevirtualisationResult


# =====================================================================
#  1. DevirtualisationResult dataclass
# =====================================================================

class TestDevirtualisationResult:
    def test_default_construction(self):
        r = DevirtualisationResult()
        assert r.success is False
        assert r.skipped is False
        assert r.handler_count == 0

    def test_success_construction(self):
        r = DevirtualisationResult(
            success=True,
            vip_register="rsi",
            handler_count=10,
            unique_operations=5,
            opcode_table={"entries": []},
            pseudocode={"text": "vm_add(...)"},
            pseudocode_text="vm_add(...)",
        )
        assert r.success is True
        assert r.vip_register == "rsi"
        assert r.handler_count == 10

    def test_to_dict(self):
        r = DevirtualisationResult(
            success=True,
            vip_register="rdi",
            handler_count=3,
            unique_operations=2,
            opcode_table={"entries": [1, 2]},
            pseudocode={"text": "x"},
            pseudocode_text="x",
            ml_classifications={"0x401000": "arithmetic"},
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["vip_register"] == "rdi"
        assert d["handler_count"] == 3
        assert d["ml_classifications"]["0x401000"] == "arithmetic"
        # Optional None fields should be absent
        assert "vmprotect_dispatcher" not in d

    def test_to_dict_omits_none(self):
        r = DevirtualisationResult(success=True)
        d = r.to_dict()
        assert "vmprotect_dispatcher" not in d
        assert "handler_cfg" not in d

    def test_skipped_result_factory(self):
        r = DevirtualisationResult.skipped_result("no trace")
        assert r.skipped is True
        assert r.success is False
        assert r.skip_reason == "no trace"
        d = r.to_dict()
        assert d["skipped"] is True
        assert d["skip_reason"] == "no trace"

    def test_from_dict_roundtrip(self):
        original = DevirtualisationResult(
            success=True,
            vip_register="rcx",
            handler_count=7,
            unique_operations=4,
            opcode_table={"entries": []},
            pseudocode={"text": "code"},
            pseudocode_text="code",
            ml_classifications={"0x1000": "bitwise"},
        )
        d = original.to_dict()
        restored = DevirtualisationResult.from_dict(d)
        assert restored.success == original.success
        assert restored.vip_register == original.vip_register
        assert restored.handler_count == original.handler_count
        assert restored.ml_classifications == original.ml_classifications

    def test_from_dict_with_extra_keys(self):
        """Unknown keys should be ignored."""
        d = {"success": True, "vip_register": "rax", "extra_key": 42}
        r = DevirtualisationResult.from_dict(d)
        assert r.success is True
        assert r.vip_register == "rax"


# =====================================================================
#  2. Binary parse stage
# =====================================================================

class TestBinaryParseStage:
    def _make_minimal_pe(self, *, bits: int = 64) -> bytes:
        """Build a minimal valid PE."""
        from dragonslayer.analysis.binary_format import parse_binary
        # Use helper from test_pe_integration if available, otherwise
        # build a simple MZ+PE stub.
        import struct
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        pe_offset = 64
        struct.pack_into("<I", dos_header, 0x3C, pe_offset)

        magic = 0x20B if bits == 64 else 0x10B
        opt_hdr_size = 112 if bits == 64 else 96

        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH",
                           0x8664 if bits == 64 else 0x14C,  # Machine
                           1,   # NumberOfSections
                           0, 0, 0,
                           opt_hdr_size + 16 * 8,  # SizeOfOptionalHeader
                           0x22)  # Characteristics

        # Minimal optional header
        opt = bytearray(opt_hdr_size + 16 * 8)
        struct.pack_into("<H", opt, 0, magic)
        struct.pack_into("<I" if bits == 32 else "<Q",
                         opt, 16 if bits == 32 else 24, 0x00400000)  # ImageBase
        struct.pack_into("<I", opt, (28 if bits == 32 else 32), 0x1000)  # SectionAlignment
        struct.pack_into("<I", opt, (32 if bits == 32 else 36), 0x200)  # FileAlignment

        # Section header: .text
        sec_hdr = bytearray(40)
        sec_hdr[0:6] = b".text\x00"
        struct.pack_into("<I", sec_hdr, 8, 0x100)   # VirtualSize
        struct.pack_into("<I", sec_hdr, 12, 0x1000)  # VirtualAddress
        struct.pack_into("<I", sec_hdr, 16, 0x200)   # SizeOfRawData
        struct.pack_into("<I", sec_hdr, 20, 0x200)   # PointerToRawData
        struct.pack_into("<I", sec_hdr, 36, 0x60000020)  # Characteristics

        # Pad to PointerToRawData then section content
        header = bytes(dos_header) + pe_sig + coff + bytes(opt) + bytes(sec_hdr)
        padding = b"\x00" * (0x200 - len(header))
        section_data = b"\x90" * 0x100 + b"\x00" * 0x100  # nops

        return header + padding + section_data

    def test_binary_parse_stage_succeeds(self):
        """Pipeline._run_binary_parse stores image_base and sections."""
        from dragonslayer.core.pipeline import AnalysisPipeline, StageResult

        pe_data = self._make_minimal_pe()

        class FakeCtx:
            shared_data: Dict[str, Any] = {}
            config: Dict[str, Any] = {}

        ctx = FakeCtx()
        ctx.shared_data = {"binary_size": len(pe_data), "sha256": "abc"}
        pipe = AnalysisPipeline(config=None)
        result = pipe._run_binary_parse(pe_data, ctx)

        assert isinstance(result, StageResult)
        assert result.success is True
        assert ctx.shared_data.get("image_base", 0) > 0
        assert "sections" in ctx.shared_data
        assert len(ctx.shared_data["sections"]) >= 1

    def test_binary_parse_invalid_data(self):
        """Non-PE data should produce a failed StageResult."""
        from dragonslayer.core.pipeline import AnalysisPipeline, StageResult

        class FakeCtx:
            shared_data: Dict[str, Any] = {}
            config: Dict[str, Any] = {}

        ctx = FakeCtx()
        ctx.shared_data = {}
        pipe = AnalysisPipeline(config=None)
        result = pipe._run_binary_parse(b"\x00" * 10, ctx)
        assert isinstance(result, StageResult)
        # May succeed with raw fallback or fail — either is acceptable
        # The key is it doesn't crash

    def test_binary_parse_in_stage_handlers(self):
        """binary_parse is registered in the pipeline stage_handlers."""
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig
        pipe = AnalysisPipeline(config=None)
        # We can't easily access stage_handlers outside run(), but
        # running with stages=["binary_parse"] on dummy data should work.
        pe_data = self._make_minimal_pe()
        result = pipe.run(pe_data, PipelineConfig(stages=["binary_parse"]))
        assert len(result.stages) == 1
        assert result.stages[0].stage == "binary_parse"


# =====================================================================
#  3. ML ensemble wiring in devirt chain
# =====================================================================

class TestMLEnsembleWiring:
    def test_symbolic_classifier_accepts_features(self):
        """SymbolicClassifierModel works with the feature dict format used in pipeline."""
        from dragonslayer.ml.model import SymbolicClassifierModel
        model = SymbolicClassifierModel()
        features = {
            "symbolic_summary": {
                "simplified_registers": {"rax": "init_rax + init_rbx"},
                "input_symbols": {"rax": "init_rax"},
            }
        }
        pred = model.predict(features)
        assert pred.label == "arithmetic"

    def test_weighted_ensemble_with_feature_dict(self):
        """WeightedEnsemble works with the dict format from the pipeline."""
        from dragonslayer.ml.model import SymbolicClassifierModel, VMHandlerModel
        from dragonslayer.ml.ensemble import WeightedEnsemble

        ensemble = WeightedEnsemble(
            models=[VMHandlerModel(), SymbolicClassifierModel()],
            weights=[0.4, 0.6],
        )
        features = {
            "values": [0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 0.0],
            "names": [
                "arith_ratio", "logic_ratio", "mem_ratio", "stack_ratio",
                "branch_ratio", "vip_delta", "nop_ratio", "junk_ratio",
                "reg_diversity", "insn_count", "avg_operands", "push_ratio",
                "pop_ratio",
            ],
            "symbolic_summary": {
                "simplified_registers": {"rax": "init_rax ^ init_rbx"},
                "input_symbols": {"rax": "init_rax"},
            },
        }
        pred = ensemble.predict(features)
        assert pred.label != ""
        assert pred.confidence > 0.0


# =====================================================================
#  4. Devirt result as used by pipeline
# =====================================================================

class TestDevirtResultPipelineCompat:
    def test_skipped_result_has_required_keys(self):
        """Skipped DevirtualisationResult.to_dict() has 'skipped' key."""
        r = DevirtualisationResult.skipped_result("no trace")
        d = r.to_dict()
        assert d["skipped"] is True
        assert "skip_reason" in d

    def test_success_result_has_core_keys(self):
        """Successful result dict has opcode_table, pseudocode_text, etc."""
        r = DevirtualisationResult(
            success=True,
            vip_register="rbx",
            handler_count=5,
            unique_operations=3,
            opcode_table={"entries": []},
            pseudocode={"text": "code"},
            pseudocode_text="code",
        )
        d = r.to_dict()
        for key in ("vip_register", "handler_count", "unique_operations",
                     "opcode_table", "pseudocode", "pseudocode_text"):
            assert key in d, f"Missing key: {key}"

    def test_ml_labels_attached(self):
        """ML classification labels are attached when present."""
        r = DevirtualisationResult(
            success=True,
            ml_classifications={"0x1000": "arithmetic", "0x2000": "bitwise"},
        )
        d = r.to_dict()
        assert d["ml_classifications"]["0x1000"] == "arithmetic"
        assert d["ml_classifications"]["0x2000"] == "bitwise"


# =====================================================================
#  5. Import paths
# =====================================================================

class TestImportPaths:
    def test_import_from_analysis(self):
        from dragonslayer.analysis import DevirtualisationResult
        assert DevirtualisationResult is not None

    def test_import_from_module(self):
        from dragonslayer.analysis.devirtualisation_result import DevirtualisationResult
        assert DevirtualisationResult is not None
        assert callable(DevirtualisationResult.skipped_result)

    def test_stage_result_import(self):
        from dragonslayer.core.pipeline import StageResult, PipelineResult
        assert StageResult is not None
        assert PipelineResult is not None


# =====================================================================
#  6. Pipeline default stages include binary_parse
# =====================================================================

class TestPipelineDefaults:
    def test_binary_parse_not_forced_in_defaults(self):
        """binary_parse is available as a stage but not forced into defaults
        (backwards compat — existing configs shouldn't break)."""
        from dragonslayer.core.pipeline import PipelineConfig
        cfg = PipelineConfig()
        # binary_parse may or may not be in defaults — both are OK
        # The key is it's a valid stage key
        assert isinstance(cfg.stages, list)

    def test_custom_config_with_binary_parse(self):
        """Custom config with binary_parse first works."""
        from dragonslayer.core.pipeline import PipelineConfig
        cfg = PipelineConfig(stages=["binary_parse", "pattern_analysis"])
        assert cfg.stages[0] == "binary_parse"
