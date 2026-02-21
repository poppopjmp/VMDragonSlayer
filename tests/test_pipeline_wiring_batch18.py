"""Batch 18 — Pipeline wiring tests.

Validates that _run_devirtualize() now calls all Batch 13-17 modules
and that _run_anti_evasion() builds the runtime hook-set.
"""

from __future__ import annotations

import types
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from dragonslayer.core.pipeline import AnalysisPipeline


# ---------------------------------------------------------------------------
# Helpers — lightweight stubs for trace / boundary / opcode data
# ---------------------------------------------------------------------------

@dataclass
class _FakeInsn:
    address: int = 0x401000
    size: int = 3
    raw_bytes: bytes = b"\x0f\x31\xc3"
    disassembly: str = "rdtsc"
    registers: Dict[str, int] = field(default_factory=dict)


@dataclass
class _FakeTrace:
    instructions: List[_FakeInsn] = field(default_factory=list)


@dataclass
class _FakeVipCandidate:
    name: str = "rsi"
    register: str = "rsi"


@dataclass
class _FakeBoundary:
    vip_value: int = 0
    handler_address: int = 0x401000
    vip_delta: int = 1
    instruction_count: int = 5
    trace_start: int = 0
    trace_end: int = 5


@dataclass
class _FakeSegResult:
    boundaries: List[_FakeBoundary] = field(default_factory=list)


@dataclass
class _FakeHandlerSemantic:
    handler_address: int = 0x401000
    operation: str = "ADD"
    confidence: float = 0.9
    operand_count: int = 2
    operand_width: int = 4
    reads_memory: bool = False
    writes_memory: bool = False
    modifies_flags: bool = True
    mnemonic_histogram: Dict[str, int] = field(default_factory=dict)
    detail: str = ""


@dataclass
class _FakeOpcodeEntry:
    opcode: int = 0
    handler_address: int = 0x401000
    semantic: _FakeHandlerSemantic = field(default_factory=_FakeHandlerSemantic)
    vip_delta: int = 1

    def to_dict(self):
        return {"opcode": self.opcode, "handler_address": hex(self.handler_address)}


@dataclass
class _FakeOpcodeTable:
    entries: List[_FakeOpcodeEntry] = field(default_factory=list)
    handler_count: int = 1
    unique_operations: int = 1

    def to_dict(self):
        return {
            "handler_count": self.handler_count,
            "unique_operations": self.unique_operations,
            "entries": [e.to_dict() for e in self.entries],
        }

    def operations_summary(self):
        return {"ADD": 1}


@dataclass
class _FakePseudoResult:
    text: str = "void vm_func() { /* stub */ }"
    line_count: int = 1
    style: str = "c_like"
    warnings: List[str] = field(default_factory=list)

    def to_dict(self):
        return {"text": self.text, "line_count": self.line_count, "style": self.style}


def _make_trace(n: int = 10) -> _FakeTrace:
    return _FakeTrace(
        instructions=[_FakeInsn(address=0x401000 + i * 3) for i in range(n)]
    )


def _make_ctx(**shared_extra) -> MagicMock:
    ctx = MagicMock()
    ctx.shared_data = {"binary_size": 1024, **shared_extra}
    return ctx


# ---------------------------------------------------------------------------
# Tests for _run_devirtualize pipeline wiring
# ---------------------------------------------------------------------------


class TestDevirtWiringSkips:
    """Gracefully skip when no trace is available."""

    def setup_method(self):
        self.pipe = AnalysisPipeline(config=MagicMock(_config={}))

    def test_skips_without_trace(self):
        ctx = _make_ctx()
        result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
        assert result.success is True
        assert result.data.get("skipped") is True


class TestDevirtWiringFull:
    """When a trace IS available, all Batch 13-17 modules are called."""

    def setup_method(self):
        self.pipe = AnalysisPipeline(config=MagicMock(_config={}))

    @staticmethod
    def _patch_all():
        """Return a dict of patch targets and their return values."""
        trace = _make_trace()
        boundaries = [_FakeBoundary()]
        seg = _FakeSegResult(boundaries=boundaries)
        opcode_table = _FakeOpcodeTable(entries=[_FakeOpcodeEntry()])
        pseudo = _FakePseudoResult()

        patches = {
            "dragonslayer.analysis.trace_ingestion.from_shared_data": MagicMock(return_value=trace),
            "dragonslayer.analysis.vm_discovery.handler_boundaries.identify_vip_register": MagicMock(return_value=_FakeVipCandidate()),
            "dragonslayer.analysis.vm_discovery.handler_boundaries.segment_trace": MagicMock(return_value=seg),
            "dragonslayer.analysis.handler_semantics.analyse_handler_semantics": MagicMock(return_value=opcode_table),
            "dragonslayer.analysis.pseudocode.emit_pseudocode": MagicMock(return_value=pseudo),
        }
        return patches, trace, boundaries, opcode_table

    def _run_with_patches(self, extra_shared=None, extra_patches=None):
        """Run _run_devirtualize with all core modules mocked."""
        patches, trace, boundaries, opcode_table = self._patch_all()
        if extra_patches:
            patches.update(extra_patches)

        shared = extra_shared or {}
        ctx = _make_ctx(**shared)

        with patch.dict("sys.modules", {}):
            active = {}
            for target, mock_obj in patches.items():
                p = patch(target, mock_obj)
                active[target] = p.start()

            try:
                result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
            finally:
                for p_target in patches:
                    patch.stopall()

        return result, ctx, active

    # -- Core pipeline still works -----------------------------------------

    def test_basic_devirt_produces_result(self):
        result, ctx, _ = self._run_with_patches()
        assert result.success is True
        assert "pseudocode_text" in result.data
        assert result.data["handler_count"] == 1

    def test_result_contains_vip_register(self):
        result, _, _ = self._run_with_patches()
        assert result.data["vip_register"] == "rsi"

    # -- Batch 13: VMProtect dispatcher ------------------------------------

    def test_vmprotect_dispatcher_called(self):
        """find_dispatcher_in_trace should be attempted."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_dispatcher_in_trace,
            find_vmprotect_dispatcher,
        )
        # We only test the import path works — the function is called
        # inside a try/except, so if the trace doesn't match, it just
        # produces None and the pipeline continues.
        result, ctx, _ = self._run_with_patches()
        assert result.success is True

    def test_vmprotect_dispatcher_result_attached(self):
        """When VMProtect dispatcher is found, result should contain it."""
        from dragonslayer.analysis.vm_discovery.dispatcher import VMProtectDispatcherMatch

        fake_match = MagicMock()
        fake_match.to_dict.return_value = {
            "dispatcher_address": 0x401000,
            "handler_table": [{"handler_address": 0x402000}],
            "score": 0.95,
        }

        patches, *_ = self._patch_all()
        patches["dragonslayer.analysis.vm_discovery.dispatcher.find_dispatcher_in_trace"] = MagicMock(return_value=fake_match)
        patches["dragonslayer.analysis.vm_discovery.dispatcher.find_vmprotect_dispatcher"] = MagicMock(return_value=None)

        ctx = _make_ctx()
        with patch.dict("sys.modules", {}):
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
            finally:
                patch.stopall()

        assert result.success is True
        assert "vmprotect_dispatcher" in result.data
        assert result.data["vmprotect_dispatcher"]["dispatcher_address"] == 0x401000

    # -- Batch 14: Handler extraction --------------------------------------

    def test_handler_extraction_attempted(self):
        """extract_handler_bodies should be called."""
        fake_extraction = MagicMock()
        fake_extraction.to_dict.return_value = {
            "handler_count": 1,
            "unique_fingerprints": 1,
        }

        patches, *_ = self._patch_all()
        patches["dragonslayer.analysis.vm_discovery.handler_extraction.extract_handler_bodies"] = MagicMock(return_value=fake_extraction)

        ctx = _make_ctx()
        with patch.dict("sys.modules", {}):
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
            finally:
                patch.stopall()

        assert result.success is True
        assert "handler_extraction" in result.data
        assert ctx.shared_data.get("handler_extraction") is not None

    # -- Batch 15: Context registers ---------------------------------------

    def test_context_registers_attempted(self):
        """identify_vm_context should be called."""
        fake_ctx_layout = MagicMock()
        fake_ctx_layout.to_dict.return_value = {
            "vsp": "rsp",
            "table_base": "rbx",
            "key_register": None,
        }

        patches, *_ = self._patch_all()
        patches["dragonslayer.analysis.vm_discovery.context_registers.identify_vm_context"] = MagicMock(return_value=fake_ctx_layout)

        ctx = _make_ctx()
        with patch.dict("sys.modules", {}):
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
            finally:
                patch.stopall()

        assert result.success is True
        assert "vm_context_layout" in result.data
        assert ctx.shared_data.get("vm_context_layout") is not None

    # -- Batch 16: Clustering ----------------------------------------------

    def test_clustering_attempted(self):
        """cluster_handlers_by_semantics should be called."""
        fake_cluster = MagicMock()
        fake_cluster.to_dict.return_value = {
            "cluster_count": 1,
            "clusters": [],
        }

        patches, *_ = self._patch_all()

        # The refined opcode table returned by refine_opcode_table
        refined = _FakeOpcodeTable(entries=[_FakeOpcodeEntry()])
        patches["dragonslayer.analysis.handler_clustering.cluster_handlers_by_semantics"] = MagicMock(return_value=fake_cluster)
        patches["dragonslayer.analysis.handler_clustering.refine_opcode_table"] = MagicMock(return_value=refined)

        ctx = _make_ctx()
        with patch.dict("sys.modules", {}):
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
            finally:
                patch.stopall()

        assert result.success is True
        assert "handler_clustering" in result.data
        assert ctx.shared_data.get("handler_clustering") is not None

    # -- Batch 17: Anti-evasion hooks in devirt ----------------------------

    def test_hooks_from_anti_evasion_report(self):
        """When anti_evasion report exists in shared_data, hooks are built."""
        from dragonslayer.analysis.anti_evasion.runtime_hooks import HookCategory

        fake_hook = MagicMock()
        fake_hook.category = HookCategory.TIMING
        fake_hook.name = "rdtsc_normalize"

        fake_hookset = MagicMock()
        fake_hookset.hooks = [fake_hook]

        patches, *_ = self._patch_all()
        patches["dragonslayer.analysis.anti_evasion.runtime_hooks.build_hook_set_from_report"] = MagicMock(return_value=fake_hookset)

        ae_report = {"risk_score": 0.6, "techniques": ["rdtsc"]}
        ctx = _make_ctx(anti_evasion=ae_report)

        with patch.dict("sys.modules", {}):
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)
            finally:
                patch.stopall()

        assert result.success is True
        assert "anti_evasion_hooks" in result.data
        assert result.data["anti_evasion_hooks"]["hook_count"] == 1

    # -- Boundaries stored in shared_data ----------------------------------

    def test_boundaries_stored_in_shared_data(self):
        result, ctx, _ = self._run_with_patches()
        assert "devirt_boundaries" in ctx.shared_data
        assert len(ctx.shared_data["devirt_boundaries"]) == 1
        assert ctx.shared_data["devirt_boundaries"][0]["handler_address"] == 0x401000


# ---------------------------------------------------------------------------
# Tests for _run_anti_evasion hook-set generation
# ---------------------------------------------------------------------------


class TestAntiEvasionHookSetWiring:
    """_run_anti_evasion should now also build the runtime hook-set."""

    def setup_method(self):
        self.pipe = AnalysisPipeline(config=MagicMock(_config={}))

    def test_hook_set_attached_to_result(self):
        """When EnvironmentNormalizer succeeds, hook-set data is in result."""
        from dragonslayer.analysis.anti_evasion.runtime_hooks import HookCategory

        # Mock the EnvironmentNormalizer
        fake_report = MagicMock()
        fake_report.to_dict.return_value = {
            "risk_score": 0.5,
            "techniques": [],
        }
        fake_report.risk_score = 0.5

        fake_hook = MagicMock()
        fake_hook.category = HookCategory.TIMING
        fake_hook.name = "rdtsc_normalize"

        fake_hookset = MagicMock()
        fake_hookset.hooks = [fake_hook]

        ctx = _make_ctx()

        with patch("dragonslayer.analysis.anti_evasion.environment_normalizer.EnvironmentNormalizer") as mock_cls, \
             patch("dragonslayer.analysis.anti_evasion.runtime_hooks.build_hook_set_from_report", return_value=fake_hookset):
            mock_cls.return_value.analyze.return_value = fake_report
            result = self.pipe._run_anti_evasion(b"\x00" * 64, ctx)

        assert result.success is True
        assert "runtime_hooks" in result.data
        assert result.data["runtime_hooks"]["hook_count"] == 1
        assert "rdtsc_normalize" in result.data["runtime_hooks"]["hook_names"]

    def test_hook_set_stored_in_shared_data(self):
        """runtime_hook_set should be stored in ctx.shared_data."""
        fake_report = MagicMock()
        fake_report.to_dict.return_value = {"risk_score": 0.3, "techniques": []}
        fake_report.risk_score = 0.3

        fake_hookset = MagicMock()
        fake_hookset.hooks = []

        ctx = _make_ctx()

        with patch("dragonslayer.analysis.anti_evasion.environment_normalizer.EnvironmentNormalizer") as mock_cls, \
             patch("dragonslayer.analysis.anti_evasion.runtime_hooks.build_hook_set_from_report", return_value=fake_hookset):
            mock_cls.return_value.analyze.return_value = fake_report
            self.pipe._run_anti_evasion(b"\x00" * 64, ctx)

        assert "runtime_hook_set" in ctx.shared_data

    def test_anti_evasion_still_works_without_hooks(self):
        """If hook-set generation fails, the stage still succeeds."""
        fake_report = MagicMock()
        fake_report.to_dict.return_value = {"risk_score": 0.2, "techniques": []}
        fake_report.risk_score = 0.2

        ctx = _make_ctx()

        with patch("dragonslayer.analysis.anti_evasion.environment_normalizer.EnvironmentNormalizer") as mock_cls, \
             patch("dragonslayer.analysis.anti_evasion.runtime_hooks.build_hook_set_from_report", side_effect=RuntimeError("boom")):
            mock_cls.return_value.analyze.return_value = fake_report
            result = self.pipe._run_anti_evasion(b"\x00" * 64, ctx)

        assert result.success is True
        assert "runtime_hooks" not in result.data


# ---------------------------------------------------------------------------
# VMProtect dispatcher addresses supplement
# ---------------------------------------------------------------------------


class TestVMProtectAddressSupplement:
    """VMProtect dispatcher match should feed addresses into segmentation."""

    def setup_method(self):
        self.pipe = AnalysisPipeline(config=MagicMock(_config={}))

    def test_handler_table_addresses_merged(self):
        """Addresses from vmprotect_match.handler_table should be added."""
        trace = _make_trace()
        boundaries = [_FakeBoundary()]
        seg = _FakeSegResult(boundaries=boundaries)
        opcode_table = _FakeOpcodeTable(entries=[_FakeOpcodeEntry()])
        pseudo = _FakePseudoResult()

        fake_disp_match = MagicMock()
        fake_disp_match.to_dict.return_value = {
            "dispatcher_address": 0x401000,
            "handler_table": [
                {"handler_address": 0x402000},
                {"handler_address": 0x403000},
            ],
            "score": 0.95,
        }

        # Track what dispatcher_addrs are passed to identify_vip_register
        captured_args = {}

        def fake_identify_vip(trace_arg, dispatcher_addrs):
            captured_args["dispatcher_addrs"] = list(dispatcher_addrs)
            return _FakeVipCandidate()

        with patch("dragonslayer.analysis.trace_ingestion.from_shared_data", return_value=trace), \
             patch("dragonslayer.analysis.vm_discovery.handler_boundaries.identify_vip_register", side_effect=fake_identify_vip) as mock_vip, \
             patch("dragonslayer.analysis.vm_discovery.handler_boundaries.segment_trace", return_value=seg), \
             patch("dragonslayer.analysis.handler_semantics.analyse_handler_semantics", return_value=opcode_table), \
             patch("dragonslayer.analysis.pseudocode.emit_pseudocode", return_value=pseudo), \
             patch("dragonslayer.analysis.vm_discovery.dispatcher.find_dispatcher_in_trace", return_value=fake_disp_match), \
             patch("dragonslayer.analysis.vm_discovery.dispatcher.find_vmprotect_dispatcher", return_value=None):

            ctx = _make_ctx()
            result = self.pipe._run_devirtualize(b"\x00" * 64, ctx)

        assert result.success is True
        # The addresses from handler_table should be in the dispatcher_addrs
        assert 0x402000 in captured_args["dispatcher_addrs"]
        assert 0x403000 in captured_args["dispatcher_addrs"]
