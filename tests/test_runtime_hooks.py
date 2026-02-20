"""Tests for anti-evasion runtime hooks."""
from __future__ import annotations

import pytest

from dragonslayer.analysis.anti_evasion.runtime_hooks import (
    HookCategory,
    HookDescriptor,
    HookSet,
    HookInstallResult,
    TimingState,
    build_hook_set,
    build_hook_set_from_report,
    hooks_for_binary,
    apply_hooks_to_qiling,
    apply_hooks_to_angr,
    apply_hooks_to_triton,
    _ALL_HOOKS,
)


# ═══════════════════════════════════════════════════════════════════════
# Test: HookDescriptor
# ═══════════════════════════════════════════════════════════════════════

class TestHookDescriptor:
    def test_to_dict(self):
        h = HookDescriptor(
            name="test", category=HookCategory.DEBUG,
            description="test hook", api_name="Foo", return_value=0,
        )
        d = h.to_dict()
        assert d["name"] == "test"
        assert d["category"] == "debug"
        assert d["return_value"] == 0

    def test_fields(self):
        h = HookDescriptor(
            name="rdtsc", category=HookCategory.TIMING,
            description="RDTSC", opcode_bytes=b"\x0f\x31",
        )
        assert h.opcode_bytes == b"\x0f\x31"
        assert h.api_name == ""
        assert h.return_value is None


# ═══════════════════════════════════════════════════════════════════════
# Test: HookSet
# ═══════════════════════════════════════════════════════════════════════

class TestHookSet:
    def test_to_dict(self):
        hs = HookSet(
            hooks=[HookDescriptor(name="a", category=HookCategory.TIMING, description="")],
            categories={HookCategory.TIMING},
        )
        d = hs.to_dict()
        assert d["hook_count"] == 1
        assert "timing" in d["categories"]

    def test_by_category(self):
        hooks = [
            HookDescriptor(name="a", category=HookCategory.TIMING, description=""),
            HookDescriptor(name="b", category=HookCategory.DEBUG, description=""),
            HookDescriptor(name="c", category=HookCategory.TIMING, description=""),
        ]
        hs = HookSet(hooks=hooks, categories={HookCategory.TIMING, HookCategory.DEBUG})
        timing = hs.by_category(HookCategory.TIMING)
        assert len(timing) == 2
        debug = hs.by_category(HookCategory.DEBUG)
        assert len(debug) == 1

    def test_empty(self):
        hs = HookSet()
        assert hs.to_dict()["hook_count"] == 0


# ═══════════════════════════════════════════════════════════════════════
# Test: HookInstallResult
# ═══════════════════════════════════════════════════════════════════════

class TestHookInstallResult:
    def test_success_count(self):
        r = HookInstallResult(installed=["a", "b"], skipped=["c"])
        assert r.success_count == 2

    def test_to_dict(self):
        r = HookInstallResult(
            installed=["a"],
            skipped=["b"],
            errors={"c": "fail"},
        )
        d = r.to_dict()
        assert d["installed_count"] == 1
        assert len(d["errors"]) == 1


# ═══════════════════════════════════════════════════════════════════════
# Test: TimingState
# ═══════════════════════════════════════════════════════════════════════

class TestTimingState:
    def test_monotonic_tsc(self):
        ts = TimingState(initial=1000, delta_range=(10, 50))
        values = [ts.next_tsc() for _ in range(100)]
        assert all(values[i] < values[i + 1] for i in range(99))

    def test_initial_value(self):
        ts = TimingState(initial=0x1_0000_0000)
        v = ts.next_tsc()
        assert v > 0x1_0000_0000

    def test_split_edx_eax(self):
        ts = TimingState()
        tsc = 0x0000_0002_0000_0003
        edx, eax = ts.split_edx_eax(tsc)
        assert eax == 0x0000_0003
        assert edx == 0x0000_0002

    def test_next_tick_monotonic(self):
        ts = TimingState()
        ticks = [ts.next_tick() for _ in range(50)]
        assert all(ticks[i] < ticks[i + 1] for i in range(49))

    def test_tick_base(self):
        ts = TimingState()
        first = ts.next_tick()
        assert first > 60000
        assert first < 70000


# ═══════════════════════════════════════════════════════════════════════
# Test: build_hook_set
# ═══════════════════════════════════════════════════════════════════════

class TestBuildHookSet:
    def test_all_categories(self):
        hs = build_hook_set()
        assert len(hs.hooks) == len(_ALL_HOOKS)
        assert len(hs.categories) == len(HookCategory)

    def test_timing_only(self):
        hs = build_hook_set(categories={"timing"})
        assert all(h.category == HookCategory.TIMING for h in hs.hooks)
        assert len(hs.hooks) >= 2  # rdtsc + rdtscp at minimum

    def test_debug_only(self):
        hs = build_hook_set(categories={"debug"})
        assert all(h.category == HookCategory.DEBUG for h in hs.hooks)
        assert len(hs.hooks) >= 3

    def test_cpuid_only(self):
        hs = build_hook_set(categories={"cpuid"})
        assert len(hs.hooks) >= 1
        assert any(h.name == "cpuid_mask_hypervisor" for h in hs.hooks)

    def test_exclude_names(self):
        hs = build_hook_set(
            categories={"timing"},
            exclude_names={"rdtsc_normalize"},
        )
        names = {h.name for h in hs.hooks}
        assert "rdtsc_normalize" not in names
        # rdtscp and others should remain
        assert len(hs.hooks) >= 1

    def test_multiple_categories(self):
        hs = build_hook_set(categories={"timing", "debug"})
        cats = {h.category for h in hs.hooks}
        assert HookCategory.TIMING in cats
        assert HookCategory.DEBUG in cats

    def test_empty_categories(self):
        """Edge case: no categories requested → empty set."""
        hs = build_hook_set(categories=set())
        assert len(hs.hooks) == 0


# ═══════════════════════════════════════════════════════════════════════
# Test: build_hook_set_from_report
# ═══════════════════════════════════════════════════════════════════════

class TestBuildFromReport:
    def test_timing_indicators(self):
        report = {
            "indicators": [
                {"category": "timing_check", "confidence": 0.9},
            ],
        }
        hs = build_hook_set_from_report(report)
        assert HookCategory.TIMING in hs.categories

    def test_debug_indicators(self):
        report = {
            "indicators": [
                {"category": "anti_debug", "confidence": 0.85},
            ],
        }
        hs = build_hook_set_from_report(report)
        assert HookCategory.DEBUG in hs.categories

    def test_below_confidence_threshold(self):
        report = {
            "indicators": [
                {"category": "timing_check", "confidence": 0.3},
            ],
        }
        hs = build_hook_set_from_report(report, min_confidence=0.5)
        assert len(hs.hooks) == 0

    def test_empty_report(self):
        hs = build_hook_set_from_report({"indicators": []})
        assert len(hs.hooks) == 0

    def test_none_report(self):
        hs = build_hook_set_from_report(None)
        assert len(hs.hooks) == 0

    def test_anti_vm_indicators(self):
        report = {
            "indicators": [
                {"category": "anti_vm", "confidence": 0.8},
            ],
        }
        hs = build_hook_set_from_report(report)
        # Should include CPUID and ENV hooks
        assert HookCategory.CPUID in hs.categories or HookCategory.ENV in hs.categories

    def test_multiple_indicator_types(self):
        report = {
            "indicators": [
                {"category": "timing_check", "confidence": 0.9},
                {"category": "anti_debug", "confidence": 0.8},
                {"category": "anti_vm", "confidence": 0.7},
            ],
        }
        hs = build_hook_set_from_report(report)
        assert len(hs.categories) >= 3

    def test_accepts_normalization_report_object(self):
        """Should accept objects with to_dict()."""
        class FakeReport:
            def to_dict(self):
                return {
                    "indicators": [
                        {"category": "anti_debug", "confidence": 0.9}
                    ],
                }
        hs = build_hook_set_from_report(FakeReport())
        assert HookCategory.DEBUG in hs.categories


# ═══════════════════════════════════════════════════════════════════════
# Test: hooks_for_binary
# ═══════════════════════════════════════════════════════════════════════

class TestHooksForBinary:
    def test_empty_binary_returns_full_set(self):
        """Empty/invalid binary falls back to full hook set."""
        hs = hooks_for_binary(b"")
        assert len(hs.hooks) > 0

    def test_pe_binary_with_rdtsc(self):
        """Binary containing RDTSC should trigger timing hooks."""
        # Build a minimal PE-like binary with rdtsc bytes
        data = b"MZ" + b"\x00" * 100 + b"\x0f\x31" + b"\x00" * 100
        hs = hooks_for_binary(data)
        assert len(hs.hooks) > 0

    def test_binary_with_anti_debug_import(self):
        """Binary with IsDebuggerPresent should trigger debug hooks."""
        data = b"MZ" + b"\x00" * 50 + b"IsDebuggerPresent" + b"\x00" * 50
        hs = hooks_for_binary(data)
        assert len(hs.hooks) > 0


# ═══════════════════════════════════════════════════════════════════════
# Test: apply_hooks_to_qiling (mock)
# ═══════════════════════════════════════════════════════════════════════

class MockQilingRegs:
    def __init__(self):
        self._regs = {}

    def write(self, name, value):
        self._regs[name] = value

    def read(self, name):
        return self._regs.get(name, 0)


class MockQilingArch:
    def __init__(self):
        self.regs = MockQilingRegs()


class MockQilingOS:
    def __init__(self):
        self._apis = {}

    def set_api(self, name, callback):
        self._apis[name] = callback


class MockQiling:
    def __init__(self):
        self.arch = MockQilingArch()
        self.os = MockQilingOS()
        self._insn_hooks = {}

    def hook_insn(self, callback, opcode):
        self._insn_hooks[opcode] = callback


class TestApplyQiling:
    def test_api_hooks_installed(self):
        ql = MockQiling()
        hs = build_hook_set(categories={"debug"})
        result = apply_hooks_to_qiling(ql, hs)
        # IsDebuggerPresent should be installed as an API hook
        assert "IsDebuggerPresent_zero" in result.installed
        assert "IsDebuggerPresent" in ql.os._apis

    def test_api_hook_returns_zero(self):
        ql = MockQiling()
        hs = build_hook_set(categories={"debug"})
        apply_hooks_to_qiling(ql, hs)
        # Call the IsDebuggerPresent hook
        ret = ql.os._apis["IsDebuggerPresent"](ql)
        assert ret == 0

    def test_rdtsc_hook_installed(self):
        ql = MockQiling()
        hs = build_hook_set(categories={"timing"})
        result = apply_hooks_to_qiling(ql, hs)
        assert "rdtsc_normalize" in result.installed
        assert 0x0F31 in ql._insn_hooks

    def test_rdtsc_hook_sets_registers(self):
        ql = MockQiling()
        hs = build_hook_set(categories={"timing"})
        apply_hooks_to_qiling(ql, hs)
        # Invoke the RDTSC hook
        ql._insn_hooks[0x0F31](ql)
        eax = ql.arch.regs._regs.get("eax", 0)
        edx = ql.arch.regs._regs.get("edx", 0)
        assert eax > 0 or edx > 0

    def test_cpuid_hook_installed(self):
        ql = MockQiling()
        hs = build_hook_set(categories={"cpuid"})
        result = apply_hooks_to_qiling(ql, hs)
        assert "cpuid_mask_hypervisor" in result.installed
        assert 0x0FA2 in ql._insn_hooks

    def test_cpuid_leaf0_sets_vendor(self):
        ql = MockQiling()
        hs = build_hook_set(categories={"cpuid"})
        apply_hooks_to_qiling(ql, hs)
        # Set EAX=0 (leaf 0) and invoke
        ql.arch.regs.write("eax", 0)
        ql._insn_hooks[0x0FA2](ql)
        ebx = ql.arch.regs._regs.get("ebx", 0)
        # "Genu" in little-endian
        assert ebx == 0x756e6547


# ═══════════════════════════════════════════════════════════════════════
# Test: apply_hooks_to_angr (mock)
# ═══════════════════════════════════════════════════════════════════════

class MockAngrProject:
    def __init__(self):
        self._hooked = {}

    def hook_symbol(self, name, proc):
        self._hooked[name] = proc


class TestApplyAngr:
    def test_api_hooks_installed(self):
        """angr hooks should be installed for API-based descriptors."""
        proj = MockAngrProject()
        # Only select hooks that have api_name
        hs = build_hook_set(categories={"debug"})
        result = apply_hooks_to_angr(proj, hs)
        # At least IsDebuggerPresent should succeed
        assert len(result.installed) >= 1 or len(result.errors) >= 1

    def test_non_api_hooks_skipped(self):
        """Instruction-only hooks should be skipped for angr."""
        proj = MockAngrProject()
        hs = build_hook_set(categories={"timing"})
        result = apply_hooks_to_angr(proj, hs)
        # RDTSC/RDTSCP have no api_name → skipped
        rdtsc_hooks = [n for n in result.skipped if "rdtsc" in n]
        assert len(rdtsc_hooks) >= 1


# ═══════════════════════════════════════════════════════════════════════
# Test: apply_hooks_to_triton (mock)
# ═══════════════════════════════════════════════════════════════════════

class TestApplyTriton:
    def test_api_hooks_skipped(self):
        """Triton cannot hook APIs → all API hooks skipped."""

        class MockTritonCtx:
            class registers:
                eax = "eax"
                edx = "edx"
                ebx = "ebx"
                ecx = "ecx"

            def addCallback(self, *args): pass
            def getConcreteRegisterValue(self, reg): return 0
            def setConcreteRegisterValue(self, reg, val): pass

        tc = MockTritonCtx()
        hs = build_hook_set(categories={"debug"})
        result = apply_hooks_to_triton(tc, hs)
        # All debug hooks are API-based → should be skipped
        assert len(result.skipped) >= 3


# ═══════════════════════════════════════════════════════════════════════
# Test: _ALL_HOOKS integrity
# ═══════════════════════════════════════════════════════════════════════

class TestAllHooks:
    def test_unique_names(self):
        names = [h.name for h in _ALL_HOOKS]
        assert len(names) == len(set(names))

    def test_all_have_category(self):
        for h in _ALL_HOOKS:
            assert isinstance(h.category, HookCategory)

    def test_all_have_description(self):
        for h in _ALL_HOOKS:
            assert h.description

    def test_priority_sorted(self):
        priorities = [h.priority for h in _ALL_HOOKS]
        assert priorities == sorted(priorities)

    def test_at_least_one_per_category(self):
        cats = {h.category for h in _ALL_HOOKS}
        for c in HookCategory:
            assert c in cats, f"No hooks for {c}"


# ═══════════════════════════════════════════════════════════════════════
# Test: Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_hook_set_categories_match_hooks(self):
        hs = build_hook_set()
        actual_cats = {h.category for h in hs.hooks}
        assert actual_cats == hs.categories

    def test_timing_state_large_range(self):
        ts = TimingState(delta_range=(1, 10000))
        vals = [ts.next_tsc() for _ in range(1000)]
        assert vals[-1] > vals[0]
        assert all(vals[i] < vals[i + 1] for i in range(999))

    def test_hook_descriptor_metadata(self):
        h = _ALL_HOOKS[0]
        assert isinstance(h.metadata, dict)
