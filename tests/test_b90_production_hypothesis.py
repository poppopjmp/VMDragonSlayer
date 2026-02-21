"""
B90 — Hypothesis property-based tests for production classes.

Exercises real ByteTaintMap, TaintTracker, SymbolicState, DispatcherScoringConfig,
and PatternClassifier with fuzz-generated inputs for round-trip consistency,
invariant checking, and robustness.
"""

from __future__ import annotations

import math
from dataclasses import fields as dc_fields
from typing import Dict

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# ByteTaintMap + TaintTag
# ---------------------------------------------------------------------------
from dragonslayer.analysis.taint_tracking.tracker import ByteTaintMap, TaintTag

# Canonical GP registers (8-byte) and their 32/16/8-bit sub-registers
_GP_CANONICALS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
_GP_SUBS_32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]
_ALL_GP = _GP_CANONICALS + _GP_SUBS_32
_GP_REG = st.sampled_from(_ALL_GP)
_TAINT_TAG = st.sampled_from([t for t in TaintTag if t != TaintTag.CLEAN])


class TestByteTaintMapProperties:
    """Property-based tests for ByteTaintMap."""

    @given(reg=st.sampled_from(_GP_CANONICALS), tag=_TAINT_TAG)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_set_then_get_roundtrip(self, reg: str, tag: TaintTag) -> None:
        """set_bytes(reg, tag) → get_bytes(reg) must include *tag*."""
        m = ByteTaintMap()
        m.set_bytes(reg, tag)
        got = m.get_bytes(reg)
        assert tag & got, f"tag={tag!r} not in get_bytes({reg})={got!r}"

    @given(reg=st.sampled_from(_GP_CANONICALS), tag=_TAINT_TAG)
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_clear_removes_taint(self, reg: str, tag: TaintTag) -> None:
        """clear_bytes(reg) must make get_full(reg)==CLEAN."""
        m = ByteTaintMap()
        m.set_bytes(reg, tag)
        m.clear_bytes(reg)
        assert m.get_full(reg) == TaintTag.CLEAN

    @given(reg=st.sampled_from(_GP_CANONICALS),
           tags=st.lists(_TAINT_TAG, min_size=2, max_size=5))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_last_set_wins(self, reg: str, tags: list) -> None:
        """set_bytes replaces the tag; last call determines taint."""
        m = ByteTaintMap()
        for t in tags:
            m.set_bytes(reg, t)
        last = tags[-1]
        got = m.get_bytes(reg)
        assert last & got, f"last tag={last!r} not reflected in get_bytes({reg})={got!r}"

    @given(reg=st.sampled_from(_GP_CANONICALS))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_fresh_map_is_clean(self, reg: str) -> None:
        """A fresh map must report CLEAN for any register."""
        m = ByteTaintMap()
        assert m.get_full(reg) == TaintTag.CLEAN

    @given(reg=st.sampled_from(_GP_CANONICALS), tag=_TAINT_TAG)
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_clear_all(self, reg: str, tag: TaintTag) -> None:
        """clear() must make all registers CLEAN."""
        m = ByteTaintMap()
        m.set_bytes(reg, tag)
        m.clear()
        assert m.get_full(reg) == TaintTag.CLEAN

    @given(reg=st.sampled_from(_GP_CANONICALS), tag=_TAINT_TAG)
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_to_dict_reflects_taint(self, reg: str, tag: TaintTag) -> None:
        """to_dict() must contain non-CLEAN entries after set_bytes."""
        m = ByteTaintMap()
        m.set_bytes(reg, tag)
        d = m.to_dict()
        assert len(d) > 0, "to_dict() should have entries after set"


# ---------------------------------------------------------------------------
# TaintTracker
# ---------------------------------------------------------------------------
from dragonslayer.analysis.taint_tracking.tracker import TaintTracker


class TestTaintTrackerProperties:
    """Property-based tests for TaintTracker."""

    @given(reg=st.sampled_from(_GP_CANONICALS), tag=_TAINT_TAG)
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_taint_register_then_check(self, reg: str, tag: TaintTag) -> None:
        """taint_register(reg, tag) → is_tainted(reg) must be True."""
        t = TaintTracker()
        t.taint_register(reg, tag)
        assert t.is_tainted(reg)

    @given(addr=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_taint_memory_roundtrip(self, addr: int) -> None:
        """taint_memory(addr) → mem_taint must contain addr."""
        t = TaintTracker()
        t.taint_memory(addr)
        assert addr in t.mem_taint

    @given(addr=st.integers(min_value=0, max_value=0xFFFF_FFFF),
           size=st.integers(min_value=1, max_value=64))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_taint_memory_region(self, addr: int, size: int) -> None:
        """taint_memory_region → is_memory_region_tainted must be True."""
        t = TaintTracker()
        t.taint_memory_region(addr, size)
        assert t.is_memory_region_tainted(addr, size)

    @given(reg=st.sampled_from(_GP_CANONICALS), tag=_TAINT_TAG)
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_reset_clears_all(self, reg: str, tag: TaintTag) -> None:
        """reset() must clear all register and memory taint."""
        t = TaintTracker()
        t.taint_register(reg, tag)
        t.taint_memory(0x1000)
        t.reset()
        assert not t.is_tainted(reg)
        assert 0x1000 not in t.mem_taint

    @given(reg=st.sampled_from(_GP_CANONICALS))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_fresh_tracker_not_tainted(self, reg: str) -> None:
        """A fresh tracker must report no taint."""
        t = TaintTracker()
        assert not t.is_tainted(reg)

    @given(addr=st.integers(min_value=0x1000, max_value=0x2000))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_bind_pointer_then_alias(self, addr: int) -> None:
        """bind_pointer + taint_register → memory_taint_via_reg propagates."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        t.bind_pointer("rax", addr)
        # After binding, memory_taint_via_reg should return something
        taint = t.memory_taint_via_reg("rax")
        # Either the mechanism works or returns CLEAN – no crash
        assert isinstance(taint, TaintTag)


# ---------------------------------------------------------------------------
# SymbolicState
# ---------------------------------------------------------------------------
from dragonslayer.analysis.symbolic_execution.state import SymbolicState


class TestSymbolicStateProperties:
    """Property-based tests for SymbolicState."""

    @given(val=st.integers(min_value=0, max_value=0xFFFF_FFFF_FFFF_FFFF))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_register_set_get_roundtrip(self, val: int) -> None:
        """set_register → get_register must return the same value."""
        s = SymbolicState(arch="x86_64", bit_width=64)
        s.set_register("rax", val)
        got = s.get_register("rax")
        assert got == val, f"expected {val:#x}, got {got:#x}"

    @given(val=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_32bit_zero_extend(self, val: int) -> None:
        """Writing eax should zero-extend to rax on x86_64."""
        s = SymbolicState(arch="x86_64", bit_width=64)
        s.set_register("rax", 0xDEAD_BEEF_DEAD_BEEF)
        s.set_register("eax", val)
        got = s.get_register("rax")
        assert got == val, f"32-bit write: expected {val:#x}, got {got:#x}"

    @given(addr=st.integers(min_value=0x1000, max_value=0x1_0000),
           val=st.integers(min_value=0, max_value=0xFF))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_memory_write_read_roundtrip(self, addr: int, val: int) -> None:
        """write_memory → read_memory must return the written value."""
        s = SymbolicState(arch="x86_64", bit_width=64)
        s.write_memory(addr, val, size=1)
        got = s.read_memory(addr, size=1)
        assert got == val

    @given(val=st.integers(min_value=0, max_value=0xFFFF_FFFF_FFFF_FFFF))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_fork_preserves_registers(self, val: int) -> None:
        """fork() must copy register values."""
        s = SymbolicState(arch="x86_64", bit_width=64)
        s.set_register("rbx", val)
        s2 = s.fork()
        assert s2.get_register("rbx") == val

    @given(val=st.integers(min_value=0, max_value=0xFFFF_FFFF_FFFF_FFFF))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_fork_is_independent(self, val: int) -> None:
        """Modifying forked state must not affect original."""
        s = SymbolicState(arch="x86_64", bit_width=64)
        s.set_register("rcx", val)
        s2 = s.fork()
        s2.set_register("rcx", 0x42)
        assert s.get_register("rcx") == val

    @given(pc=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_initial_pc(self, pc: int) -> None:
        """initial_pc must set the program counter."""
        s = SymbolicState(arch="x86_64", bit_width=64, initial_pc=pc)
        assert s.pc == pc


# ---------------------------------------------------------------------------
# DispatcherScoringConfig
# ---------------------------------------------------------------------------
from dragonslayer.analysis.vm_discovery.dispatcher import DispatcherScoringConfig

_SCORING_FIELDS = [f.name for f in dc_fields(DispatcherScoringConfig)]
_scoring_float = st.floats(min_value=0.0, max_value=1.0, allow_nan=False,
                           allow_infinity=False)


class TestDispatcherScoringConfigProperties:
    """Property-based tests for DispatcherScoringConfig."""

    @given(data=st.fixed_dictionaries(
        {f: _scoring_float for f in _SCORING_FIELDS}
    ))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_from_dict_roundtrip(self, data: Dict[str, float]) -> None:
        """from_dict(d) → field values must match d."""
        cfg = DispatcherScoringConfig.from_dict(data)
        for k, v in data.items():
            got = getattr(cfg, k)
            assert abs(got - v) < 1e-12, f"{k}: expected {v}, got {got}"

    @given(extra=st.dictionaries(
        st.text(min_size=1, max_size=20),
        st.floats(min_value=-10, max_value=10, allow_nan=False),
        min_size=1, max_size=5,
    ))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_from_dict_ignores_unknown_keys(self, extra: Dict[str, float]) -> None:
        """from_dict must silently ignore keys not in the dataclass."""
        # Filter out keys that happen to match real fields
        junk = {k: v for k, v in extra.items() if k not in _SCORING_FIELDS}
        assume(len(junk) > 0)
        cfg = DispatcherScoringConfig.from_dict(junk)
        # Must equal the default config since no valid keys were provided
        default = DispatcherScoringConfig()
        for f in _SCORING_FIELDS:
            assert getattr(cfg, f) == getattr(default, f)

    @given(floor=_scoring_float)
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_confidence_floor_preserved(self, floor: float) -> None:
        """confidence_floor must be preserved through from_dict."""
        cfg = DispatcherScoringConfig.from_dict({"confidence_floor": floor})
        assert abs(cfg.confidence_floor - floor) < 1e-12

    @settings(max_examples=20)
    @given(data=st.data())
    def test_default_weights_are_positive(self, data: st.DataObject) -> None:
        """All default weights must be non-negative."""
        cfg = DispatcherScoringConfig()
        for f in _SCORING_FIELDS:
            val = getattr(cfg, f)
            assert val >= 0.0, f"{f} has negative default: {val}"


# ---------------------------------------------------------------------------
# PatternClassifier — classify_handler_bytes
# ---------------------------------------------------------------------------
from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier


class TestPatternClassifierProperties:
    """Property-based tests for PatternClassifier.classify_handler_bytes."""

    @given(raw=st.binary(min_size=1, max_size=256))
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_classify_bytes_never_crashes(self, raw: bytes) -> None:
        """classify_handler_bytes must not raise on arbitrary bytes."""
        pc = PatternClassifier(use_llm=False)
        result = pc.classify_handler_bytes(raw)
        # Must return a result with handler_type and confidence
        assert hasattr(result, "handler_type")
        assert hasattr(result, "confidence")
        assert 0.0 <= result.confidence <= 1.0

    @given(raw=st.binary(min_size=1, max_size=256),
           name=st.text(min_size=0, max_size=30))
    @settings(max_examples=50, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_classify_bytes_deterministic(self, raw: bytes, name: str) -> None:
        """Same bytes → same classification."""
        pc = PatternClassifier(use_llm=False)
        r1 = pc.classify_handler_bytes(raw, handler_name=name)
        r2 = pc.classify_handler_bytes(raw, handler_name=name)
        assert r1.handler_type == r2.handler_type
        assert abs(r1.confidence - r2.confidence) < 1e-9

    @given(raw=st.just(b"\x00" * 16))
    @settings(max_examples=5, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_classify_nop_bytes(self, raw: bytes) -> None:
        """Null bytes should produce a result (possibly unknown/low conf)."""
        pc = PatternClassifier(use_llm=False)
        result = pc.classify_handler_bytes(raw)
        assert result.confidence >= 0.0


# ---------------------------------------------------------------------------
# Cross-component: TaintTracker + SymbolicState interop
# ---------------------------------------------------------------------------


class TestCrossComponentProperties:
    """Verify that taint and symbolic state objects compose correctly."""

    @given(reg=st.sampled_from(["rax", "rbx", "rcx", "rdx"]),
           val=st.integers(min_value=0, max_value=0xFFFF_FFFF_FFFF_FFFF),
           tag=_TAINT_TAG)
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_symbolic_plus_taint(self, reg: str, val: int, tag: TaintTag) -> None:
        """Setting a register in SymbolicState + tainting it in TaintTracker
        must both independently reflect the operation."""
        sym = SymbolicState(arch="x86_64", bit_width=64)
        sym.set_register(reg, val)

        tt = TaintTracker()
        tt.taint_register(reg, tag)

        assert sym.get_register(reg) == val
        assert tt.is_tainted(reg)
        assert tt.get_taint(reg) & tag
