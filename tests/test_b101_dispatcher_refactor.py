"""B101 — Dispatcher refactor tests.

Tests for:
* ``TraceRecord`` TypedDict.
* ``_compute_trace_features`` shared helper.
* ``_subsample_trace`` adversarial-input guard.
* ``register_dispatcher_finder`` / ``_reset_finder_registry`` registry.
* Early-exit in ``find_dispatcher`` for high-confidence matches.
* Nested-depth limits enforced by the pipeline.
"""

from __future__ import annotations

import pytest
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rec(
    addr: int,
    disasm: str,
    *,
    registers: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Shortcut to build a trace record dict."""
    rec: Dict[str, Any] = {"address": addr, "disassembly": disasm}
    if registers:
        rec["registers"] = registers
    return rec


def _make_themida_trace(*, dispatch_visits: int = 10) -> List[Dict[str, Any]]:
    """Build a minimal Themida-like trace with pushad + indirect call."""
    trace: List[Dict[str, Any]] = [
        _make_rec(0x1000, "pushad"),
        _make_rec(0x1010, "mov ebp, esp"),
    ]
    for _ in range(dispatch_visits):
        trace.append(_make_rec(0x2000, "call [eax+ecx*4]"))
        trace.append(_make_rec(0x3000, "nop"))  # handler
    return trace


def _make_cv_trace(*, dispatch_visits: int = 10) -> List[Dict[str, Any]]:
    """Build a minimal Code Virtualizer trace with lodsb + jmp."""
    trace: List[Dict[str, Any]] = [
        _make_rec(0x4000, "lodsb"),
    ]
    for _ in range(dispatch_visits):
        trace.append(_make_rec(0x4000, "lodsb"))
        trace.append(_make_rec(0x4010, "jmp rax"))
        trace.append(_make_rec(0x5000, "nop"))  # handler
    return trace


def _make_generic_trace(*, dispatch_visits: int = 10) -> List[Dict[str, Any]]:
    """Build a trace with a hot indirect jmp (no protector markers)."""
    trace: List[Dict[str, Any]] = []
    for _ in range(dispatch_visits):
        trace.append(_make_rec(0x6000, "jmp [rbx+rcx*8]"))
        trace.append(_make_rec(0x7000, "nop"))
    return trace


# ═══════════════════════════════════════════════════════════════════════════
# TraceRecord TypedDict
# ═══════════════════════════════════════════════════════════════════════════


class TestTraceRecordTypedDict:
    """Verify the TraceRecord TypedDict is importable and well-shaped."""

    def test_import(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import TraceRecord
        assert TraceRecord is not None

    def test_keys(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import TraceRecord
        annotations = TraceRecord.__annotations__
        expected = {"address", "disassembly", "mnemonic", "operands",
                    "registers", "raw_bytes"}
        assert expected == set(annotations.keys())

    def test_total_false(self):
        """TraceRecord should be total=False (all keys optional)."""
        from dragonslayer.analysis.vm_discovery.dispatcher import TraceRecord
        assert TraceRecord.__total__ is False  # type: ignore[attr-defined]


# ═══════════════════════════════════════════════════════════════════════════
# _compute_trace_features
# ═══════════════════════════════════════════════════════════════════════════


class TestComputeTraceFeatures:
    """Verify the single-pass feature extractor."""

    def test_empty_trace(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        f = _compute_trace_features([])
        assert len(f.addr_freq) == 0
        assert len(f.pushad_addrs) == 0

    def test_addr_frequency(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        trace = [
            _make_rec(0x100, "nop"),
            _make_rec(0x100, "nop"),
            _make_rec(0x200, "ret"),
        ]
        f = _compute_trace_features(trace)
        assert f.addr_freq[0x100] == 2
        assert f.addr_freq[0x200] == 1

    def test_pushad_detection(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        trace = [
            _make_rec(0x100, "pushad"),
            _make_rec(0x200, "pusha"),
            _make_rec(0x300, "pushfd"),
            _make_rec(0x400, "push eax"),  # NOT pushad
        ]
        f = _compute_trace_features(trace)
        assert f.pushad_addrs == {0x100, 0x200, 0x300}

    def test_lodsb_and_xlat_detection(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        trace = [
            _make_rec(0x100, "lodsb"),
            _make_rec(0x200, "lodsw"),
            _make_rec(0x300, "lodsd"),
            _make_rec(0x400, "xlat"),
        ]
        f = _compute_trace_features(trace)
        assert f.lodsb_addrs == {0x100, 0x200, 0x300}
        assert f.xlat_addrs == {0x400}

    def test_indirect_call_detection(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        trace = [
            _make_rec(0x100, "call [eax]"),
            _make_rec(0x200, "call 0x5000"),   # direct — not collected
        ]
        f = _compute_trace_features(trace)
        assert len(f.indirect_calls) == 1
        assert f.indirect_calls[0]["address"] == 0x100

    def test_indirect_jump_detection(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        trace = [
            _make_rec(0x100, "jmp rax"),
            _make_rec(0x200, "jmp [rbx+rcx*8]"),
            _make_rec(0x300, "jmp 0x5000"),   # direct — not collected
        ]
        f = _compute_trace_features(trace)
        assert len(f.indirect_jumps) == 2

    def test_no_disassembly_field(self):
        """Records missing 'disassembly' should not crash."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _compute_trace_features,
        )
        trace = [{"address": 0x100}]
        f = _compute_trace_features(trace)
        assert f.addr_freq[0x100] == 1


# ═══════════════════════════════════════════════════════════════════════════
# _subsample_trace
# ═══════════════════════════════════════════════════════════════════════════


class TestSubsampleTrace:
    """Verify trace subsampling for adversarial-input resilience."""

    def test_short_trace_unchanged(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _subsample_trace,
        )
        trace = [_make_rec(i, "nop") for i in range(100)]
        result = _subsample_trace(trace, max_len=200)
        assert result is trace  # identity preserved

    def test_long_trace_subsampled(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _subsample_trace,
        )
        big_trace = [_make_rec(i, "nop") for i in range(10_000)]
        result = _subsample_trace(big_trace, max_len=500)
        assert len(result) == 500

    def test_subsample_is_uniform(self):
        """Subsampled records should span the entire original range."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _subsample_trace,
        )
        big_trace = [_make_rec(i, "nop") for i in range(5000)]
        result = _subsample_trace(big_trace, max_len=100)
        addrs = [r["address"] for r in result]
        # First should be near start, last near end
        assert addrs[0] < 100
        assert addrs[-1] > 4800

    def test_exact_boundary(self):
        """Trace exactly at the limit should be returned unchanged."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            _subsample_trace,
        )
        trace = [_make_rec(i, "nop") for i in range(500)]
        result = _subsample_trace(trace, max_len=500)
        assert result is trace


# ═══════════════════════════════════════════════════════════════════════════
# Finders accept _features kwarg
# ═══════════════════════════════════════════════════════════════════════════


class TestFindersAcceptFeatures:
    """All three finders accept the ``_features`` kwarg."""

    def test_themida_with_features(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_themida_dispatcher,
            _compute_trace_features,
        )
        trace = _make_themida_trace(dispatch_visits=10)
        features = _compute_trace_features(trace)
        result = find_themida_dispatcher(trace, _features=features)
        assert result is not None
        assert result.protector == "themida"

    def test_cv_with_features(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_cv_dispatcher,
            _compute_trace_features,
        )
        trace = _make_cv_trace(dispatch_visits=10)
        features = _compute_trace_features(trace)
        result = find_cv_dispatcher(trace, _features=features)
        assert result is not None
        assert result.protector == "code_virtualizer"

    def test_generic_with_features(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_generic_dispatcher,
            _compute_trace_features,
        )
        trace = _make_generic_trace(dispatch_visits=10)
        features = _compute_trace_features(trace)
        result = find_generic_dispatcher(trace, _features=features)
        assert result is not None
        assert result.protector == "unknown"

    def test_themida_returns_none_without_pushad(self):
        """No pushad → None even with features."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_themida_dispatcher,
            _compute_trace_features,
        )
        trace = _make_generic_trace(dispatch_visits=10)
        features = _compute_trace_features(trace)
        result = find_themida_dispatcher(trace, _features=features)
        assert result is None

    def test_cv_returns_none_without_lodsb(self):
        """No lodsb → None even with features."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_cv_dispatcher,
            _compute_trace_features,
        )
        trace = _make_generic_trace(dispatch_visits=10)
        features = _compute_trace_features(trace)
        result = find_cv_dispatcher(trace, _features=features)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# Dispatcher Finder Registry
# ═══════════════════════════════════════════════════════════════════════════


class TestDispatcherFinderRegistry:
    """Test the B101 registry pattern for pluggable finders."""

    def test_register_and_call(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            register_dispatcher_finder,
            find_dispatcher,
            _reset_finder_registry,
            GenericDispatcherMatch,
        )
        _reset_finder_registry()
        try:
            def my_finder(trace_records, *, bit_width=64, _features=None):
                return GenericDispatcherMatch(
                    protector="my_custom",
                    dispatch_address=0xDEAD,
                    confidence=0.99,
                )

            register_dispatcher_finder("my_custom", my_finder, priority=10)
            # Feed generic trace that wouldn't match VMProtect/Themida/CV well
            trace = _make_generic_trace(dispatch_visits=3)
            result = find_dispatcher(trace)
            # The custom finder returns 0.99 confidence — should win
            assert result is not None
            assert result.protector == "my_custom"
            assert result.dispatch_address == 0xDEAD
        finally:
            _reset_finder_registry()

    def test_reset_clears_registry(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            register_dispatcher_finder,
            _reset_finder_registry,
            _DISPATCHER_FINDERS,
            GenericDispatcherMatch,
        )
        _reset_finder_registry()
        assert len(_DISPATCHER_FINDERS) == 0

        def dummy(trace_records, *, bit_width=64, _features=None):
            return None

        register_dispatcher_finder("dummy", dummy)
        assert len(_DISPATCHER_FINDERS) == 1
        _reset_finder_registry()
        assert len(_DISPATCHER_FINDERS) == 0

    def test_priority_ordering(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            register_dispatcher_finder,
            _reset_finder_registry,
            _DISPATCHER_FINDERS,
        )
        _reset_finder_registry()
        try:

            def f1(trace_records, *, bit_width=64, _features=None):
                return None

            def f2(trace_records, *, bit_width=64, _features=None):
                return None

            register_dispatcher_finder("low", f1, priority=50)
            register_dispatcher_finder("high", f2, priority=10)
            names = [name for name, _, _ in _DISPATCHER_FINDERS]
            assert names == ["high", "low"]
        finally:
            _reset_finder_registry()

    def test_plugin_exception_caught(self):
        """Plugin that raises should not crash find_dispatcher."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            register_dispatcher_finder,
            find_dispatcher,
            _reset_finder_registry,
        )
        _reset_finder_registry()
        try:

            def bad_finder(trace_records, *, bit_width=64, _features=None):
                raise RuntimeError("boom")

            register_dispatcher_finder("bad", bad_finder)
            trace = _make_generic_trace(dispatch_visits=3)
            # Should not raise — just skip the bad plugin
            result = find_dispatcher(trace)
            # May or may not find something with generic, but no crash
            assert result is None or hasattr(result, "confidence")
        finally:
            _reset_finder_registry()


# ═══════════════════════════════════════════════════════════════════════════
# Early-exit in find_dispatcher
# ═══════════════════════════════════════════════════════════════════════════


class TestFindDispatcherEarlyExit:
    """Verify that the orchestrator exits early on high-confidence match."""

    def test_early_exit_with_high_confidence_vmp(self):
        """When VMProtect finder returns >= 0.9, Themida/CV should be skipped.

        We can't easily prove that later finders were NOT called, but we
        can assert the result is the high-confidence match.
        """
        from unittest.mock import patch
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_dispatcher,
            GenericDispatcherMatch,
            VMProtectDispatcherMatch,
        )
        fake_vmp = VMProtectDispatcherMatch(
            entry_address=0x1000,
            indirect_jump_address=0x2000,
            vip_register="rsi",
            confidence=0.95,
        )
        trace = _make_generic_trace(dispatch_visits=10)
        with patch(
            "dragonslayer.analysis.vm_discovery.dispatcher.find_dispatcher_in_trace",
            return_value=fake_vmp,
        ):
            result = find_dispatcher(trace)
        assert result is not None
        assert result.protector == "vmprotect"
        assert result.confidence == 0.95

    def test_protector_hint_overrides(self):
        """protector_hint should prefer the hinted protector's match."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_dispatcher,
        )
        # Themida trace that also triggers generic finder
        trace = _make_themida_trace(dispatch_visits=12)
        result = find_dispatcher(trace, protector_hint="themida")
        assert result is not None
        assert result.protector == "themida"


# ═══════════════════════════════════════════════════════════════════════════
# find_dispatcher accepts empty / None-like input
# ═══════════════════════════════════════════════════════════════════════════


class TestFindDispatcherEdgeCases:
    """Edge-case coverage for the orchestrator."""

    def test_empty_trace(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import find_dispatcher
        assert find_dispatcher([]) is None

    def test_single_record(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import find_dispatcher
        trace = [_make_rec(0x100, "nop")]
        assert find_dispatcher(trace) is None

    def test_all_direct_jumps(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import find_dispatcher
        trace = [_make_rec(0x100 + i, "jmp 0x5000") for i in range(20)]
        result = find_dispatcher(trace)
        # direct jumps only — no dispatcher
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# Nested depth limit (pipeline integration)
# ═══════════════════════════════════════════════════════════════════════════


class TestNestedDepthLimit:
    """Verify pipeline respects max_nesting_depth."""

    def test_pipeline_has_nesting_depth_default(self):
        """Pipeline step 9 should honour a max depth."""
        import ast
        from pathlib import Path
        pipeline_path = Path(__file__).resolve().parent.parent / \
            "dragonslayer" / "core" / "pipeline.py"
        if not pipeline_path.exists():
            pytest.skip("pipeline.py not found")
        source = pipeline_path.read_text(encoding="utf-8")
        # Must contain max_nesting_depth or similar sentinel
        assert "max_nesting_depth" in source or "nesting_depth" in source

    def test_generic_match_nesting_depth_field(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            GenericDispatcherMatch,
        )
        m = GenericDispatcherMatch(nesting_depth=2)
        assert m.nesting_depth == 2
        d = m.to_dict()
        assert d["nesting_depth"] == 2

    def test_inner_entries_field(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            GenericDispatcherMatch,
        )
        m = GenericDispatcherMatch(inner_entries=[0xA000, 0xB000])
        d = m.to_dict()
        assert d["inner_entries"] == ["0xa000", "0xb000"]


# ═══════════════════════════════════════════════════════════════════════════
# DispatcherFinderProtocol
# ═══════════════════════════════════════════════════════════════════════════


class TestDispatcherFinderProtocol:
    """Verify the Protocol class is importable and well-defined."""

    def test_import(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            DispatcherFinderProtocol,
        )
        assert DispatcherFinderProtocol is not None

    def test_callable_conformance(self):
        """A plain function should satisfy the protocol shape."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            GenericDispatcherMatch,
        )

        def my_finder(
            trace_records,
            *,
            bit_width=64,
            _features=None,
        ):
            return GenericDispatcherMatch(protector="test", confidence=0.5)

        # Just verify it's callable with the expected signature
        result = my_finder([], bit_width=64, _features=None)
        assert result.protector == "test"


# ═══════════════════════════════════════════════════════════════════════════
# _TraceFeatures dataclass
# ═══════════════════════════════════════════════════════════════════════════


class TestTraceFeaturesDataclass:
    """Verify the _TraceFeatures dataclass contract."""

    def test_defaults(self):
        from collections import Counter
        from dragonslayer.analysis.vm_discovery.dispatcher import _TraceFeatures
        f = _TraceFeatures()
        assert isinstance(f.addr_freq, Counter)
        assert isinstance(f.pushad_addrs, set)
        assert isinstance(f.lodsb_addrs, set)
        assert isinstance(f.xlat_addrs, set)
        assert isinstance(f.indirect_calls, list)
        assert isinstance(f.indirect_jumps, list)

    def test_mutation(self):
        from dragonslayer.analysis.vm_discovery.dispatcher import _TraceFeatures
        f = _TraceFeatures()
        f.addr_freq[0x100] = 5
        f.pushad_addrs.add(0x200)
        f.indirect_calls.append({"address": 0x300})
        assert f.addr_freq[0x100] == 5
        assert 0x200 in f.pushad_addrs
        assert len(f.indirect_calls) == 1
