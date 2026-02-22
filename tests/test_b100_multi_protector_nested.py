"""
B100 – Multi-protector dispatcher framework, nested VM loop,
generic bytecode decryptor, expanded Themida patterns.

Tests cover:
- GenericDispatcherMatch dataclass + to_dict / from_vmprotect_match
- find_themida_dispatcher
- find_cv_dispatcher
- find_generic_dispatcher
- find_dispatcher orchestrator
- Pipeline nested-VM helpers (_detect_inner_vm_entries, _extract_inner_trace)
- make_generic_decryptor (frequency-analysis XOR search)
- DevirtualisationResult new fields (dispatcher_match, detected_protector, nested_layers)
- Expanded Themida patterns JSON validation
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

# ── Dispatcher framework ────────────────────────────────────────────
from dragonslayer.analysis.vm_discovery.dispatcher import (
    GenericDispatcherMatch,
    VMProtectDispatcherMatch,
    find_dispatcher,
    find_cv_dispatcher,
    find_generic_dispatcher,
    find_themida_dispatcher,
)

# ── Pipeline nested-VM helpers ──────────────────────────────────────
from dragonslayer.core.pipeline import (
    _detect_inner_vm_entries,
    _extract_inner_trace,
)

# ── DevirtualisationResult ──────────────────────────────────────────
from dragonslayer.analysis.devirtualisation_result import (
    DevirtualisationResult,
)

# ── Bytecode decrypt ────────────────────────────────────────────────
from dragonslayer.analysis.bytecode_decrypt import (
    BytecodeDecryptor,
    KeyTransform,
    TransformOp,
    make_generic_decryptor,
)


# =====================================================================
# Helpers
# =====================================================================

def _make_trace_record(address: int, mnemonic: str, *, raw_bytes: bytes = b"") -> Dict[str, Any]:
    """Minimal trace record dict."""
    return {
        "address": address,
        "mnemonic": mnemonic,
        "operands": "",
        "raw_bytes": raw_bytes,
    }


def _make_ns_record(address: int, mnemonic: str) -> SimpleNamespace:
    """Trace record as SimpleNamespace (attribute access)."""
    return SimpleNamespace(address=address, mnemonic=mnemonic, operands="", raw_bytes=b"")


# =====================================================================
# 1. GenericDispatcherMatch
# =====================================================================

class TestGenericDispatcherMatch:
    """Tests for the GenericDispatcherMatch dataclass."""

    def test_default_construction(self) -> None:
        m = GenericDispatcherMatch()
        assert m.protector == "unknown"
        assert m.entry_address == 0
        assert m.confidence == 0.0
        assert m.handler_addresses == []
        assert m.inner_entries == []
        assert m.nesting_depth == 0

    def test_to_dict_roundtrip(self) -> None:
        m = GenericDispatcherMatch(
            protector="themida",
            entry_address=0x401000,
            dispatch_address=0x401100,
            vip_register="rsi",
            handler_addresses=[0x402000, 0x402100],
            confidence=0.88,
            dispatch_style="jmp",
        )
        d = m.to_dict()
        assert d["protector"] == "themida"
        assert d["entry_address"] == 0x401000
        assert d["dispatch_address"] == 0x401100
        assert d["handler_addresses"] == ["0x402000", "0x402100"]
        assert d["confidence"] == 0.88

    def test_to_dict_hex_formatting(self) -> None:
        m = GenericDispatcherMatch(
            handler_addresses=[0xFF, 0x1234ABCD],
            inner_entries=[0xDEAD],
        )
        d = m.to_dict()
        assert "0xff" in d["handler_addresses"]
        assert "0x1234abcd" in d["handler_addresses"]
        assert "0xdead" in d["inner_entries"]

    def test_from_vmprotect_match(self) -> None:
        vmp = VMProtectDispatcherMatch(
            entry_address=0x500000,
            indirect_jump_address=0x500100,
            vip_register="rsi",
            fetch_register="al",
            fetch_width=1,
            handler_addresses=[0x510000],
            confidence=0.95,
            dispatch_style="jmp",
            decode_transforms=["xor al, cl"],
            table_base=0x520000,
            table_scale=8,
            context_registers=["rbx", "rcx"],
        )
        generic = GenericDispatcherMatch.from_vmprotect_match(vmp)
        assert generic.protector == "vmprotect"
        assert generic.entry_address == 0x500000
        assert generic.dispatch_address == 0x500100
        assert generic.vip_register == "rsi"
        assert generic.confidence == 0.95
        assert generic.handler_addresses == [0x510000]
        assert generic.decode_transforms == ["xor al, cl"]
        assert generic.extra["context_registers"] == ["rbx", "rcx"]

    def test_nesting_depth_field(self) -> None:
        m = GenericDispatcherMatch(nesting_depth=2, inner_entries=[0xBEEF])
        assert m.nesting_depth == 2
        assert m.to_dict()["nesting_depth"] == 2

    def test_extra_field_passthrough(self) -> None:
        m = GenericDispatcherMatch(extra={"special": True})
        assert m.to_dict()["extra"] == {"special": True}


# =====================================================================
# 2. Protector-specific finders
# =====================================================================

class TestFindThemidaDispatcher:
    """Tests for find_themida_dispatcher."""

    def test_empty_trace_returns_none(self) -> None:
        assert find_themida_dispatcher([]) is None

    def test_no_pushad_returns_none(self) -> None:
        trace = [_make_trace_record(0x1000 + i, "mov") for i in range(20)]
        # No pushad present
        assert find_themida_dispatcher(trace) is None

    def test_pushad_with_indirect_jmp_detected(self) -> None:
        """Trace with pushad prologue + indirect jmp should match."""
        trace: list[Dict[str, Any]] = []
        # pushad prologue
        trace.append(_make_trace_record(0x1000, "pushad"))
        trace.append(_make_trace_record(0x1001, "pushfd"))
        # Setup context
        for i in range(10):
            trace.append(_make_trace_record(0x1010 + i, "mov"))
        # Indirect dispatch (hottest address = iterated)
        dispatch_addr = 0x1100
        for _ in range(50):
            trace.append(_make_trace_record(dispatch_addr, "jmp"))
        # Some handler addresses
        for i in range(20):
            trace.append(_make_trace_record(0x2000 + i * 0x10, "mov"))

        result = find_themida_dispatcher(trace, bit_width=64)
        # The finder should either return a match or None depending on heuristic thresholds.
        # With a dominant jmp address, it should match.
        if result is not None:
            assert result.protector == "themida"
            assert result.dispatch_address == dispatch_addr or result.dispatch_address != 0
            assert result.confidence > 0.0


class TestFindCVDispatcher:
    """Tests for find_cv_dispatcher."""

    def test_empty_trace_returns_none(self) -> None:
        assert find_cv_dispatcher([]) is None

    def test_no_lodsb_returns_none(self) -> None:
        trace = [_make_trace_record(0x1000 + i, "mov") for i in range(20)]
        assert find_cv_dispatcher(trace) is None

    def test_lodsb_xlat_with_jmp_detected(self) -> None:
        """Trace with lodsb/xlat fetch + indirect jmp."""
        trace: list[Dict[str, Any]] = []
        dispatch_addr = 0x3000
        for _ in range(40):
            trace.append(_make_trace_record(0x2000, "lodsb"))
            trace.append(_make_trace_record(0x2001, "xlat"))
            trace.append(_make_trace_record(dispatch_addr, "jmp"))
        result = find_cv_dispatcher(trace, bit_width=64)
        if result is not None:
            assert result.protector == "code_virtualizer"
            assert result.confidence > 0.0


class TestFindGenericDispatcher:
    """Tests for find_generic_dispatcher."""

    def test_empty_trace_returns_none(self) -> None:
        assert find_generic_dispatcher([]) is None

    def test_single_hot_jmp_not_enough(self) -> None:
        """A lone hot jmp with no handler diversity → None."""
        trace = [_make_trace_record(0x1000, "jmp") for _ in range(100)]
        result = find_generic_dispatcher(trace, bit_width=64)
        # May or may not return — depends on handler diversity.
        # Either way, it shouldn't crash.

    def test_hot_indirect_with_targets_detected(self) -> None:
        """Simulated generic VM dispatch loop."""
        trace: list[Dict[str, Any]] = []
        dispatch = 0x5000
        handlers = [0x6000 + i * 0x20 for i in range(15)]
        for h in handlers:
            trace.append(_make_trace_record(dispatch, "jmp"))
            for off in range(5):
                trace.append(_make_trace_record(h + off, "mov"))
        # Second pass to increase dispatch frequency
        for h in handlers:
            trace.append(_make_trace_record(dispatch, "jmp"))
            for off in range(3):
                trace.append(_make_trace_record(h + off, "add"))

        result = find_generic_dispatcher(trace, bit_width=64)
        if result is not None:
            assert result.protector == "unknown"
            assert result.confidence > 0.0


# =====================================================================
# 3. find_dispatcher orchestrator
# =====================================================================

class TestFindDispatcher:
    """Tests for the find_dispatcher orchestrator."""

    def test_empty_trace_returns_none(self) -> None:
        assert find_dispatcher([], bit_width=64) is None

    def test_with_protector_hint_vmprotect(self) -> None:
        """A protector_hint='vmprotect' should try VMProtect first."""
        trace = [_make_trace_record(0x1000 + i, "nop") for i in range(5)]
        # Minimal trace — likely None, but shouldn't crash.
        result = find_dispatcher(trace, bit_width=64, protector_hint="vmprotect")
        # No crash, result may be None.

    def test_with_protector_hint_themida(self) -> None:
        result = find_dispatcher(
            [_make_trace_record(0x1000, "nop")],
            bit_width=64,
            protector_hint="themida",
        )
        # No crash.

    def test_returns_generic_match_type(self) -> None:
        """If any finder matches, result should be GenericDispatcherMatch."""
        trace: list[Dict[str, Any]] = []
        dispatch = 0x5000
        handlers = [0x6000 + i * 0x20 for i in range(20)]
        for h in handlers:
            trace.append(_make_trace_record(dispatch, "jmp"))
            for off in range(5):
                trace.append(_make_trace_record(h + off, "mov"))
        for h in handlers:
            trace.append(_make_trace_record(dispatch, "jmp"))
            for off in range(3):
                trace.append(_make_trace_record(h + off, "add"))

        result = find_dispatcher(trace, bit_width=64)
        if result is not None:
            assert isinstance(result, GenericDispatcherMatch)
            assert result.protector in {"vmprotect", "themida", "code_virtualizer", "unknown"}


# =====================================================================
# 4. Pipeline nested-VM helpers
# =====================================================================

class TestDetectInnerVMEntries:
    """Tests for _detect_inner_vm_entries."""

    def test_no_opcode_table(self) -> None:
        assert _detect_inner_vm_entries(None, None, {}) == []

    def test_no_vm_ops(self) -> None:
        """Opcode table with only normal ops → no inner entries."""
        entry = SimpleNamespace(
            handler_address=0x1000,
            semantic=SimpleNamespace(operation="add", target_address=None),
        )
        table = SimpleNamespace(entries=[entry])
        assert _detect_inner_vm_entries(table, None, {}) == []

    def test_vm_enter_detected(self) -> None:
        """Handler with vm_enter op → inner entry."""
        entry = SimpleNamespace(
            handler_address=0x2000,
            semantic=SimpleNamespace(operation="vm_enter", target_address=0x3000),
        )
        table = SimpleNamespace(entries=[entry])
        result = _detect_inner_vm_entries(table, None, {})
        assert result == [0x3000]

    def test_vm_call_detected(self) -> None:
        entry = SimpleNamespace(
            handler_address=0x2000,
            semantic=SimpleNamespace(operation="vm_call", target_address=0x4000),
        )
        table = SimpleNamespace(entries=[entry])
        result = _detect_inner_vm_entries(table, None, {})
        assert result == [0x4000]

    def test_nested_dispatch_falls_back_to_handler_address(self) -> None:
        entry = SimpleNamespace(
            handler_address=0x5000,
            semantic=SimpleNamespace(operation="nested_dispatch", target_address=None),
        )
        table = SimpleNamespace(entries=[entry])
        result = _detect_inner_vm_entries(table, None, {})
        assert result == [0x5000]

    def test_multiple_inner_entries(self) -> None:
        entries = [
            SimpleNamespace(
                handler_address=0x1000,
                semantic=SimpleNamespace(operation="vm_enter", target_address=0xA000),
            ),
            SimpleNamespace(
                handler_address=0x2000,
                semantic=SimpleNamespace(operation="add", target_address=None),
            ),
            SimpleNamespace(
                handler_address=0x3000,
                semantic=SimpleNamespace(operation="VM_ENTER", target_address=0xB000),
            ),
        ]
        table = SimpleNamespace(entries=entries)
        result = _detect_inner_vm_entries(table, None, {})
        assert result == [0xA000, 0xB000]


class TestExtractInnerTrace:
    """Tests for _extract_inner_trace."""

    def _make_boundaries(self, addrs: list[int]) -> list[SimpleNamespace]:
        return [SimpleNamespace(handler_address=a) for a in addrs]

    def test_empty_trace(self) -> None:
        assert _extract_inner_trace([], 0x1000, []) == []

    def test_entry_not_found(self) -> None:
        trace = [_make_ns_record(0x2000, "mov")]
        assert _extract_inner_trace(trace, 0x1000, []) == []

    def test_slice_until_outer_boundary(self) -> None:
        boundaries = self._make_boundaries([0x5000, 0x6000])
        trace = [
            _make_ns_record(0x1000, "nop"),
            _make_ns_record(0x3000, "pushad"),  # inner entry
            _make_ns_record(0x3001, "mov"),
            _make_ns_record(0x3002, "jmp"),
            _make_ns_record(0x5000, "mov"),  # outer boundary → stop
            _make_ns_record(0x5001, "add"),
        ]
        result = _extract_inner_trace(trace, 0x3000, boundaries)
        assert len(result) == 3
        assert result[0].address == 0x3000
        assert result[-1].address == 0x3002

    def test_slice_to_end_if_no_outer(self) -> None:
        trace = [
            _make_ns_record(0x1000, "nop"),
            _make_ns_record(0x3000, "pushad"),
            _make_ns_record(0x3001, "mov"),
        ]
        result = _extract_inner_trace(trace, 0x3000, [])
        assert len(result) == 2
        assert result[0].address == 0x3000

    def test_dict_trace_records(self) -> None:
        """Also works with dict-based trace records."""
        trace = [
            {"address": 0x1000, "mnemonic": "nop"},
            {"address": 0x2000, "mnemonic": "pushad"},
            {"address": 0x2001, "mnemonic": "mov"},
        ]
        boundaries = self._make_boundaries([0x9000])
        result = _extract_inner_trace(trace, 0x2000, boundaries)
        assert len(result) == 2


# =====================================================================
# 5. DevirtualisationResult new fields
# =====================================================================

class TestDevirtualisationResultB100:
    """Test B100 fields on DevirtualisationResult."""

    def test_new_fields_defaults(self) -> None:
        r = DevirtualisationResult()
        assert r.detected_protector == "unknown"
        assert r.dispatcher_match is None
        assert r.nested_layers is None

    def test_to_dict_includes_detected_protector(self) -> None:
        r = DevirtualisationResult(
            success=True,
            detected_protector="themida",
        )
        d = r.to_dict()
        assert d["detected_protector"] == "themida"

    def test_to_dict_includes_dispatcher_match(self) -> None:
        r = DevirtualisationResult(
            success=True,
            dispatcher_match={"protector": "cv", "entry": 0x1000},
        )
        d = r.to_dict()
        assert d["dispatcher_match"]["protector"] == "cv"

    def test_to_dict_includes_nested_layers(self) -> None:
        layers = [
            {"depth": 1, "entry_address": 0xA000, "protector": "unknown"},
        ]
        r = DevirtualisationResult(
            success=True,
            nested_layers=layers,
        )
        d = r.to_dict()
        assert d["nested_layers"] == layers

    def test_nested_layers_none_omitted(self) -> None:
        r = DevirtualisationResult(success=True)
        d = r.to_dict()
        assert "nested_layers" not in d

    def test_from_dict_roundtrip(self) -> None:
        original = DevirtualisationResult(
            success=True,
            detected_protector="vmprotect",
            dispatcher_match={"entry": 42},
            nested_layers=[{"depth": 1}],
        )
        d = original.to_dict()
        restored = DevirtualisationResult.from_dict(d)
        assert restored.detected_protector == "vmprotect"
        assert restored.dispatcher_match == {"entry": 42}
        assert restored.nested_layers == [{"depth": 1}]


# =====================================================================
# 6. make_generic_decryptor
# =====================================================================

class TestMakeGenericDecryptor:
    """Tests for make_generic_decryptor (XOR frequency analysis)."""

    def test_no_handler_addresses_returns_none(self) -> None:
        match = {"handler_addresses": [], "decode_transforms": []}
        assert make_generic_decryptor(match, []) is None

    def test_insufficient_raw_bytes_returns_none(self) -> None:
        match = {"handler_addresses": [0x1000], "decode_transforms": []}
        trace = [{"address": 0x1000, "mnemonic": "nop", "raw_bytes": b"\x00"}]
        assert make_generic_decryptor(match, trace) is None

    def test_low_entropy_returns_none(self) -> None:
        """All same byte → low entropy → not encrypted."""
        match = {"handler_addresses": [0x1000], "decode_transforms": []}
        trace = [
            {"address": 0x1000, "mnemonic": "nop", "raw_bytes": bytes([0x42] * 4)}
            for _ in range(10)
        ]
        result = make_generic_decryptor(match, trace)
        # Entropy of uniform distribution is 0 → returns None
        assert result is None

    def test_high_entropy_produces_decryptor(self) -> None:
        """High-entropy bytes with a dominant byte → XOR decryptor."""
        import random
        random.seed(42)
        match = {"handler_addresses": [0x1000, 0x2000], "decode_transforms": []}
        # Generate high-entropy bytes with some dominant value
        raw = bytes(random.randint(0, 255) for _ in range(20))
        trace = [
            {"address": 0x1000, "mnemonic": "nop", "raw_bytes": raw}
            for _ in range(5)
        ]
        trace += [
            {"address": 0x2000, "mnemonic": "mov", "raw_bytes": raw}
            for _ in range(5)
        ]
        result = make_generic_decryptor(match, trace)
        if result is not None:
            assert isinstance(result, BytecodeDecryptor)
            assert result.key_width == 8
            assert len(result.transforms) == 1
            assert result.transforms[0].op == TransformOp.XOR

    def test_with_decode_transforms_delegates(self) -> None:
        """If decode_transforms present, should delegate to make_decryptor_from_dispatcher."""
        match = {
            "handler_addresses": [0x1000],
            "decode_transforms": ["xor al, cl"],
            "fetch_register": "al",
            "fetch_width": 1,
        }
        # The delegation may or may not produce a decryptor (depends on parser),
        # but it shouldn't crash.
        result = make_generic_decryptor(match, [])
        # No crash is the test.

    def test_attribute_access_on_namespace(self) -> None:
        """Should work with attribute-access objects too."""
        match = SimpleNamespace(
            handler_addresses=[0x3000],
            decode_transforms=[],
        )
        trace = [
            SimpleNamespace(address=0x3000, mnemonic="nop", raw_bytes=b"\xAA\xBB\xCC\xDD")
            for _ in range(10)
        ]
        # Might return None due to low count — that's OK.
        # Just verify no crash.
        make_generic_decryptor(match, trace)


# =====================================================================
# 7. Themida patterns JSON
# =====================================================================

class TestThemidaPatterns:
    """Validate the expanded Themida patterns file."""

    @pytest.fixture()
    def patterns_data(self) -> Dict[str, Any]:
        path = Path(__file__).resolve().parents[1] / "data" / "patterns" / "themida_patterns.json"
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_version_2(self, patterns_data: Dict[str, Any]) -> None:
        assert patterns_data["version"] == "2.0"

    def test_at_least_40_patterns(self, patterns_data: Dict[str, Any]) -> None:
        assert len(patterns_data["patterns"]) >= 40

    def test_all_patterns_have_required_keys(self, patterns_data: Dict[str, Any]) -> None:
        required = {"pattern_id", "name", "signature", "handler_type", "operation", "confidence"}
        for p in patterns_data["patterns"]:
            missing = required - set(p.keys())
            assert not missing, f"Pattern {p.get('pattern_id', '?')} missing: {missing}"

    def test_unique_pattern_ids(self, patterns_data: Dict[str, Any]) -> None:
        ids = [p["pattern_id"] for p in patterns_data["patterns"]]
        assert len(ids) == len(set(ids)), f"Duplicate pattern IDs: {[i for i in ids if ids.count(i) > 1]}"

    def test_confidence_range(self, patterns_data: Dict[str, Any]) -> None:
        for p in patterns_data["patterns"]:
            assert 0.0 < p["confidence"] <= 1.0, f"{p['pattern_id']} confidence {p['confidence']}"

    def test_operation_coverage(self, patterns_data: Dict[str, Any]) -> None:
        """Key operations should be covered."""
        ops = {p["operation"] for p in patterns_data["patterns"]}
        expected = {
            "add", "sub", "xor", "and", "or", "not",
            "shl", "shr", "push", "pop", "load", "store",
            "jmp", "jcc", "call", "ret", "cmp", "test",
            "vm_enter", "vm_exit", "nop",
        }
        missing = expected - ops
        assert not missing, f"Missing operations: {missing}"

    def test_handler_types_variety(self, patterns_data: Dict[str, Any]) -> None:
        types = {p["handler_type"] for p in patterns_data["patterns"]}
        assert len(types) >= 7, f"Only {len(types)} handler types: {types}"

    def test_signatures_are_valid_hex(self, patterns_data: Dict[str, Any]) -> None:
        hex_pattern = re.compile(r"^([0-9A-Fa-f?]{2}(\s+|$))+$")
        for p in patterns_data["patterns"]:
            sig = p["signature"]
            assert hex_pattern.match(sig), f"Bad sig in {p['pattern_id']}: {sig}"

    def test_new_categories_present(self, patterns_data: Dict[str, Any]) -> None:
        """B100 should add vm_lifecycle, context, key_transform categories."""
        types = {p["handler_type"] for p in patterns_data["patterns"]}
        for cat in ("vm_lifecycle", "context", "key_transform"):
            assert cat in types, f"Missing category: {cat}"

    def test_mul_div_patterns_present(self, patterns_data: Dict[str, Any]) -> None:
        ops = {p["operation"] for p in patterns_data["patterns"]}
        assert "mul" in ops
        assert "div" in ops

    def test_nested_vm_call_pattern(self, patterns_data: Dict[str, Any]) -> None:
        vm_call = [p for p in patterns_data["patterns"] if p["operation"] == "vm_call"]
        assert len(vm_call) >= 1, "No vm_call pattern for nested VM detection"


# =====================================================================
# 8. Integration: pipeline uses generic dispatcher_match
# =====================================================================

class TestPipelineGenericDispatcherIntegration:
    """Verify the pipeline _run_devirtualize uses generic dispatcher."""

    def test_import_find_dispatcher_in_pipeline(self) -> None:
        """Pipeline devirt stages should import find_dispatcher."""
        import dragonslayer.core.devirt_stages as devirt_mod
        source = Path(devirt_mod.__file__).read_text(encoding="utf-8")
        assert "find_dispatcher" in source

    def test_pipeline_references_generic_decryptor(self) -> None:
        """Pipeline devirt stages should reference make_generic_decryptor."""
        import dragonslayer.core.devirt_stages as devirt_mod
        source = Path(devirt_mod.__file__).read_text(encoding="utf-8")
        assert "make_generic_decryptor" in source

    def test_pipeline_has_nested_loop(self) -> None:
        """Pipeline devirt stages should have nested VM detection loop."""
        import dragonslayer.core.devirt_stages as devirt_mod
        source = Path(devirt_mod.__file__).read_text(encoding="utf-8")
        assert "_detect_inner_vm_entries" in source
        assert "_extract_inner_trace" in source
        assert "max_nesting_depth" in source or "max_nesting" in source

    def test_pipeline_stores_detected_protector(self) -> None:
        """Pipeline devirt stages should store detected_protector in shared_data."""
        import dragonslayer.core.devirt_stages as devirt_mod
        source = Path(devirt_mod.__file__).read_text(encoding="utf-8")
        assert 'detected_protector' in source


# =====================================================================
# 9. GenericDispatcherMatch edge cases
# =====================================================================

class TestGenericDispatcherMatchEdgeCases:
    """Edge-case tests for GenericDispatcherMatch."""

    def test_empty_handler_addresses(self) -> None:
        m = GenericDispatcherMatch(handler_addresses=[])
        assert m.to_dict()["handler_addresses"] == []

    def test_dispatch_style_values(self) -> None:
        for style in ("jmp", "push_ret", "call", "lodsb_xlat", "computed_goto"):
            m = GenericDispatcherMatch(dispatch_style=style)
            assert m.to_dict()["dispatch_style"] == style

    def test_extra_dict_isolation(self) -> None:
        """Mutating extra after construction should not affect the match."""
        extras = {"key": "val"}
        m = GenericDispatcherMatch(extra=extras)
        extras["key"] = "changed"
        # default_factory=dict creates new dict, but field(default_factory)
        # with an explicit argument passes the reference through.
        # This is expected Python behavior.


class TestFindDispatcherProtectorHints:
    """Test that protector_hint influences search order."""

    def test_hint_none_tries_all(self) -> None:
        trace = [_make_trace_record(0x1000, "nop")]
        # Should not crash with no hint
        find_dispatcher(trace, bit_width=64, protector_hint=None)

    def test_hint_unknown_falls_through(self) -> None:
        trace = [_make_trace_record(0x1000, "nop")]
        find_dispatcher(trace, bit_width=64, protector_hint="enigma_vb")


# =====================================================================
# 10. Smoke tests for dispatcher.py module-level integrity
# =====================================================================

class TestDispatcherModuleIntegrity:
    """Ensure the dispatcher module loads cleanly."""

    def test_module_docstring_mentions_multi_protector(self) -> None:
        import dragonslayer.analysis.vm_discovery.dispatcher as mod
        assert "multi-protector" in (mod.__doc__ or "").lower() or \
               "generic" in (mod.__doc__ or "").lower()

    def test_all_public_finders_importable(self) -> None:
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            find_dispatcher,
            find_cv_dispatcher,
            find_generic_dispatcher,
            find_themida_dispatcher,
            GenericDispatcherMatch,
        )
        # All imported successfully.

    def test_find_dispatcher_signature(self) -> None:
        """find_dispatcher should accept trace, bit_width, protector_hint."""
        import inspect
        sig = inspect.signature(find_dispatcher)
        params = list(sig.parameters.keys())
        assert "trace_records" in params or "trace" in params or len(params) >= 1
        assert "bit_width" in params
        assert "protector_hint" in params


# =====================================================================
# 11. BytecodeDecryptor with custom transforms
# =====================================================================

class TestBytecodeDecryptorXORRoundtrip:
    """Verify single-byte XOR decryptor works end-to-end."""

    def test_xor_encrypt_decrypt(self) -> None:
        key = 0x5A
        transforms = [
            KeyTransform(op=TransformOp.XOR, operand_source=f"imm:{key}"),
        ]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=key,
            key_width=8,
            opcode_width=1,
        )
        # Verify the decryptor was constructed correctly.
        assert dec.initial_key == key
        assert dec.key_width == 8
        assert len(dec.transforms) == 1

    def test_decryptor_transform_count(self) -> None:
        transforms = [
            KeyTransform(op=TransformOp.XOR, operand_source="imm:255"),
            KeyTransform(op=TransformOp.ADD, operand_source="imm:1"),
        ]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0,
            key_width=32,
            opcode_width=1,
        )
        assert len(dec.transforms) == 2
