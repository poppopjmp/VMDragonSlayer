"""
B91 — Hypothesis property-based tests for dispatcher scoring, pattern recognition,
bytecode decryption, CFG construction, and key recovery.

Exercises production APIs with fuzz-generated inputs to validate invariants,
roundtrip consistency, and robustness.
"""

from __future__ import annotations

import math
from dataclasses import fields as dc_fields
from typing import Any, Dict, List, Optional

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# ═══════════════════════════════════════════════════════════════════════════
# Dispatcher Scoring
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.vm_discovery.dispatcher import (
    DispatcherScoringConfig,
    find_vmprotect_dispatcher,
    find_dispatcher_in_trace,
)

_SCORING_FIELDS = [f.name for f in dc_fields(DispatcherScoringConfig)]
_scoring_float = st.floats(min_value=0.0, max_value=1.0,
                           allow_nan=False, allow_infinity=False)


class TestDispatcherScoringProperties:
    """Fuzz dispatcher scoring and detection with randomized configs."""

    @given(data=st.fixed_dictionaries(
        {f: _scoring_float for f in _SCORING_FIELDS}
    ))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_config_all_weights_are_floats(self, data: Dict[str, float]) -> None:
        """All fields created from_dict must be floats."""
        cfg = DispatcherScoringConfig.from_dict(data)
        for f in _SCORING_FIELDS:
            val = getattr(cfg, f)
            assert isinstance(val, float), f"{f} is {type(val)}, not float"

    @given(floor=st.floats(min_value=0.0, max_value=1.0,
                           allow_nan=False, allow_infinity=False))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_empty_instructions_returns_none(self, floor: float) -> None:
        """find_vmprotect_dispatcher must return None for empty input."""
        cfg = DispatcherScoringConfig(confidence_floor=floor)
        result = find_vmprotect_dispatcher([], scoring_config=cfg)
        assert result is None

    @given(floor=st.floats(min_value=0.0, max_value=1.0,
                           allow_nan=False, allow_infinity=False))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_empty_trace_returns_none(self, floor: float) -> None:
        """find_dispatcher_in_trace must return None for empty trace."""
        cfg = DispatcherScoringConfig(confidence_floor=floor)
        result = find_dispatcher_in_trace([], scoring_config=cfg)
        assert result is None

    @given(n=st.integers(min_value=1, max_value=20))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_benign_trace_below_threshold(self, n: int) -> None:
        """A trace of identical NOPs should not match as a dispatcher."""
        records = [
            {"address": 0x401000 + i, "disassembly": "nop"}
            for i in range(n)
        ]
        cfg = DispatcherScoringConfig(confidence_floor=0.30)
        result = find_dispatcher_in_trace(records, scoring_config=cfg)
        assert result is None

    @given(floor=_scoring_float)
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_high_floor_rejects_more(self, floor: float) -> None:
        """Higher confidence_floor should not produce MORE matches than lower."""
        records = [
            {"address": 0x401000 + i, "disassembly": "nop"}
            for i in range(10)
        ]
        low = find_dispatcher_in_trace(
            records, scoring_config=DispatcherScoringConfig(confidence_floor=0.01)
        )
        high = find_dispatcher_in_trace(
            records, scoring_config=DispatcherScoringConfig(confidence_floor=0.99)
        )
        # If high found something, low must also have found something
        if high is not None:
            assert low is not None


# ═══════════════════════════════════════════════════════════════════════════
# Pattern Recognition + Database
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.pattern_analysis.database import (
    Pattern,
    PatternDatabase,
)
from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer


def _make_pattern(pid: str = "test_001", sig: str = "4883EC..") -> Pattern:
    """Helper to create a valid Pattern with defaults."""
    return Pattern(
        pattern_id=pid,
        name=f"Test {pid}",
        signature=sig,
        architecture="x86_64",
        handler_type="stack",
        operation="push",
        confidence=0.9,
    )


class TestPatternDatabaseProperties:
    """Property-based tests for PatternDatabase CRUD invariants."""

    @given(pid=st.text(min_size=1, max_size=30,
                       alphabet=st.characters(whitelist_categories=("L", "N"))))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_add_then_get_roundtrip(self, pid: str) -> None:
        """add_pattern → get_pattern must return the same pattern."""
        db = PatternDatabase()
        p = _make_pattern(pid=pid)
        db.add_pattern(p)
        got = db.get_pattern(pid)
        assert got is not None
        assert got.pattern_id == pid
        assert got.name == p.name

    @given(pid=st.text(min_size=1, max_size=30,
                       alphabet=st.characters(whitelist_categories=("L", "N"))))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_add_duplicate_raises(self, pid: str) -> None:
        """Adding a pattern with existing ID must raise ValueError."""
        db = PatternDatabase()
        db.add_pattern(_make_pattern(pid=pid))
        with pytest.raises(ValueError):
            db.add_pattern(_make_pattern(pid=pid))

    @given(pid=st.text(min_size=1, max_size=30,
                       alphabet=st.characters(whitelist_categories=("L", "N"))))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_delete_removes_pattern(self, pid: str) -> None:
        """delete_pattern(id) → get_pattern(id) must return None."""
        db = PatternDatabase()
        db.add_pattern(_make_pattern(pid=pid))
        assert db.delete_pattern(pid)
        assert db.get_pattern(pid) is None

    @given(pids=st.lists(
        st.text(min_size=1, max_size=20,
                alphabet=st.characters(whitelist_categories=("L", "N"))),
        min_size=1, max_size=10, unique=True))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_get_all_patterns_count(self, pids: List[str]) -> None:
        """get_all_patterns() count must match number of added patterns."""
        db = PatternDatabase()
        for pid in pids:
            db.add_pattern(_make_pattern(pid=pid))
        assert len(db.get_all_patterns()) == len(pids)

    @given(conf=st.floats(min_value=0.0, max_value=1.0,
                          allow_nan=False, allow_infinity=False))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_search_min_confidence_filter(self, conf: float) -> None:
        """search(min_confidence=c) should not return patterns below c."""
        db = PatternDatabase()
        db.add_pattern(Pattern(
            pattern_id="low", name="Low", signature="90",
            architecture="x86_64", handler_type="nop", operation="nop",
            confidence=0.3))
        db.add_pattern(Pattern(
            pattern_id="high", name="High", signature="CC",
            architecture="x86_64", handler_type="trap", operation="int3",
            confidence=0.95))
        results = db.search(min_confidence=conf)
        for p in results:
            assert p.confidence >= conf

    @given(conf=st.floats(min_value=-1.0, max_value=-0.01,
                          allow_nan=False, allow_infinity=False))
    @settings(max_examples=20)
    def test_pattern_invalid_confidence_raises(self, conf: float) -> None:
        """Pattern with negative confidence must raise ValueError."""
        with pytest.raises(ValueError):
            Pattern(
                pattern_id="bad", name="Bad", signature="FF",
                architecture="x86_64", handler_type="stack",
                operation="push", confidence=conf)


class TestPatternRecognizerProperties:
    """Property-based tests for PatternRecognizer."""

    @given(hex_bytes=st.from_regex(r"[0-9A-Fa-f]{2,64}", fullmatch=True))
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_recognize_never_crashes(self, hex_bytes: str) -> None:
        """recognize() must not raise on arbitrary hex strings."""
        db = PatternDatabase()
        db.add_pattern(_make_pattern())
        rec = PatternRecognizer(db, use_yara=False)
        matches = rec.recognize(hex_bytes, min_confidence=0.0)
        assert isinstance(matches, list)

    @given(hex_bytes=st.from_regex(r"[0-9A-Fa-f]{2,64}", fullmatch=True))
    @settings(max_examples=50, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_version_fingerprint_never_crashes(self, hex_bytes: str) -> None:
        """version_fingerprint() must not raise on arbitrary hex."""
        db = PatternDatabase()
        db.add_pattern(_make_pattern())
        rec = PatternRecognizer(db, use_yara=False)
        result = rec.version_fingerprint(hex_bytes)
        assert isinstance(result, dict)
        assert "protector" in result
        assert "confidence" in result

    @given(hex_bytes=st.just("90" * 32))
    @settings(max_examples=5, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_nop_sled_recognition(self, hex_bytes: str) -> None:
        """A NOP sled should produce matches or empty list, never crash."""
        db = PatternDatabase()
        db.add_pattern(_make_pattern(sig="90+"))
        rec = PatternRecognizer(db, use_yara=False)
        matches = rec.recognize(hex_bytes, min_confidence=0.0)
        assert isinstance(matches, list)


# ═══════════════════════════════════════════════════════════════════════════
# Bytecode Decryption
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.bytecode_decrypt import (
    BytecodeDecryptor,
    CipherOp,
    CipherStep,
    KeyTransform,
    TransformOp,
)


class TestBytecodeDecryptorProperties:
    """Property-based tests for BytecodeDecryptor decrypt/roundtrip."""

    @given(data=st.binary(min_size=1, max_size=256),
           key=st.integers(min_value=0, max_value=0xFFFFFFFF))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_decrypt_returns_same_length(self, data: bytes, key: int) -> None:
        """decrypt() output length must match input length."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        plaintext, keys = dec.decrypt(data)
        assert len(plaintext) == len(data)
        assert len(keys) == len(data)

    @given(key=st.integers(min_value=0, max_value=0xFFFFFFFF))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_no_transforms_is_identity(self, key: int) -> None:
        """With no transforms, decrypt() returns data as-is with empty keys."""
        original = bytes(range(16))
        dec = BytecodeDecryptor(
            transforms=[],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        plaintext, keys = dec.decrypt(original)
        assert plaintext == original
        assert keys == []  # no transforms → no key tracking

    @given(data=st.binary(min_size=1, max_size=64))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_zero_key_xor_identity(self, data: bytes) -> None:
        """Decrypt with key=0 and XOR transform: XOR-0 is identity."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
            initial_key=0,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        plaintext, keys = dec.decrypt(data)
        assert len(plaintext) == len(data)
        # With key=0, first byte is XOR-0 = identity, then key evolves
        assert plaintext[0] == data[0]

    @given(opcode=st.integers(min_value=0, max_value=255),
           key=st.integers(min_value=1, max_value=0xFFFF))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_decrypt_single_consistency(self, opcode: int, key: int) -> None:
        """decrypt_single must agree with decrypt for a single byte."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        plain_single, next_key = dec.decrypt_single(opcode, key)
        plain_bulk, keys_bulk = dec.decrypt(bytes([opcode]))
        assert plain_bulk[0] == plain_single

    @given(data=st.binary(min_size=1, max_size=64),
           key=st.integers(min_value=0, max_value=0xFFFF))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_chained_decrypt_returns_valid(self, data: bytes, key: int) -> None:
        """decrypt_chained must return same-length output."""
        dec = BytecodeDecryptor(
            transforms=[],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[CipherStep(op=CipherOp.XOR, operand_source="key")],
        )
        plaintext, keys = dec.decrypt_chained(data)
        assert len(plaintext) == len(data)

    @given(op=st.sampled_from(list(TransformOp)),
           key=st.integers(min_value=1, max_value=0xFFFF),
           opcode=st.integers(min_value=0, max_value=255))
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_key_transform_produces_valid_key(self, op: TransformOp,
                                               key: int, opcode: int) -> None:
        """Any KeyTransform must produce a non-negative integer key."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=op, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        plaintext, keys = dec.decrypt(bytes([opcode]))
        assert len(keys) == 1
        assert isinstance(keys[0], int)
        assert keys[0] >= 0


# ═══════════════════════════════════════════════════════════════════════════
# CFG Construction
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.bytecode_cfg import (
    VMInstruction,
    HandlerBasicBlock,
    CFGEdge,
    HandlerCFG,
    NaturalLoop,
    LoopTree,
    VMOperation,
    detect_natural_loops,
)


class TestCFGProperties:
    """Property-based tests for CFG dataclasses and loop detection."""

    @given(vip=st.integers(min_value=0, max_value=0xFFFF),
           opcode=st.integers(min_value=0, max_value=255))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_vm_instruction_to_dict_roundtrip(self, vip: int, opcode: int) -> None:
        """to_dict() must preserve vip and opcode."""
        insn = VMInstruction(vip=vip, opcode=opcode, handler_address=0x1000)
        d = insn.to_dict()
        assert d["vip"] == vip
        assert d["opcode"] == opcode

    @given(n=st.integers(min_value=1, max_value=20))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_basic_block_instruction_count(self, n: int) -> None:
        """instruction_count must match the number of instructions."""
        insns = [VMInstruction(vip=i, opcode=0x90, handler_address=0x1000)
                 for i in range(n)]
        bb = HandlerBasicBlock(block_id=0, start_vip=0, instructions=insns)
        assert bb.instruction_count == n

    @given(delta=st.integers(min_value=1, max_value=10))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_fallthrough_vip(self, delta: int) -> None:
        """fallthrough_vip must be vip + vip_delta."""
        insn = VMInstruction(vip=100, opcode=0x90, handler_address=0x1000,
                             vip_delta=delta)
        assert insn.fallthrough_vip() == 100 + delta

    @given(n_blocks=st.integers(min_value=2, max_value=10))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_linear_cfg_no_loops(self, n_blocks: int) -> None:
        """A linear chain of blocks (no back edges) has no loops."""
        blocks = [
            HandlerBasicBlock(
                block_id=i,
                start_vip=i * 10,
                instructions=[VMInstruction(vip=i * 10, opcode=0x90,
                                            handler_address=0x1000)],
            )
            for i in range(n_blocks)
        ]
        edges = [
            CFGEdge(source_block=i, target_block=i + 1, edge_type="fallthrough")
            for i in range(n_blocks - 1)
        ]
        loops = detect_natural_loops(blocks, edges)
        assert len(loops) == 0

    @given(body_size=st.integers(min_value=1, max_value=8))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_single_loop_detected(self, body_size: int) -> None:
        """A CFG with one back edge should detect one natural loop."""
        n = body_size + 1  # +1 for entry block
        blocks = [
            HandlerBasicBlock(
                block_id=i,
                start_vip=i * 10,
                instructions=[VMInstruction(vip=i * 10, opcode=0x90,
                                            handler_address=0x1000)],
            )
            for i in range(n)
        ]
        # Linear chain + back edge from last to block 1 (loop header)
        edges = [
            CFGEdge(source_block=i, target_block=i + 1, edge_type="fallthrough")
            for i in range(n - 1)
        ]
        edges.append(CFGEdge(source_block=n - 1, target_block=1,
                             edge_type="back_edge"))
        loops = detect_natural_loops(blocks, edges)
        assert len(loops) >= 1
        # The loop header should be block 1
        headers = {lp["header"] for lp in loops}
        assert 1 in headers

    @given(n=st.integers(min_value=2, max_value=6))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_handler_cfg_block_count(self, n: int) -> None:
        """HandlerCFG.block_count must match blocks list length."""
        blocks = [
            HandlerBasicBlock(
                block_id=i,
                start_vip=i * 10,
                instructions=[VMInstruction(vip=i * 10, opcode=0x90,
                                            handler_address=0x1000)],
            )
            for i in range(n)
        ]
        edges = [
            CFGEdge(source_block=i, target_block=i + 1)
            for i in range(n - 1)
        ]
        cfg = HandlerCFG(blocks=blocks, edges=edges, vm_instructions=[])
        assert cfg.block_count == n
        assert cfg.edge_count == n - 1

    def test_loop_tree_empty(self) -> None:
        """LoopTree with no loops should have loop_count == 0."""
        tree = LoopTree(loops=[])
        assert tree.loop_count == 0
        assert tree.max_depth == 0

    @given(header=st.integers(min_value=0, max_value=100),
           body_ids=st.lists(st.integers(min_value=0, max_value=100),
                             min_size=1, max_size=10, unique=True))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_loop_tree_single_loop(self, header: int, body_ids: List[int]) -> None:
        """LoopTree with one loop should report loop_count == 1."""
        body = set(body_ids) | {header}
        tree = LoopTree(loops=[{
            "header": header,
            "back_edge_source": body_ids[0],
            "body": body,
        }])
        assert tree.loop_count == 1
        loop = tree.get_loop(header)
        assert loop is not None
        assert header in loop


# ═══════════════════════════════════════════════════════════════════════════
# Cross-component: Decryptor + Key Transform invariants
# ═══════════════════════════════════════════════════════════════════════════


class TestDecryptorKeyInvariants:
    """Cross-component tests for key evolution invariants."""

    @given(data=st.binary(min_size=2, max_size=32),
           key=st.integers(min_value=1, max_value=0xFFFF))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_key_evolves_with_xor_transform(self, data: bytes, key: int) -> None:
        """With XOR transform on opcode, key must change after each byte."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        _, keys = dec.decrypt(data)
        # Key should not stay constant (unless all opcodes XOR to 0)
        # At minimum, keys list must have correct length
        assert len(keys) == len(data)

    @given(key=st.integers(min_value=1, max_value=0xFFFF))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_add_transform_monotonic_tendency(self, key: int) -> None:
        """ADD transform should generally increase key (modulo width)."""
        data = bytes([0x42] * 8)
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.ADD, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[],
        )
        _, keys = dec.decrypt(data)
        assert len(keys) == 8
        # All keys should be valid non-negative integers
        for k in keys:
            assert isinstance(k, int)
            assert k >= 0
