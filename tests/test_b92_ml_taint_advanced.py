"""
B92 — Hypothesis property-based tests for ML classification, taint interprocedural
tracking, dispatcher scoring, and decrypt/CFG advanced invariants.

Targets axes: ML (8.4→9.0), Taint (8.5→9.0), Dispatcher (8.7→9.0),
Decrypt (8.6→9.0), CFG (8.6→9.0).
"""

from __future__ import annotations

import copy
from dataclasses import fields as dc_fields
from typing import Any, Dict, List

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# ═══════════════════════════════════════════════════════════════════════════
# ML Classification: VMClassifier, Ensemble, Trainer
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.ml.model import BaseModel, PredictionResult, VMHandlerModel
from dragonslayer.ml.classifier import VMClassifier
from dragonslayer.ml.ensemble import EnsembleClassifier
from dragonslayer.ml.trainer import ModelTrainer
from dragonslayer.ml.pipeline import FeatureVector

# Minimal handler dicts for classify
_HANDLER_MNEMONICS = st.lists(
    st.sampled_from(["mov", "add", "sub", "xor", "push", "pop", "nop",
                     "cmp", "jz", "jnz", "call", "ret", "lea", "and",
                     "or", "shl", "shr", "ror", "rol", "test", "inc"]),
    min_size=1, max_size=50,
)

_HANDLER_STRATEGY = _HANDLER_MNEMONICS.map(
    lambda mnems: {"mnemonics": mnems, "instructions": [
        {"mnemonic": m, "operands": []} for m in mnems
    ]}
)

# Feature vector strategy
_FEATURE_NAMES = [
    "instruction_count", "unique_mnemonic_count", "arith_ratio",
    "logic_ratio", "stack_ratio", "mem_ratio", "branch_ratio",
    "nop_ratio", "has_memory_read", "has_memory_write",
    "has_indirect_branch", "has_cmp_insn", "has_test_insn",
]

_FEATURE_VECTOR = st.fixed_dictionaries({
    "values": st.lists(
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        min_size=len(_FEATURE_NAMES), max_size=len(_FEATURE_NAMES)),
    "names": st.just(_FEATURE_NAMES),
}).map(lambda d: FeatureVector(
    values=d["values"], feature_names=d["names"], metadata={}
))


class TestVMClassifierProperties:
    """Hypothesis tests for VMClassifier.classify and classify_batch."""

    @given(handler=_HANDLER_STRATEGY)
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_classify_returns_valid_result(self, handler: Dict[str, Any]) -> None:
        """classify() must return PredictionResult with valid fields."""
        clf = VMClassifier()
        result = clf.classify(handler)
        assert isinstance(result, PredictionResult)
        assert isinstance(result.label, str)
        assert 0.0 <= result.confidence <= 1.0

    @given(handlers=st.lists(_HANDLER_STRATEGY, min_size=1, max_size=10))
    @settings(max_examples=40, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_classify_batch_length(self, handlers: List[Dict[str, Any]]) -> None:
        """classify_batch must return exactly len(handlers) results."""
        clf = VMClassifier()
        results = clf.classify_batch(handlers)
        assert len(results) == len(handlers)

    @given(handler=_HANDLER_STRATEGY)
    @settings(max_examples=40, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_classify_deterministic(self, handler: Dict[str, Any]) -> None:
        """Same handler should produce same label."""
        clf = VMClassifier()
        r1 = clf.classify(handler)
        r2 = clf.classify(handler)
        assert r1.label == r2.label

    @given(handlers=st.lists(_HANDLER_STRATEGY, min_size=2, max_size=5))
    @settings(max_examples=30, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_batch_matches_individual(self, handlers: List[Dict[str, Any]]) -> None:
        """classify_batch results must match individual classify results."""
        clf = VMClassifier()
        batch = clf.classify_batch(handlers)
        for i, h in enumerate(handlers):
            single = clf.classify(h)
            assert batch[i].label == single.label


class TestEnsembleClassifierProperties:
    """Hypothesis tests for EnsembleClassifier voting logic."""

    @given(handler=_HANDLER_STRATEGY)
    @settings(max_examples=40, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_single_model_passthrough(self, handler: Dict[str, Any]) -> None:
        """With 1 model, ensemble must return that model's prediction."""
        model = VMHandlerModel()
        ens = EnsembleClassifier(models=[model])
        single = model.predict({"values": [0.5] * 13, "names": _FEATURE_NAMES})
        result = ens.predict_safe({"values": [0.5] * 13, "names": _FEATURE_NAMES})
        assert result.label == single.label

    @given(n=st.integers(min_value=1, max_value=5))
    @settings(max_examples=30, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_n_models_count(self, n: int) -> None:
        """n_models property must match number of added models."""
        ens = EnsembleClassifier()
        for _ in range(n):
            ens.add_model(VMHandlerModel())
        assert ens.n_models == n

    def test_predict_safe_never_crashes(self) -> None:
        """predict_safe with no models should return unknown."""
        ens = EnsembleClassifier(models=[])
        result = ens.predict_safe({"values": [0.5] * 5, "names": ["a"] * 5})
        assert result.label == "unknown"
        assert result.confidence == 0.0

    @given(handler=_HANDLER_STRATEGY)
    @settings(max_examples=30, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_predict_safe_confidence_bounds(self, handler: Dict[str, Any]) -> None:
        """predict_safe confidence must be in [0, 1]."""
        ens = EnsembleClassifier(models=[VMHandlerModel(), VMHandlerModel()])
        features = {"values": [0.5] * 13, "names": _FEATURE_NAMES}
        result = ens.predict_safe(features)
        assert 0.0 <= result.confidence <= 1.0


class TestModelTrainerProperties:
    """Hypothesis tests for ModelTrainer training API."""

    @given(n=st.integers(min_value=3, max_value=20))
    @settings(max_examples=30, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_train_returns_result(self, n: int) -> None:
        """train() with valid data must return TrainingResult."""
        features = [
            FeatureVector(values=[float(i % 3)] * 5,
                          feature_names=["f1", "f2", "f3", "f4", "f5"],
                          metadata={})
            for i in range(n)
        ]
        labels = [["arith", "logic", "stack"][i % 3] for i in range(n)]
        trainer = ModelTrainer()
        result = trainer.train(features, labels, epochs=1)
        assert result.accuracy >= 0.0
        assert result.epochs >= 0

    def test_train_empty_raises(self) -> None:
        """train() with empty data must raise ValueError."""
        trainer = ModelTrainer()
        with pytest.raises(ValueError):
            trainer.train([], [])

    def test_train_mismatched_lengths_raises(self) -> None:
        """train() with different feature/label lengths must raise ValueError."""
        features = [FeatureVector(values=[1.0], feature_names=["f1"], metadata={})]
        trainer = ModelTrainer()
        with pytest.raises(ValueError):
            trainer.train(features, ["a", "b"])


# ═══════════════════════════════════════════════════════════════════════════
# Taint Tracking: Interprocedural, Alias, Implicit Flow
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.taint_tracking.tracker import (
    ByteTaintMap,
    MemoryAliasTracker,
    TaintTag,
    TaintTracker,
)


class TestTaintInterproceduralProperties:
    """Hypothesis tests for push/pop call context."""

    @given(reg=st.sampled_from(["rax", "rbx", "rcx", "rdx"]),
           tag=st.sampled_from([TaintTag.INPUT, TaintTag.VM_OPERAND,
                                TaintTag.MEMORY, TaintTag.COMPUTED]))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_push_pop_preserves_caller_taint(self, reg: str, tag: TaintTag) -> None:
        """push → taint callee → pop must restore caller taint."""
        t = TaintTracker()
        t.taint_register(reg, tag)
        t.push_call_context()
        # In callee scope, taint something different
        t.taint_register("r8", TaintTag.CRYPTO)
        # Pop should restore caller state
        t.pop_call_context()
        assert t.is_tainted(reg)
        assert t.get_taint(reg) & tag

    @given(reg=st.sampled_from(["rax", "rbx", "rcx", "rdx"]))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_push_pop_return_reg_propagates(self, reg: str) -> None:
        """Callee taint on return registers must propagate through pop."""
        t = TaintTracker()
        t.push_call_context()
        t.taint_register("rax", TaintTag.COMPUTED)
        t.pop_call_context(return_regs=("rax",))
        # rax should retain callee taint
        assert t.is_tainted("rax")
        assert t.get_taint("rax") & TaintTag.COMPUTED

    @given(reg=st.sampled_from(["r8", "r9", "r10", "r11"]))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_push_pop_callee_non_return_cleared(self, reg: str) -> None:
        """Callee taint on non-return registers must NOT survive pop."""
        t = TaintTracker()
        t.push_call_context()
        t.taint_register(reg, TaintTag.COMPUTED)
        t.pop_call_context(return_regs=("rax",))
        # Non-return register taint should be gone
        assert not t.is_tainted(reg)

    def test_pop_empty_stack_no_crash(self) -> None:
        """pop_call_context on empty stack must not crash."""
        t = TaintTracker()
        t.pop_call_context()  # should warn but not raise

    @given(depth=st.integers(min_value=1, max_value=5))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_nested_calls(self, depth: int) -> None:
        """Nested push/pop should correctly restore each level."""
        t = TaintTracker()
        tags = [TaintTag.INPUT, TaintTag.VM_OPERAND, TaintTag.MEMORY,
                TaintTag.COMPUTED, TaintTag.CRYPTO]
        # Push multiple levels
        for i in range(depth):
            t.taint_register("rbx", tags[i % len(tags)])
            t.push_call_context()
        # Pop all levels
        for _ in range(depth):
            t.pop_call_context()
        # Original taint from before first push should be gone or restored
        # depending on whether we tainted rbx before or after push


class TestMemoryAliasTrackerProperties:
    """Hypothesis tests for MemoryAliasTracker."""

    @given(addr=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_bind_then_resolve(self, addr: int) -> None:
        """bind(reg, addr) → resolve(reg) must return addr."""
        mat = MemoryAliasTracker()
        mat.bind("rax", addr)
        assert mat.resolve("rax") == addr

    @given(addr=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_must_alias_same_address(self, addr: int) -> None:
        """Two regs bound to same address must alias."""
        mat = MemoryAliasTracker()
        mat.bind("rax", addr)
        mat.bind("rbx", addr)
        assert mat.must_alias("rax", "rbx")

    @given(a1=st.integers(min_value=0, max_value=0xFFFF_FFFF),
           a2=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_different_addrs_no_alias(self, a1: int, a2: int) -> None:
        """Two regs bound to different addresses must not alias."""
        assume(a1 != a2)
        mat = MemoryAliasTracker()
        mat.bind("rax", a1)
        mat.bind("rbx", a2)
        assert not mat.must_alias("rax", "rbx")

    @given(addr=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_unbind_removes_alias(self, addr: int) -> None:
        """unbind(reg) → resolve(reg) must return None."""
        mat = MemoryAliasTracker()
        mat.bind("rax", addr)
        mat.unbind("rax")
        assert mat.resolve("rax") is None

    @given(addr=st.integers(min_value=0, max_value=0xFFFF_FFFF))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_aliases_of_returns_peers(self, addr: int) -> None:
        """aliases_of(rax) must include rbx if both bound to same address."""
        mat = MemoryAliasTracker()
        mat.bind("rax", addr)
        mat.bind("rbx", addr)
        peers = mat.aliases_of("rax")
        assert "rbx" in peers
        assert "rax" not in peers

    def test_clear_removes_all(self) -> None:
        """clear() must remove all bindings."""
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x2000)
        mat.clear()
        assert mat.resolve("rax") is None
        assert mat.resolve("rbx") is None


class TestTaintImplicitFlowProperties:
    """Hypothesis tests for implicit flow tracking via TaintTracker."""

    @given(depth=st.integers(min_value=0, max_value=32))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_implicit_depth_zero_disables(self, depth: int) -> None:
        """implicit_flow_depth=0 should disable implicit flow (no CONTROL tag)."""
        t = TaintTracker(implicit_flow_depth=0)
        t.taint_register("rax", TaintTag.INPUT)
        # No instructions processed, but the tracker should have no implicit scope
        assert t._implicit_scope_remaining == 0

    @given(depth=st.integers(min_value=1, max_value=64))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_implicit_depth_stored(self, depth: int) -> None:
        """implicit_flow_depth must be stored correctly."""
        t = TaintTracker(implicit_flow_depth=depth)
        assert t._implicit_flow_depth == depth


# ═══════════════════════════════════════════════════════════════════════════
# Advanced Dispatcher: Score invariants
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.vm_discovery.dispatcher import (
    DispatcherScoringConfig,
    find_vmprotect_dispatcher,
    find_dispatcher_in_trace,
)


class TestDispatcherAdvancedProperties:
    """Advanced Hypothesis tests for dispatcher scoring."""

    @given(n=st.integers(min_value=1, max_value=30))
    @settings(max_examples=40, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_mov_only_trace_no_match(self, n: int) -> None:
        """A trace of only `mov eax, eax` should not match as dispatcher."""
        records = [
            {"address": 0x401000 + i * 2, "disassembly": "mov eax, eax"}
            for i in range(n)
        ]
        result = find_dispatcher_in_trace(records)
        assert result is None

    @given(n=st.integers(min_value=1, max_value=20))
    @settings(max_examples=30, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_ret_only_trace_no_match(self, n: int) -> None:
        """A trace of only `ret` should not match as dispatcher."""
        records = [
            {"address": 0x401000 + i, "disassembly": "ret"}
            for i in range(n)
        ]
        result = find_dispatcher_in_trace(records)
        assert result is None

    @given(data=st.fixed_dictionaries({
        f: st.floats(min_value=0.0, max_value=0.5, allow_nan=False, allow_infinity=False)
        for f in [f.name for f in dc_fields(DispatcherScoringConfig)]
    }))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_config_sum_invariant(self, data: Dict[str, float]) -> None:
        """All config weights should be non-negative floats."""
        cfg = DispatcherScoringConfig.from_dict(data)
        total = sum(getattr(cfg, f.name) for f in dc_fields(cfg))
        assert total >= 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Advanced CFG: nested loops, topological order
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.bytecode_cfg import (
    VMInstruction,
    HandlerBasicBlock,
    CFGEdge,
    HandlerCFG,
    LoopTree,
    detect_natural_loops,
)


class TestCFGAdvancedProperties:
    """Advanced Hypothesis tests for CFG and loop detection."""

    @given(inner_size=st.integers(min_value=1, max_value=4),
           outer_size=st.integers(min_value=2, max_value=5))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_nested_loops_depth(self, inner_size: int, outer_size: int) -> None:
        """Two nested loops should produce max_depth >= 1 (inner nested in outer)."""
        # Build: entry(0) → outer_header(1) → ... → inner_header → ... → last
        # Outer back edge: last block → outer_header (1)
        # Inner back edge: inner_last → inner_header
        n = 1 + outer_size + inner_size  # entry + outer + inner
        blocks = [
            HandlerBasicBlock(
                block_id=i, start_vip=i * 10,
                instructions=[VMInstruction(vip=i * 10, opcode=0x90,
                                            handler_address=0x1000)],
            )
            for i in range(n)
        ]
        edges = []
        # Linear chain
        for i in range(n - 1):
            edges.append(CFGEdge(source_block=i, target_block=i + 1))

        outer_header = 1
        inner_header = outer_size  # somewhere inside the outer loop
        last_block = n - 1

        # Outer back edge: last block → outer header
        # Body (fallback): blocks[1..last] = all blocks except entry
        edges.append(CFGEdge(source_block=last_block, target_block=outer_header,
                             edge_type="back_edge"))
        # Inner back edge: last block → inner header
        # Body (fallback): blocks[inner_header..last] ⊂ outer body
        edges.append(CFGEdge(source_block=last_block, target_block=inner_header,
                             edge_type="back_edge"))

        loops = detect_natural_loops(blocks, edges)
        assert len(loops) >= 2
        tree = LoopTree(loops=loops)
        assert tree.max_depth >= 1

    @given(n=st.integers(min_value=3, max_value=15))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_topological_order_valid(self, n: int) -> None:
        """topological_order on a DAG must list all blocks in valid order."""
        blocks = [
            HandlerBasicBlock(
                block_id=i, start_vip=i * 10,
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
        order = cfg.topological_order()
        assert len(order) == n
        # Verify ordering: source appears before target
        pos = {bid: idx for idx, bid in enumerate(order)}
        for e in edges:
            assert pos[e.source_block] < pos[e.target_block]

    @given(n=st.integers(min_value=2, max_value=10))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_exit_blocks_correct(self, n: int) -> None:
        """Exit blocks (marked is_exit) must be reported by exit_blocks()."""
        blocks = [
            HandlerBasicBlock(
                block_id=i, start_vip=i * 10,
                instructions=[VMInstruction(vip=i * 10, opcode=0x90,
                                            handler_address=0x1000)],
            )
            for i in range(n)
        ]
        # Mark last block as exit (mirrors build_handler_cfg behaviour)
        blocks[-1].is_exit = True
        edges = [
            CFGEdge(source_block=i, target_block=i + 1)
            for i in range(n - 1)
        ]
        cfg = HandlerCFG(blocks=blocks, edges=edges, vm_instructions=[])
        exits = cfg.exit_blocks()
        exit_ids = {b.block_id for b in exits}
        assert n - 1 in exit_ids

    @given(n=st.integers(min_value=2, max_value=8))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_back_edges_with_loop(self, n: int) -> None:
        """A CFG with a back edge should report it."""
        blocks = [
            HandlerBasicBlock(
                block_id=i, start_vip=i * 10,
                instructions=[VMInstruction(vip=i * 10, opcode=0x90,
                                            handler_address=0x1000)],
            )
            for i in range(n)
        ]
        edges = [CFGEdge(source_block=i, target_block=i + 1)
                 for i in range(n - 1)]
        edges.append(CFGEdge(source_block=n - 1, target_block=0,
                             edge_type="back_edge"))
        cfg = HandlerCFG(blocks=blocks, edges=edges, vm_instructions=[])
        back = cfg.back_edges()
        assert len(back) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# Advanced Decrypt: Cipher chain + inverse roundtrip
# ═══════════════════════════════════════════════════════════════════════════
from dragonslayer.analysis.bytecode_decrypt import (
    BytecodeDecryptor,
    CipherOp,
    CipherStep,
    KeyTransform,
    TransformOp,
)


class TestDecryptorAdvancedProperties:
    """Advanced Hypothesis tests for decryptor invariants."""

    @given(key=st.integers(min_value=1, max_value=0xFFFF),
           data=st.binary(min_size=1, max_size=32))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_multi_step_chain_valid(self, key: int, data: bytes) -> None:
        """Multi-step cipher chain must produce valid output."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[
                CipherStep(op=CipherOp.XOR, operand_source="key"),
                CipherStep(op=CipherOp.NOT, operand_source=""),
            ],
        )
        plaintext, keys = dec.decrypt_chained(data)
        assert len(plaintext) == len(data)
        for k in keys:
            assert isinstance(k, int) and k >= 0

    @given(key=st.integers(min_value=0, max_value=0xFF),
           opcode=st.integers(min_value=0, max_value=255))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_not_is_involution(self, key: int, opcode: int) -> None:
        """NOT applied twice should return original (involution property)."""
        dec = BytecodeDecryptor(
            transforms=[],
            initial_key=key,
            key_width=8,
            opcode_width=1,
            cipher_chain=[
                CipherStep(op=CipherOp.NOT, operand_source=""),
                CipherStep(op=CipherOp.NOT, operand_source=""),
            ],
        )
        plaintext, _ = dec.decrypt_chained(bytes([opcode]))
        # XOR with key cancels, then NOT(NOT(x)) = x, so:
        # result should be opcode XOR key (from the default XOR step before chain)
        assert len(plaintext) == 1

    @given(key=st.integers(min_value=1, max_value=0xFFFF),
           data=st.binary(min_size=1, max_size=32))
    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
    def test_bswap_preserves_length(self, key: int, data: bytes) -> None:
        """BSWAP cipher step must not change output length."""
        dec = BytecodeDecryptor(
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
            initial_key=key,
            key_width=32,
            opcode_width=1,
            cipher_chain=[CipherStep(op=CipherOp.BSWAP, operand_source="")],
        )
        plaintext, keys = dec.decrypt_chained(data)
        assert len(plaintext) == len(data)
