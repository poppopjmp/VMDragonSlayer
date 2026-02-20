"""Tests for handler semantic equivalence clustering."""
from __future__ import annotations

import pytest

from dragonslayer.analysis.handler_clustering import (
    NormalizedEffect,
    SemanticCluster,
    ClusteringResult,
    are_semantically_equivalent,
    cluster_handlers_by_semantics,
    extract_operand_binding,
    normalize_symbolic_effect,
    refine_opcode_table,
    _normalize_commutative,
    _detect_width_from_regs,
)


# ───────────────────────────────────────────────────────────────────────
# Helper factories
# ───────────────────────────────────────────────────────────────────────

def _make_summary(
    *,
    address: int = 0x401000,
    final_registers: dict | None = None,
    simplified_registers: dict | None = None,
    input_symbols: dict | None = None,
    memory_writes: list | None = None,
    error: str | None = None,
) -> dict:
    """Build a dict matching HandlerSymbolicSummary.to_dict() output."""
    return {
        "address": address,
        "instruction_count": 10,
        "final_registers": final_registers or {},
        "simplified_registers": simplified_registers or {},
        "memory_writes": memory_writes or [],
        "memory_write_count": len(memory_writes or []),
        "constraints": [],
        "constraint_count": 0,
        "input_symbols": input_symbols or {},
        "error": error,
    }


def _make_add_summary(
    reg_a: str = "rax",
    reg_b: str = "rbx",
    out_reg: str = "rax",
    address: int = 0x401000,
) -> dict:
    """Create a summary for a simple binary ADD handler."""
    return _make_summary(
        address=address,
        simplified_registers={
            out_reg: f"init_{reg_a} + init_{reg_b}",
        },
        final_registers={
            out_reg: f"init_{reg_a} + init_{reg_b}",
        },
        input_symbols={
            out_reg: f"init_{out_reg}",
            reg_a: f"init_{reg_a}",
            reg_b: f"init_{reg_b}",
        },
    )


def _make_semantic(
    handler_address: int = 0x401000,
    operation: str = "vm_unknown",
    confidence: float = 0.5,
    operand_width: int = 8,
) -> dict:
    """Build a dict matching HandlerSemantic fields."""
    return {
        "handler_address": handler_address,
        "operation": operation,
        "confidence": confidence,
        "operand_width": operand_width,
    }


# ═══════════════════════════════════════════════════════════════════════
# Test: NormalizedEffect dataclass
# ═══════════════════════════════════════════════════════════════════════

class TestNormalizedEffect:
    def test_signature_format(self):
        ne = NormalizedEffect(
            operation="vm_add",
            operand_width=8,
            canonical_expression="slot_0 + slot_1",
        )
        assert ne.signature() == "vm_add:8:slot_0 + slot_1"

    def test_default_unknown(self):
        ne = NormalizedEffect()
        assert ne.operation == "vm_unknown"
        assert ne.operand_width == 0

    def test_side_effects_frozen(self):
        ne = NormalizedEffect(side_effects=frozenset({"mem_write"}))
        assert "mem_write" in ne.side_effects


# ═══════════════════════════════════════════════════════════════════════
# Test: Width detection
# ═══════════════════════════════════════════════════════════════════════

class TestWidthDetection:
    def test_64bit_registers(self):
        assert _detect_width_from_regs(["rax", "rbx"]) == 8

    def test_32bit_registers(self):
        assert _detect_width_from_regs(["eax", "ecx"]) == 4

    def test_mixed_widths_majority(self):
        # More 64-bit regs → 8
        assert _detect_width_from_regs(["rax", "rbx", "ecx"]) == 8

    def test_empty(self):
        assert _detect_width_from_regs([]) == 0

    def test_16bit(self):
        assert _detect_width_from_regs(["ax", "bx"]) == 2


# ═══════════════════════════════════════════════════════════════════════
# Test: Commutative normalization
# ═══════════════════════════════════════════════════════════════════════

class TestCommutativeNormalization:
    def test_swap_slots(self):
        assert _normalize_commutative("slot_1 + slot_0") == "slot_0 + slot_1"

    def test_already_sorted(self):
        assert _normalize_commutative("slot_0 + slot_1") == "slot_0 + slot_1"

    def test_xor_function_form(self):
        result = _normalize_commutative("Xor(slot_1, slot_0)")
        assert result == "Xor(slot_0, slot_1)"

    def test_subtraction_not_swapped(self):
        # Subtraction is NOT commutative → should be unchanged
        assert _normalize_commutative("slot_1 - slot_0") == "slot_1 - slot_0"

    def test_multiple_parts(self):
        result = _normalize_commutative("slot_1 + slot_0 ; slot_2 * slot_0")
        parts = result.split(" ; ")
        assert parts[0] == "slot_0 + slot_1"
        assert parts[1] == "slot_0 * slot_2"


# ═══════════════════════════════════════════════════════════════════════
# Test: normalize_symbolic_effect
# ═══════════════════════════════════════════════════════════════════════

class TestNormalizeSymbolicEffect:
    def test_add_two_regs(self):
        summary = _make_add_summary("rax", "rbx", "rax")
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_add"
        assert ne.confidence >= 0.90
        assert "slot_0" in ne.canonical_expression
        assert "slot_1" in ne.canonical_expression
        assert ne.input_slots == 2

    def test_add_different_regs_same_effect(self):
        """Two ADD handlers with different register allocation should produce
        equivalent normalized effects."""
        s1 = _make_add_summary("rax", "rbx", "rax", address=0x1000)
        s2 = _make_add_summary("r12", "rsi", "r12", address=0x2000)
        ne1 = normalize_symbolic_effect(s1)
        ne2 = normalize_symbolic_effect(s2)
        assert ne1.operation == ne2.operation == "vm_add"
        # Both should have the same canonical expression
        assert ne1.canonical_expression == ne2.canonical_expression

    def test_sub_operation(self):
        summary = _make_summary(
            simplified_registers={"rax": "init_rax - init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_sub"

    def test_xor_operation(self):
        summary = _make_summary(
            simplified_registers={"rax": "init_rcx ^ init_rdx"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx", "rdx": "init_rdx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_xor"

    def test_not_unary(self):
        summary = _make_summary(
            simplified_registers={"rax": "~init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_not"
        assert ne.input_slots == 1

    def test_neg_unary(self):
        summary = _make_summary(
            simplified_registers={"rax": "-init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_neg"

    def test_shl_shift(self):
        summary = _make_summary(
            simplified_registers={"rax": "init_rax << init_rcx"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_shl"

    def test_width_from_32bit_regs(self):
        summary = _make_summary(
            simplified_registers={"eax": "init_eax + init_ecx"},
            input_symbols={"eax": "init_eax", "ecx": "init_ecx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operand_width == 4

    def test_width_from_64bit_regs(self):
        summary = _make_add_summary("rax", "rbx", "rax")
        ne = normalize_symbolic_effect(summary)
        assert ne.operand_width == 8

    def test_error_summary_returns_default(self):
        summary = _make_summary(error="symbolic execution failed")
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_unknown"

    def test_empty_registers_returns_default(self):
        summary = _make_summary()
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_unknown"

    def test_memory_write_store(self):
        summary = _make_summary(
            memory_writes=[{"address": "init_rdi", "value": "init_rax"}],
            simplified_registers={},
            input_symbols={"rdi": "init_rdi", "rax": "init_rax"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_store"
        assert "mem_write" in ne.side_effects

    def test_stack_push(self):
        summary = _make_summary(
            memory_writes=[{"address": "init_rsp - 8", "value": "init_rax"}],
            simplified_registers={},
            input_symbols={"rsp": "init_rsp", "rax": "init_rax"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_push"
        assert "stack_write" in ne.side_effects

    def test_slot_map_populated(self):
        summary = _make_add_summary("rax", "rbx", "rax")
        ne = normalize_symbolic_effect(summary)
        assert len(ne.slot_map) == 2
        assert ne.slot_map[0] in ("rax", "rbx")
        assert ne.slot_map[1] in ("rax", "rbx")

    def test_commutative_add_normalized(self):
        """ADD is commutative — slot order should be canonical."""
        s1 = _make_summary(
            simplified_registers={"rax": "init_rbx + init_rax"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        s2 = _make_summary(
            simplified_registers={"rcx": "init_rdi + init_rsi"},
            input_symbols={"rcx": "init_rcx", "rdi": "init_rdi", "rsi": "init_rsi"},
        )
        ne1 = normalize_symbolic_effect(s1)
        ne2 = normalize_symbolic_effect(s2)
        # After commutative normalization, both should have same expression
        assert ne1.canonical_expression == ne2.canonical_expression

    def test_accepts_dataclass_summary(self):
        """Should accept objects with to_dict() method."""
        class FakeSummary:
            def to_dict(self):
                return _make_add_summary("rax", "rbx", "rax")
        ne = normalize_symbolic_effect(FakeSummary())
        assert ne.operation == "vm_add"

    def test_none_summary_returns_default(self):
        ne = normalize_symbolic_effect(None)
        assert ne.operation == "vm_unknown"

    def test_prefers_simplified_over_final(self):
        """simplified_registers should be used over final_registers."""
        summary = _make_summary(
            simplified_registers={"rax": "init_rax + init_rbx"},
            final_registers={"rax": "complicated_mba_expr"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        ne = normalize_symbolic_effect(summary)
        assert ne.operation == "vm_add"


# ═══════════════════════════════════════════════════════════════════════
# Test: are_semantically_equivalent
# ═══════════════════════════════════════════════════════════════════════

class TestEquivalence:
    def test_identical(self):
        ne = NormalizedEffect(
            operation="vm_add", operand_width=8,
            canonical_expression="slot_0 + slot_1",
            input_slots=2, confidence=0.95,
        )
        eq, conf = are_semantically_equivalent(ne, ne)
        assert eq is True
        assert conf >= 0.90

    def test_same_op_different_width(self):
        ne1 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        ne2 = NormalizedEffect(operation="vm_add", operand_width=4,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        eq, _ = are_semantically_equivalent(ne1, ne2)
        assert eq is False

    def test_same_op_ignore_width(self):
        ne1 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        ne2 = NormalizedEffect(operation="vm_add", operand_width=4,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        eq, _ = are_semantically_equivalent(ne1, ne2, strict_width=False)
        assert eq is True

    def test_different_ops(self):
        ne1 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        ne2 = NormalizedEffect(operation="vm_sub", operand_width=8,
                               canonical_expression="slot_0 - slot_1",
                               input_slots=2, confidence=0.95)
        eq, _ = are_semantically_equivalent(ne1, ne2)
        assert eq is False

    def test_unknown_never_matches(self):
        ne1 = NormalizedEffect(operation="vm_unknown", confidence=0.5)
        ne2 = NormalizedEffect(operation="vm_unknown", confidence=0.5)
        eq, _ = are_semantically_equivalent(ne1, ne2)
        assert eq is False

    def test_structural_match(self):
        """Different slot numbering but same algebraic structure."""
        ne1 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        ne2 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_3 + slot_7",
                               input_slots=2, confidence=0.95)
        eq, conf = are_semantically_equivalent(ne1, ne2)
        assert eq is True
        assert conf > 0.0

    def test_different_input_count(self):
        ne1 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=2, confidence=0.95)
        ne2 = NormalizedEffect(operation="vm_add", operand_width=8,
                               canonical_expression="slot_0 + slot_1",
                               input_slots=3, confidence=0.95)
        eq, _ = are_semantically_equivalent(ne1, ne2)
        assert eq is False


# ═══════════════════════════════════════════════════════════════════════
# Test: extract_operand_binding
# ═══════════════════════════════════════════════════════════════════════

class TestOperandBinding:
    def test_binding_from_add(self):
        summary = _make_add_summary("rax", "rbx", "rax")
        ne = normalize_symbolic_effect(summary)
        binding = extract_operand_binding(summary, ne)
        # Should map slot indices to register names
        assert len(binding) == 2
        assert set(binding.values()) == {"rax", "rbx"}


# ═══════════════════════════════════════════════════════════════════════
# Test: cluster_handlers_by_semantics
# ═══════════════════════════════════════════════════════════════════════

class TestClustering:
    def test_two_add_handlers_cluster_together(self):
        """Two ADD handlers with different register allocation cluster."""
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
            0x2000: _make_add_summary("r12", "rsi", "r12", 0x2000),
        }
        semantics = [
            _make_semantic(0x1000, "vm_add", 0.9, 8),
            _make_semantic(0x2000, "vm_add", 0.9, 8),
        ]
        result = cluster_handlers_by_semantics(semantics, summaries)
        assert len(result.clusters) >= 1
        # Find the ADD cluster
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        assert len(add_clusters) >= 1
        # Both should be in the same cluster
        members = add_clusters[0].members
        assert 0x1000 in members
        assert 0x2000 in members

    def test_add_and_sub_separate_clusters(self):
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
            0x2000: _make_summary(
                address=0x2000,
                simplified_registers={"rax": "init_rax - init_rbx"},
                input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
            ),
        }
        semantics = [
            _make_semantic(0x1000, "vm_add", 0.9, 8),
            _make_semantic(0x2000, "vm_sub", 0.9, 8),
        ]
        result = cluster_handlers_by_semantics(semantics, summaries)
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        sub_clusters = [c for c in result.clusters if c.operation == "vm_sub"]
        assert len(add_clusters) == 1
        assert len(sub_clusters) == 1
        assert 0x1000 in add_clusters[0].members
        assert 0x2000 in sub_clusters[0].members

    def test_width_separates_clusters(self):
        """vm_add_32 and vm_add_64 should be in separate clusters."""
        summaries = {
            0x1000: _make_summary(
                address=0x1000,
                simplified_registers={"rax": "init_rax + init_rbx"},
                input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
            ),
            0x2000: _make_summary(
                address=0x2000,
                simplified_registers={"eax": "init_eax + init_ecx"},
                input_symbols={"eax": "init_eax", "ecx": "init_ecx"},
            ),
        }
        semantics = [
            _make_semantic(0x1000, "vm_add", 0.9, 8),
            _make_semantic(0x2000, "vm_add", 0.9, 4),
        ]
        result = cluster_handlers_by_semantics(semantics, summaries)
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        assert len(add_clusters) == 2  # 64-bit and 32-bit separate

    def test_fallback_sans_symbolic(self):
        """Handlers without symbolic summaries use heuristic grouping."""
        semantics = [
            _make_semantic(0x1000, "vm_xor", 0.7, 8),
            _make_semantic(0x2000, "vm_xor", 0.6, 8),
        ]
        result = cluster_handlers_by_semantics(semantics, {})
        xor_clusters = [c for c in result.clusters if c.operation == "vm_xor"]
        assert len(xor_clusters) == 1
        assert len(xor_clusters[0].members) == 2

    def test_unclustered_unknown(self):
        """Handlers with vm_unknown and no symbolic summary are unclustered."""
        semantics = [
            _make_semantic(0x1000, "vm_unknown", 0.3, 0),
        ]
        result = cluster_handlers_by_semantics(semantics, {})
        assert 0x1000 in result.unclustered
        assert len(result.clusters) == 0

    def test_mixed_symbolic_and_heuristic(self):
        """Some handlers symbolic, some heuristic-only."""
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
        }
        semantics = [
            _make_semantic(0x1000, "vm_add", 0.9, 8),
            _make_semantic(0x2000, "vm_add", 0.7, 8),
            _make_semantic(0x3000, "vm_sub", 0.8, 8),
        ]
        result = cluster_handlers_by_semantics(semantics, summaries)
        # 0x1000 from symbolic, 0x2000 from heuristic fallback
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        assert len(add_clusters) >= 1
        all_add_members = set()
        for c in add_clusters:
            all_add_members.update(c.members)
        assert 0x1000 in all_add_members
        assert 0x2000 in all_add_members

    def test_operation_counts(self):
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
            0x2000: _make_add_summary("rcx", "rdx", "rcx", 0x2000),
            0x3000: _make_summary(
                address=0x3000,
                simplified_registers={"rax": "init_rax ^ init_rbx"},
                input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
            ),
        }
        semantics = [
            _make_semantic(0x1000, "vm_add", 0.9, 8),
            _make_semantic(0x2000, "vm_add", 0.9, 8),
            _make_semantic(0x3000, "vm_xor", 0.9, 8),
        ]
        result = cluster_handlers_by_semantics(semantics, summaries)
        assert result.operation_counts.get("vm_add", 0) >= 2
        assert result.operation_counts.get("vm_xor", 0) >= 1

    def test_cluster_has_operand_bindings(self):
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
        }
        semantics = [_make_semantic(0x1000, "vm_add", 0.9, 8)]
        result = cluster_handlers_by_semantics(semantics, summaries)
        add_c = [c for c in result.clusters if c.operation == "vm_add"][0]
        assert 0x1000 in add_c.operand_bindings
        assert len(add_c.operand_bindings[0x1000]) == 2

    def test_empty_input(self):
        result = cluster_handlers_by_semantics([], {})
        assert len(result.clusters) == 0
        assert len(result.unclustered) == 0

    def test_many_handlers_cluster(self):
        """Regression: 10 ADD variants with different register pairs."""
        reg_pairs = [
            ("rax", "rbx"), ("rcx", "rdx"), ("rsi", "rdi"),
            ("r8", "r9"), ("r10", "r11"), ("r12", "r13"),
            ("r14", "r15"), ("rax", "rcx"), ("rbx", "rdx"),
            ("rsi", "r8"),
        ]
        summaries = {}
        semantics = []
        for i, (a, b) in enumerate(reg_pairs):
            addr = 0x1000 + i * 0x100
            summaries[addr] = _make_add_summary(a, b, a, addr)
            semantics.append(_make_semantic(addr, "vm_add", 0.9, 8))

        result = cluster_handlers_by_semantics(semantics, summaries)
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        total_members = sum(len(c.members) for c in add_clusters)
        assert total_members == 10


# ═══════════════════════════════════════════════════════════════════════
# Test: ClusteringResult
# ═══════════════════════════════════════════════════════════════════════

class TestClusteringResult:
    def test_find_cluster(self):
        c = SemanticCluster(
            cluster_id=0, operation="vm_add", operand_width=8,
            members=[0x1000, 0x2000],
        )
        result = ClusteringResult(clusters=[c])
        assert result.find_cluster(0x1000) is c
        assert result.find_cluster(0x9999) is None

    def test_to_dict(self):
        c = SemanticCluster(
            cluster_id=0, operation="vm_add", operand_width=8,
            members=[0x1000], confidence=0.95,
        )
        result = ClusteringResult(
            clusters=[c],
            unclustered=[0x5000],
            operation_counts={"vm_add": 1},
        )
        d = result.to_dict()
        assert d["cluster_count"] == 1
        assert d["unclustered_count"] == 1

    def test_cluster_to_dict(self):
        ne = NormalizedEffect(
            operation="vm_add", canonical_expression="slot_0 + slot_1",
        )
        c = SemanticCluster(
            cluster_id=0, operation="vm_add", operand_width=8,
            members=[0x1000, 0x2000], normalized_effect=ne, confidence=0.95,
        )
        d = c.to_dict()
        assert d["member_count"] == 2
        assert d["canonical_expression"] == "slot_0 + slot_1"


# ═══════════════════════════════════════════════════════════════════════
# Test: refine_opcode_table
# ═══════════════════════════════════════════════════════════════════════

class TestRefineOpcodeTable:
    def test_updates_operation(self):
        """Opcode table entries updated to cluster's canonical operation."""
        class FakeSemantic:
            def __init__(self):
                self.operation = "vm_unknown"
                self.confidence = 0.3
                self.detail = ""

        class FakeEntry:
            def __init__(self, addr):
                self.handler_address = addr
                self.semantic = FakeSemantic()

        class FakeTable:
            def __init__(self):
                self.entries = [FakeEntry(0x1000), FakeEntry(0x2000)]
                self.unique_operations = 1

        table = FakeTable()
        clustering = ClusteringResult(
            clusters=[
                SemanticCluster(
                    cluster_id=0, operation="vm_add", operand_width=8,
                    members=[0x1000, 0x2000], confidence=0.95,
                ),
            ],
        )
        refine_opcode_table(table, clustering)
        assert table.entries[0].semantic.operation == "vm_add"
        assert table.entries[1].semantic.operation == "vm_add"
        assert "cluster=0" in table.entries[0].semantic.detail

    def test_unmatched_entries_unchanged(self):
        class FakeSemantic:
            def __init__(self):
                self.operation = "vm_sub"
                self.confidence = 0.8
                self.detail = "original"

        class FakeEntry:
            def __init__(self, addr):
                self.handler_address = addr
                self.semantic = FakeSemantic()

        class FakeTable:
            def __init__(self):
                self.entries = [FakeEntry(0x9999)]
                self.unique_operations = 1

        table = FakeTable()
        clustering = ClusteringResult(
            clusters=[
                SemanticCluster(
                    cluster_id=0, operation="vm_add",
                    operand_width=8, members=[0x1000],
                ),
            ],
        )
        refine_opcode_table(table, clustering)
        assert table.entries[0].semantic.operation == "vm_sub"
        assert table.entries[0].semantic.detail == "original"


# ═══════════════════════════════════════════════════════════════════════
# Test: Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_single_handler(self):
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
        }
        semantics = [_make_semantic(0x1000, "vm_add", 0.9, 8)]
        result = cluster_handlers_by_semantics(semantics, summaries)
        assert len(result.clusters) == 1
        assert len(result.clusters[0].members) == 1

    def test_all_unknown(self):
        semantics = [
            _make_semantic(0x1000, "vm_unknown", 0.2, 0),
            _make_semantic(0x2000, "vm_unknown", 0.2, 0),
        ]
        result = cluster_handlers_by_semantics(semantics, {})
        assert len(result.unclustered) == 2

    def test_symbolic_override_heuristic(self):
        """When symbolic summary says ADD but heuristic says XOR, symbolic wins."""
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
        }
        semantics = [_make_semantic(0x1000, "vm_xor", 0.5, 8)]
        result = cluster_handlers_by_semantics(semantics, summaries)
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        assert len(add_clusters) == 1
        assert 0x1000 in add_clusters[0].members

    def test_no_semantics(self):
        """Symbolic summaries alone should work without semantics list."""
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
        }
        result = cluster_handlers_by_semantics([], summaries)
        assert len(result.clusters) == 1

    def test_duplicate_addresses(self):
        """Same address in semantics list should not cause double-counting."""
        summaries = {
            0x1000: _make_add_summary("rax", "rbx", "rax", 0x1000),
        }
        semantics = [
            _make_semantic(0x1000, "vm_add", 0.9, 8),
            _make_semantic(0x1000, "vm_add", 0.9, 8),
        ]
        result = cluster_handlers_by_semantics(semantics, summaries)
        add_clusters = [c for c in result.clusters if c.operation == "vm_add"]
        assert len(add_clusters) >= 1
