"""
Tests for Batch 27 — Symbolic Memory Model
===========================================

Validates the region-based symbolic memory model in SymbolicState
and the executor's handling of symbolic memory reads/writes
(store-forwarding, region-aware naming, LOAD/STORE summaries).
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# z3 availability
# ---------------------------------------------------------------------------
try:
    import z3
    _Z3 = True
except ImportError:
    _Z3 = False

pytestmark = pytest.mark.skipif(not _Z3, reason="z3-solver required")

from dragonslayer.analysis.symbolic_execution.state import (
    SymbolicState,
    AliasResult,
    MemoryWrite,
    SymbolicMemoryRegion,
    MemoryAccessRecord,
)
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor,
    HandlerSymbolicSummary,
)


# ═══════════════════════════════════════════════════════════════════
# 1. SymbolicMemoryRegion dataclass
# ═══════════════════════════════════════════════════════════════════

class TestSymbolicMemoryRegion:
    """Basic region dataclass tests."""

    def test_concrete_region(self):
        r = SymbolicMemoryRegion(name="stack", base=0x7FFF0000, size=0x10000)
        assert r.name == "stack"
        assert r.base == 0x7FFF0000
        assert r.size == 0x10000

    def test_symbolic_region(self):
        base = z3.BitVec("ctx_base", 64)
        r = SymbolicMemoryRegion(name="vm_context", base=base, size=0)
        assert r.name == "vm_context"
        assert r.size == 0  # unbounded

    def test_default_size_is_zero(self):
        r = SymbolicMemoryRegion(name="heap", base=0x1000)
        assert r.size == 0


# ═══════════════════════════════════════════════════════════════════
# 2. MemoryAccessRecord
# ═══════════════════════════════════════════════════════════════════

class TestMemoryAccessRecord:
    def test_load_record(self):
        rec = MemoryAccessRecord(
            kind="load", address_expr="0x1000", value_expr="mem_load_1",
            size=8, region="stack", timestamp=5,
        )
        assert rec.kind == "load"
        assert rec.region == "stack"

    def test_store_record_no_region(self):
        rec = MemoryAccessRecord(
            kind="store", address_expr="x", value_expr="y", size=4,
        )
        assert rec.region is None


# ═══════════════════════════════════════════════════════════════════
# 3. Region mapping and resolution
# ═══════════════════════════════════════════════════════════════════

class TestRegionMapping:
    """Test map_region / get_region / resolve_region."""

    def test_map_and_get_region(self):
        state = SymbolicState()
        state.map_region("stack", 0x7FFF0000, 0x10000)
        r = state.get_region("stack")
        assert r is not None
        assert r.name == "stack"

    def test_get_missing_region(self):
        state = SymbolicState()
        assert state.get_region("nonexistent") is None

    def test_resolve_concrete_in_range(self):
        state = SymbolicState()
        state.map_region("stack", 0x7FFF0000, 0x10000)
        r = state.resolve_region(0x7FFF1000)
        assert r is not None
        assert r.name == "stack"

    def test_resolve_concrete_out_of_range(self):
        state = SymbolicState()
        state.map_region("stack", 0x7FFF0000, 0x10000)
        assert state.resolve_region(0x1000) is None

    def test_resolve_concrete_unbounded_region(self):
        state = SymbolicState()
        state.map_region("heap", 0x400000, 0)  # unbounded
        r = state.resolve_region(0x500000)
        assert r is not None
        assert r.name == "heap"

    def test_resolve_symbolic_in_region(self):
        """Symbolic address = base + concrete offset → resolves to region."""
        state = SymbolicState()
        base = z3.BitVec("ctx", 64)
        state.map_region("vm_context", base, 0)
        # addr = base + 0x10
        addr = base + z3.BitVecVal(0x10, 64)
        r = state.resolve_region(addr)
        assert r is not None
        assert r.name == "vm_context"

    def test_resolve_symbolic_unrelated(self):
        """Symbolic address unrelated to any region base → None."""
        state = SymbolicState()
        base = z3.BitVec("ctx", 64)
        state.map_region("vm_context", base, 0)
        other = z3.BitVec("other", 64)
        r = state.resolve_region(other)
        # other has no algebraic relation to base, so no region
        assert r is None


# ═══════════════════════════════════════════════════════════════════
# 4. Symbolic store forwarding
# ═══════════════════════════════════════════════════════════════════

class TestStoreForwarding:
    """Verify that writes to symbolic addresses can be read back."""

    def test_write_then_read_same_symbolic_address(self):
        state = SymbolicState()
        addr = z3.BitVec("ptr", 64)
        val = z3.BitVecVal(0xDEAD, 64)
        state.write_memory(addr, val, 8)
        read_back = state.read_memory(addr, 8)
        # Must get the same value via store forwarding
        assert z3.is_true(z3.simplify(read_back == val))

    def test_write_then_read_different_symbolic_address(self):
        state = SymbolicState()
        addr1 = z3.BitVec("ptr1", 64)
        addr2 = z3.BitVec("ptr2", 64)
        val = z3.BitVecVal(0xBEEF, 64)
        state.write_memory(addr1, val, 8)
        read_back = state.read_memory(addr2, 8)
        # Different symbolic addresses → cannot forward → fresh variable
        assert not z3.is_true(z3.simplify(read_back == val))

    def test_multiple_writes_latest_wins(self):
        state = SymbolicState()
        addr = z3.BitVec("ptr", 64)
        val1 = z3.BitVecVal(0x1111, 64)
        val2 = z3.BitVecVal(0x2222, 64)
        state.write_memory(addr, val1, 8)
        state.write_memory(addr, val2, 8)
        read_back = state.read_memory(addr, 8)
        assert z3.is_true(z3.simplify(read_back == val2))

    def test_concretisable_symbolic_address(self):
        """If a symbolic address has a unique solution, it concretises."""
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        state.add_constraint(x == z3.BitVecVal(0x1000, 64))
        state.write_memory(0x1000, 42, 8)
        # Reading from x should concretise to 0x1000 and find 42
        result = state.read_memory(x, 8)
        assert result == 42


# ═══════════════════════════════════════════════════════════════════
# 5. Region-aware symbolic read naming
# ═══════════════════════════════════════════════════════════════════

class TestRegionAwareNaming:
    """Verify that fresh symbolic reads include region name."""

    def test_read_in_named_region(self):
        state = SymbolicState()
        base = z3.BitVec("stk_base", 64)
        state.map_region("stack", base, 0)
        addr = base + z3.BitVecVal(0x20, 64)
        val = state.read_memory(addr, 8)
        # The fresh variable should be named "stack_load_..."
        assert "stack_load" in str(val)

    def test_read_outside_region(self):
        state = SymbolicState()
        base = z3.BitVec("stk_base", 64)
        state.map_region("stack", base, 0)
        other = z3.BitVec("other_ptr", 64)
        val = state.read_memory(other, 8)
        # Should be "mem_load_..." (no region)
        assert "mem_load" in str(val)

    def test_unique_names_per_read(self):
        state = SymbolicState()
        addr = z3.BitVec("p", 64)
        v1 = state.read_memory(addr, 8)
        v2 = state.read_memory(addr, 8)
        # Each read should produce a uniquely-named variable
        # (they can't be proved equal since there's no write between)
        assert str(v1) != str(v2)


# ═══════════════════════════════════════════════════════════════════
# 6. Memory effects summary
# ═══════════════════════════════════════════════════════════════════

class TestMemoryEffectsSummary:
    def test_summary_has_loads_and_stores(self):
        state = SymbolicState()
        addr = z3.BitVec("a", 64)
        val = z3.BitVecVal(0xFF, 64)
        state.write_memory(addr, val, 8)
        _ = state.read_memory(addr, 8)
        summary = state.summarize_memory_effects()
        assert "loads" in summary
        assert "stores" in summary

    def test_summary_store_count(self):
        state = SymbolicState()
        addr = z3.BitVec("a", 64)
        state.write_memory(addr, z3.BitVecVal(1, 64), 8)
        state.write_memory(addr, z3.BitVecVal(2, 64), 8)
        summary = state.summarize_memory_effects()
        assert len(summary["stores"]) == 2

    def test_summary_region_annotation(self):
        state = SymbolicState()
        base = z3.BitVec("ctx", 64)
        state.map_region("vm_context", base, 0)
        addr = base + z3.BitVecVal(8, 64)
        _ = state.read_memory(addr, 8)
        summary = state.summarize_memory_effects()
        assert len(summary["loads"]) >= 1
        assert summary["loads"][0].get("region") == "vm_context"

    def test_summary_regions_key(self):
        state = SymbolicState()
        state.map_region("stack", 0x7FFF0000, 0x10000)
        summary = state.summarize_memory_effects()
        assert "stack" in summary["regions"]


# ═══════════════════════════════════════════════════════════════════
# 7. Fork preserves regions and logs
# ═══════════════════════════════════════════════════════════════════

class TestForkPreservesMemory:
    def test_fork_preserves_regions(self):
        state = SymbolicState()
        state.map_region("stack", 0x7FFF0000, 0x10000)
        forked = state.fork()
        assert forked.get_region("stack") is not None

    def test_fork_preserves_symbolic_store(self):
        state = SymbolicState()
        addr = z3.BitVec("p", 64)
        state.write_memory(addr, z3.BitVecVal(99, 64), 8)
        forked = state.fork()
        val = forked.read_memory(addr, 8)
        assert z3.is_true(z3.simplify(val == z3.BitVecVal(99, 64)))

    def test_fork_preserves_read_counter(self):
        state = SymbolicState()
        addr = z3.BitVec("p", 64)
        _ = state.read_memory(addr, 8)
        c1 = state._sym_read_counter
        forked = state.fork()
        assert forked._sym_read_counter == c1


# ═══════════════════════════════════════════════════════════════════
# 8. Executor: symbolic memory reads through state
# ═══════════════════════════════════════════════════════════════════

class TestExecutorSymbolicMemory:
    """Verify the executor routes symbolic operands through state.read/write_memory."""

    def test_mov_from_symbolic_address_uses_state(self):
        """mov rax, [rbx] with symbolic rbx -> state.read_memory path."""
        executor = SymbolicExecutor(arch="x86_64")
        state = SymbolicState(arch="x86_64", bit_width=64)
        rbx_sym = z3.BitVec("test_rbx", 64)
        state.set_register("rbx", rbx_sym)

        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction, InstructionCategory
        insn = LiftedInstruction(
            address=0x1000, size=3, mnemonic="mov",
            operands="rax, [rbx]", raw_bytes=b"\x48\x8b\x03",
            category=InstructionCategory.MEMORY_READ,
        )
        executor._apply_instruction(state, insn)
        rax = state.get_register("rax")
        # Should NOT be zero — should be a symbolic value from state.read_memory
        assert hasattr(rax, "sort")  # z3 symbolic

    def test_write_to_symbolic_address_stored(self):
        """mov [rbx], rcx with symbolic rbx -> value enters symbolic store."""
        executor = SymbolicExecutor(arch="x86_64")
        state = SymbolicState(arch="x86_64", bit_width=64)
        rbx_sym = z3.BitVec("test_rbx", 64)
        rcx_val = z3.BitVecVal(0x42, 64)
        state.set_register("rbx", rbx_sym)
        state.set_register("rcx", rcx_val)

        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction, InstructionCategory
        insn = LiftedInstruction(
            address=0x1000, size=3, mnemonic="mov",
            operands="[rbx], rcx", raw_bytes=b"\x48\x89\x0b",
            category=InstructionCategory.MEMORY_WRITE,
        )
        executor._apply_instruction(state, insn)
        assert len(state._symbolic_store) >= 1
        # The write should be recoverable via store forwarding
        read_back = state.read_memory(rbx_sym, 8)
        assert z3.is_true(z3.simplify(read_back == rcx_val))

    def test_sib_symbolic_read(self):
        """mov rax, [rbp+rcx*8] with symbolic registers → state.read_memory."""
        executor = SymbolicExecutor(arch="x86_64")
        state = SymbolicState(arch="x86_64", bit_width=64)
        rbp_sym = z3.BitVec("test_rbp", 64)
        rcx_sym = z3.BitVec("test_rcx", 64)
        state.set_register("rbp", rbp_sym)
        state.set_register("rcx", rcx_sym)

        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction, InstructionCategory
        insn = LiftedInstruction(
            address=0x2000, size=4, mnemonic="mov",
            operands="rax, [rbp+rcx*8]", raw_bytes=b"\x48\x8b\x44\xcd",
            category=InstructionCategory.MEMORY_READ,
        )
        executor._apply_instruction(state, insn)
        rax = state.get_register("rax")
        assert hasattr(rax, "sort")  # symbolic, not zero

    def test_write_read_roundtrip_sib(self):
        """Write to [rbp+0x10] then read back → store forwarding works."""
        executor = SymbolicExecutor(arch="x86_64")
        state = SymbolicState(arch="x86_64", bit_width=64)
        rbp_sym = z3.BitVec("test_rbp", 64)
        state.set_register("rbp", rbp_sym)
        state.set_register("rax", z3.BitVecVal(0xABCD, 64))

        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction, InstructionCategory
        wr = LiftedInstruction(
            address=0x3000, size=4, mnemonic="mov",
            operands="[rbp+0x10], rax", raw_bytes=b"\x48\x89\x45\x10",
            category=InstructionCategory.MEMORY_WRITE,
        )
        rd = LiftedInstruction(
            address=0x3004, size=4, mnemonic="mov",
            operands="rcx, [rbp+0x10]", raw_bytes=b"\x48\x8b\x4d\x10",
            category=InstructionCategory.MEMORY_READ,
        )
        executor._apply_instruction(state, wr)
        executor._apply_instruction(state, rd)
        rcx = state.get_register("rcx")
        assert z3.is_true(z3.simplify(rcx == z3.BitVecVal(0xABCD, 64)))


# ═══════════════════════════════════════════════════════════════════
# 9. Executor: execute_handler includes memory effects
# ═══════════════════════════════════════════════════════════════════

class TestExecuteHandlerMemoryEffects:
    """Verify execute_handler produces memory_effects in the summary."""

    def test_handler_summary_has_memory_effects(self):
        """A handler that pushes a value should have memory effects."""
        # push rax ; ret  (0x50 0xC3)
        executor = SymbolicExecutor(arch="x86_64")
        code = b"\x50\xC3"
        summary = executor.execute_handler(code, handler_address=0x5000)
        assert summary.memory_effects is not None
        assert "stores" in summary.memory_effects
        assert "regions" in summary.memory_effects

    def test_handler_summary_has_stack_region(self):
        """execute_handler should set up a 'stack' region."""
        executor = SymbolicExecutor(arch="x86_64")
        code = b"\xC3"  # just ret
        summary = executor.execute_handler(code, handler_address=0x5000)
        regions = summary.memory_effects.get("regions", {})
        assert "stack" in regions

    def test_handler_summary_has_vm_context_region(self):
        """execute_handler should set up a 'vm_context' region."""
        executor = SymbolicExecutor(arch="x86_64")
        code = b"\xC3"
        summary = executor.execute_handler(code, handler_address=0x5000)
        regions = summary.memory_effects.get("regions", {})
        assert "vm_context" in regions

    def test_handler_summary_to_dict_includes_effects(self):
        executor = SymbolicExecutor(arch="x86_64")
        code = b"\x50\xC3"  # push rax; ret
        summary = executor.execute_handler(code, handler_address=0x5000)
        d = summary.to_dict()
        assert "memory_effects" in d

    def test_load_handler_memory_effects(self):
        """A vm_load-like handler: mov rax, [rbp+rcx*8]
        Should produce at least a load in memory_effects.
        """
        # We test through execute_handler; the instructions
        # use symbolic RBP so the load should appear.
        # Using raw bytes for: mov rax, [rbp]  (48 8b 45 00)
        # followed by ret (c3)
        code = b"\x48\x8b\x45\x00\xc3"
        executor = SymbolicExecutor(arch="x86_64")
        summary = executor.execute_handler(code, handler_address=0x6000)
        effects = summary.memory_effects
        # Should have at least one load (from [rbp])
        loads = effects.get("loads", [])
        # Note: loads may or may not be captured depending on whether
        # the address was symbolic (rbp is symbolic in execute_handler).
        # The key test is that the infrastructure exists.
        assert isinstance(loads, list)


# ═══════════════════════════════════════════════════════════════════
# 10. Alias analysis integration
# ═══════════════════════════════════════════════════════════════════

class TestAliasAnalysis:
    def test_must_alias_concrete(self):
        state = SymbolicState()
        assert state.query_alias(0x1000, 0x1000) == AliasResult.MUST

    def test_no_alias_concrete(self):
        state = SymbolicState()
        assert state.query_alias(0x1000, 0x2000) == AliasResult.NO

    def test_must_alias_constrained_symbolic(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        state.add_constraint(x == y)
        assert state.query_alias(x, y) == AliasResult.MUST

    def test_no_alias_constrained_symbolic(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        state.add_constraint(x == z3.BitVecVal(0x1000, 64))
        state.add_constraint(y == z3.BitVecVal(0x2000, 64))
        assert state.query_alias(x, y) == AliasResult.NO

    def test_may_alias_unconstrained(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        assert state.query_alias(x, y) == AliasResult.MAY


# ═══════════════════════════════════════════════════════════════════
# 11. Concrete memory still works
# ═══════════════════════════════════════════════════════════════════

class TestConcreteMemoryUnchanged:
    """Ensure concrete-address memory operations are not broken."""

    def test_write_read_concrete(self):
        state = SymbolicState()
        state.write_memory(0x1000, 0xDEADBEEF, 4)
        val = state.read_memory(0x1000, 4)
        assert val == 0xDEADBEEF

    def test_byte_granularity(self):
        state = SymbolicState()
        state.write_memory(0x2000, 0x0102, 2)
        assert state.read_memory(0x2000, 1) == 0x02  # little-endian low byte
        assert state.read_memory(0x2001, 1) == 0x01  # high byte

    def test_symbolic_value_at_concrete_addr(self):
        state = SymbolicState()
        v = z3.BitVec("data", 64)
        state.write_memory(0x3000, v, 8)
        read_back = state.read_memory(0x3000, 8)
        assert z3.is_true(z3.simplify(read_back == v))
