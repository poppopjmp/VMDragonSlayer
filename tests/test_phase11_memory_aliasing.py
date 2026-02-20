"""Phase 11 Batch 7 – Symbolic memory aliasing tests."""

import pytest

try:
    import z3
    _Z3 = True
except ImportError:
    _Z3 = False

from dragonslayer.analysis.symbolic_execution.state import (
    SymbolicState,
    MemoryWrite,
    AliasResult,
)


# ---------------------------------------------------------------------------
# AliasResult constants
# ---------------------------------------------------------------------------

class TestAliasResultConstants:
    def test_must(self):
        assert AliasResult.MUST == "must"

    def test_may(self):
        assert AliasResult.MAY == "may"

    def test_no(self):
        assert AliasResult.NO == "no"


# ---------------------------------------------------------------------------
# query_alias — concrete addresses
# ---------------------------------------------------------------------------

class TestQueryAliasConcrete:
    def test_same_concrete(self):
        state = SymbolicState()
        assert state.query_alias(0x1000, 0x1000) == AliasResult.MUST

    def test_different_concrete(self):
        state = SymbolicState()
        assert state.query_alias(0x1000, 0x2000) == AliasResult.NO


# ---------------------------------------------------------------------------
# query_alias — symbolic addresses
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _Z3, reason="z3 required")
class TestQueryAliasSymbolic:
    def test_must_alias_same_symbol(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        assert state.query_alias(x, x) == AliasResult.MUST

    def test_must_alias_constrained_equal(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        state.add_constraint(x == y)
        assert state.query_alias(x, y) == AliasResult.MUST

    def test_no_alias_constrained_different(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        state.add_constraint(x != y)
        assert state.query_alias(x, y) == AliasResult.NO

    def test_may_alias_unconstrained(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        assert state.query_alias(x, y) == AliasResult.MAY

    def test_must_alias_symbolic_vs_concrete(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        state.add_constraint(x == z3.BitVecVal(0x1000, 64))
        assert state.query_alias(x, 0x1000) == AliasResult.MUST

    def test_no_alias_symbolic_vs_concrete(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        state.add_constraint(x == z3.BitVecVal(0x1000, 64))
        assert state.query_alias(x, 0x2000) == AliasResult.NO

    def test_must_alias_expression(self):
        """x+4 and y+4 must-alias when x == y."""
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        state.add_constraint(x == y)
        assert state.query_alias(x + 4, y + 4) == AliasResult.MUST


# ---------------------------------------------------------------------------
# _is_symbolic_addr helper
# ---------------------------------------------------------------------------

class TestIsSymbolicAddr:
    def test_int_is_not_symbolic(self):
        assert not SymbolicState._is_symbolic_addr(42)

    @pytest.mark.skipif(not _Z3, reason="z3 required")
    def test_z3_bitvec_is_symbolic(self):
        x = z3.BitVec("x", 64)
        assert SymbolicState._is_symbolic_addr(x)


# ---------------------------------------------------------------------------
# _try_concretise
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _Z3, reason="z3 required")
class TestTryConcretise:
    def test_unique_value(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        state.add_constraint(x == z3.BitVecVal(42, 64))
        assert state._try_concretise(x) == 42

    def test_non_unique_returns_none(self):
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        # x > 0 but not unique
        state.add_constraint(z3.UGT(x, z3.BitVecVal(0, 64)))
        assert state._try_concretise(x) is None

    def test_concrete_int(self):
        state = SymbolicState()
        assert state._try_concretise(100) == 100


# ---------------------------------------------------------------------------
# write_memory with symbolic address
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _Z3, reason="z3 required")
class TestWriteMemorySymbolic:
    def test_symbolic_write_goes_to_symbolic_store(self):
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 0xDEAD, size=4)
        assert len(state._symbolic_store) == 1
        assert state._symbolic_store[0].value == 0xDEAD
        assert state._symbolic_store[0].size == 4

    def test_symbolic_write_also_logged(self):
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 42, size=2)
        assert len(state._memory_log) == 1

    def test_concretisable_symbolic_goes_to_concrete(self):
        """Symbolic address with unique solution gets concretised."""
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.add_constraint(addr == z3.BitVecVal(0x1000, 64))
        state.write_memory(addr, 0xBEEF, size=2)
        # Should be in concrete store, not symbolic
        assert len(state._symbolic_store) == 0
        assert state.memory[0x1000] == 0xEF  # low byte
        assert state.memory[0x1001] == 0xBE  # high byte


# ---------------------------------------------------------------------------
# read_memory with symbolic address — store forwarding
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _Z3, reason="z3 required")
class TestReadMemorySymbolic:
    def test_forward_from_symbolic_store(self):
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 0xCAFE, size=4)
        val = state.read_memory(addr, size=4)
        assert val == 0xCAFE

    def test_forward_must_alias(self):
        """Read from y forwards if x == y under constraints."""
        state = SymbolicState()
        x = z3.BitVec("x", 64)
        y = z3.BitVec("y", 64)
        state.add_constraint(x == y)
        state.write_memory(x, 0x1234, size=4)
        val = state.read_memory(y, size=4)
        assert val == 0x1234

    def test_no_forward_size_mismatch(self):
        """Forwarding requires matching size."""
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 0xFF, size=1)
        val = state.read_memory(addr, size=4)
        # Size mismatch → no forwarding → returns fresh symbolic
        assert hasattr(val, "sort")  # z3 expr
        assert val.sort().size() == 32

    def test_concretisable_read(self):
        """Symbolic address that concretises to known concrete store."""
        state = SymbolicState()
        state.write_memory(0x2000, 0xAA, size=1)
        addr = z3.BitVec("a", 64)
        state.add_constraint(addr == z3.BitVecVal(0x2000, 64))
        val = state.read_memory(addr, size=1)
        assert val == 0xAA

    def test_fresh_symbolic_on_unknown(self):
        """Read from unknown symbolic address → fresh symbolic value."""
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        val = state.read_memory(addr, size=4)
        assert hasattr(val, "sort")
        assert val.sort().size() == 32

    def test_forward_most_recent_write(self):
        """Multiple writes — forwards the most recent must-alias match."""
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 0x1111, size=4)
        state.write_memory(addr, 0x2222, size=4)
        val = state.read_memory(addr, size=4)
        assert val == 0x2222


# ---------------------------------------------------------------------------
# fork copies symbolic store
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _Z3, reason="z3 required")
class TestForkSymbolicStore:
    def test_fork_copies_symbolic_store(self):
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 42, size=4)
        forked = state.fork()
        assert len(forked._symbolic_store) == 1
        assert forked._symbolic_store[0].value == 42

    def test_fork_independent(self):
        state = SymbolicState()
        addr = z3.BitVec("addr", 64)
        state.write_memory(addr, 42, size=4)
        forked = state.fork()
        # Write to forked doesn't affect original
        addr2 = z3.BitVec("addr2", 64)
        forked.write_memory(addr2, 99, size=4)
        assert len(state._symbolic_store) == 1
        assert len(forked._symbolic_store) == 2


# ---------------------------------------------------------------------------
# Concrete read/write unchanged (regression)
# ---------------------------------------------------------------------------

class TestConcreteMemoryRegression:
    def test_concrete_write_read(self):
        state = SymbolicState()
        state.write_memory(0x1000, 0xDEADBEEF, size=4)
        assert state.read_memory(0x1000, size=4) == 0xDEADBEEF

    def test_byte_granular(self):
        state = SymbolicState()
        state.write_memory(0x100, 0x0102, size=2)
        assert state.read_memory(0x100, size=1) == 0x02  # little-endian low
        assert state.read_memory(0x101, size=1) == 0x01  # high byte

    @pytest.mark.skipif(not _Z3, reason="z3 required")
    def test_symbolic_value_concrete_addr(self):
        state = SymbolicState()
        val = z3.BitVec("v", 32)
        state.write_memory(0x200, val, size=4)
        result = state.read_memory(0x200, size=4)
        assert hasattr(result, "sort")
