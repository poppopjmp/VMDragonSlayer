"""B76 tests: Memory alias tracker, pointer-aware taint, CI improvements."""

from __future__ import annotations

import pytest

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    MemoryAliasTracker,
)


# ---------------------------------------------------------------------------
# 1. MemoryAliasTracker standalone
# ---------------------------------------------------------------------------


class TestMemoryAliasTracker:
    """Unit tests for MemoryAliasTracker."""

    def test_bind_and_resolve(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        assert mat.resolve("rax") == 0x1000

    def test_must_alias_same_addr(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x1000)
        assert mat.must_alias("rax", "rbx")

    def test_no_alias_different_addr(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x2000)
        assert not mat.must_alias("rax", "rbx")

    def test_unbind_removes_alias(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x1000)
        mat.unbind("rax")
        assert not mat.must_alias("rax", "rbx")
        assert mat.resolve("rax") is None

    def test_rebind_updates_alias(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x1000)
        # Rebind rax to different address
        mat.bind("rax", 0x2000)
        assert not mat.must_alias("rax", "rbx")
        assert mat.resolve("rax") == 0x2000

    def test_aliases_of(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x1000)
        mat.bind("rcx", 0x1000)
        aliases = mat.aliases_of("rax")
        assert aliases == {"rbx", "rcx"}

    def test_clear(self):
        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.clear()
        assert mat.resolve("rax") is None

    def test_case_insensitive(self):
        mat = MemoryAliasTracker()
        mat.bind("RAX", 0x1000)
        assert mat.resolve("rax") == 0x1000

    def test_unbound_resolve_returns_none(self):
        mat = MemoryAliasTracker()
        assert mat.resolve("rdx") is None

    def test_must_alias_unbound_returns_false(self):
        mat = MemoryAliasTracker()
        assert not mat.must_alias("rax", "rbx")


# ---------------------------------------------------------------------------
# 2. TaintTracker pointer-aware methods
# ---------------------------------------------------------------------------


class TestPointerAwareTaint:
    """Test TaintTracker.bind_pointer / must_alias / memory_taint_via_reg."""

    def test_bind_and_must_alias(self):
        t = TaintTracker()
        t.bind_pointer("rax", 0x1000)
        t.bind_pointer("rbx", 0x1000)
        assert t.must_alias("rax", "rbx")

    def test_memory_taint_via_reg(self):
        """Store taint at address, query via register bound to same address."""
        t = TaintTracker()
        t.bind_pointer("rax", 0x1000)
        t.taint_memory(0x1000, TaintTag.INPUT)
        tag = t.memory_taint_via_reg("rax")
        assert tag & TaintTag.INPUT

    def test_memory_taint_via_aliased_reg(self):
        """rbx holds the same address as where we tainted memory."""
        t = TaintTracker()
        t.bind_pointer("rax", 0x1000)
        t.bind_pointer("rbx", 0x1000)
        t.taint_memory(0x1000, TaintTag.VM_OPERAND)
        # Both should see the taint
        assert t.memory_taint_via_reg("rax") & TaintTag.VM_OPERAND
        assert t.memory_taint_via_reg("rbx") & TaintTag.VM_OPERAND

    def test_unbound_reg_returns_clean(self):
        t = TaintTracker()
        assert t.memory_taint_via_reg("rcx") == TaintTag.CLEAN

    def test_pointer_tracker_property(self):
        t = TaintTracker()
        assert isinstance(t.pointer_tracker, MemoryAliasTracker)

    def test_reset_clears_pointer_tracker(self):
        t = TaintTracker()
        t.bind_pointer("rax", 0x1000)
        t.reset()
        assert t.pointer_tracker.resolve("rax") is None


# ---------------------------------------------------------------------------
# 3. Regression: pop_call_context still works after pointer_tracker addition
# ---------------------------------------------------------------------------


class TestRegressionPopCallContext:
    """Ensure B76 additions don't break interprocedural taint."""

    def test_basic_pop_still_works(self):
        t = TaintTracker(sub_register_aware=True)
        t.taint_register("rax", TaintTag.INPUT)
        t.push_call_context()
        t.taint_register("rax", TaintTag.COMPUTED)
        t.pop_call_context(return_regs=("rax",))
        tag = t.get_taint("rax")
        assert tag & TaintTag.INPUT
        assert tag & TaintTag.COMPUTED
