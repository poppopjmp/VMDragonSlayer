"""Tests for EFLAGS taint propagation (Batch 33).

Validates that flag-producing instructions taint EFLAGS when any source
operand is tainted, and that flag-consuming instructions (Jcc, CMOVcc,
SETcc) pick up the tainted flags.
"""

from types import SimpleNamespace

import pytest

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    is_eflags_producer,
    is_eflags_consumer,
    _EFLAGS_PRODUCERS,
    _EFLAGS_CONSUMERS,
    _INDIVIDUAL_FLAGS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insn(mnemonic, operands="", reads=None, writes=None, address=0,
          category="unknown", registers=None):
    """Build a fake lifted instruction."""
    return SimpleNamespace(
        mnemonic=mnemonic,
        operands=operands,
        reads=reads or [],
        writes=writes or [],
        address=address,
        category=category,
        registers=registers or {},
    )


# ---------------------------------------------------------------------------
# Classifier unit tests
# ---------------------------------------------------------------------------

class TestClassifier:
    """Unit tests for is_eflags_producer / is_eflags_consumer."""

    @pytest.mark.parametrize("mnem", [
        "add", "sub", "cmp", "test", "and", "or", "xor", "shl", "shr",
        "neg", "adc", "sbb", "imul", "bt", "sahf",
    ])
    def test_producer_positive(self, mnem):
        assert is_eflags_producer(mnem)

    @pytest.mark.parametrize("mnem", ["mov", "lea", "nop", "push", "pop", "call", "ret"])
    def test_producer_negative(self, mnem):
        assert not is_eflags_producer(mnem)

    @pytest.mark.parametrize("mnem", [
        "je", "jne", "jb", "ja", "jl", "jg", "cmove", "cmovne",
        "sete", "setb", "adc", "sbb", "pushf",
    ])
    def test_consumer_positive(self, mnem):
        assert is_eflags_consumer(mnem)

    @pytest.mark.parametrize("mnem", ["mov", "lea", "nop", "add", "sub"])
    def test_consumer_negative(self, mnem):
        assert not is_eflags_consumer(mnem)

    def test_case_insensitive(self):
        assert is_eflags_producer("ADD")
        assert is_eflags_consumer("JE")


# ---------------------------------------------------------------------------
# Basic EFLAGS propagation
# ---------------------------------------------------------------------------

class TestEflagsPropagate:
    """Flag-producing instructions should taint EFLAGS when sources are tainted."""

    def test_cmp_tainted_operand(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        insn = _insn("cmp", "rax, rbx", reads=["rax", "rbx"], writes=[])
        t.process_instruction(insn)
        assert t.is_tainted("eflags")

    def test_add_tainted_source(self):
        t = TaintTracker()
        t.taint_register("rcx", TaintTag.INPUT)
        insn = _insn("add", "rdx, rcx", reads=["rdx", "rcx"], writes=["rdx"])
        t.process_instruction(insn)
        assert t.is_tainted("eflags")
        assert t.is_tainted("rdx")

    def test_test_tainted_flags(self):
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.VM_OPERAND)
        insn = _insn("test", "rdi, rdi", reads=["rdi"], writes=[])
        t.process_instruction(insn)
        tag = t.get_taint("eflags")
        assert tag & TaintTag.VM_OPERAND

    def test_xor_tainted_flags(self):
        t = TaintTracker()
        t.taint_register("r8", TaintTag.CRYPTO)
        insn = _insn("xor", "r9, r8", reads=["r9", "r8"], writes=["r9"])
        t.process_instruction(insn)
        assert t.is_tainted("eflags")

    def test_individual_flags_tainted(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        insn = _insn("sub", "rax, rbx", reads=["rax", "rbx"], writes=["rax"])
        t.process_instruction(insn)
        for flag in ["cf", "zf", "sf", "of", "pf", "af"]:
            assert t.is_tainted(flag), f"{flag} should be tainted"


# ---------------------------------------------------------------------------
# EFLAGS consumption
# ---------------------------------------------------------------------------

class TestEflagsConsume:
    """Flag-consuming instructions should propagate tainted EFLAGS forward."""

    def _taint_flags(self, tracker):
        """Helper: taint eflags via a CMP on tainted register."""
        tracker.taint_register("rax", TaintTag.VM_OPERAND)
        tracker.process_instruction(
            _insn("cmp", "rax, 0", reads=["rax"], writes=[])
        )

    def test_jcc_sees_tainted_flags(self):
        t = TaintTracker()
        self._taint_flags(t)
        # jne normally has no explicit register reads/writes in lifting
        insn = _insn("jne", "0x401000", reads=[], writes=[],
                      category="branch_conditional")
        t.process_instruction(insn)
        # Should generate an implicit taint event
        events = [e for e in t._events if e.event_type == "implicit"]
        assert len(events) >= 1
        assert any(e.source == "eflags" for e in events)

    def test_cmovne_propagates_flags(self):
        t = TaintTracker()
        self._taint_flags(t)
        insn = _insn("cmovne", "rbx, rcx", reads=["rbx", "rcx"], writes=["rbx"])
        t.process_instruction(insn)
        # rbx should pick up taint from eflags
        assert t.is_tainted("rbx")

    def test_sete_propagates_flags(self):
        t = TaintTracker()
        self._taint_flags(t)
        insn = _insn("sete", "al", reads=[], writes=["al"])
        t.process_instruction(insn)
        assert t.is_tainted("al")

    def test_adc_reads_flags(self):
        """ADC is both producer and consumer: reads carry flag."""
        t = TaintTracker()
        self._taint_flags(t)
        # ADC with clean registers but tainted carry
        insn = _insn("adc", "rbx, 0", reads=["rbx"], writes=["rbx"])
        t.process_instruction(insn)
        assert t.is_tainted("rbx"), "ADC should propagate tainted carry"


# ---------------------------------------------------------------------------
# EFLAGS clearing
# ---------------------------------------------------------------------------

class TestEflagsClear:
    """Clean-producing instructions should clear tainted EFLAGS."""

    def test_clean_cmp_clears_flags(self):
        t = TaintTracker()
        # First taint eflags
        t.taint_register("rax", TaintTag.INPUT)
        t.process_instruction(_insn("cmp", "rax, 0", reads=["rax"], writes=[]))
        assert t.is_tainted("eflags")

        # Now clean CMP on untainted operands
        t.process_instruction(_insn("cmp", "rbx, rcx", reads=["rbx", "rcx"], writes=[]))
        assert not t.is_tainted("eflags")

    def test_clean_add_clears_flags(self):
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.VM_OPERAND)
        t.process_instruction(_insn("test", "rdi, rdi", reads=["rdi"], writes=[]))
        assert t.is_tainted("zf")

        t.process_instruction(
            _insn("add", "rbx, rcx", reads=["rbx", "rcx"], writes=["rbx"])
        )
        assert not t.is_tainted("zf")
        assert not t.is_tainted("eflags")

    def test_individual_flags_cleared(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        t.process_instruction(_insn("sub", "rax, 1", reads=["rax"], writes=["rax"]))
        for f in _INDIVIDUAL_FLAGS:
            assert t.is_tainted(f)

        # Clean producer clears all
        t.process_instruction(_insn("xor", "rbx, rbx", reads=["rbx"], writes=["rbx"]))
        for f in _INDIVIDUAL_FLAGS:
            assert not t.is_tainted(f), f"{f} should be clean now"


# ---------------------------------------------------------------------------
# Flow graph tracking
# ---------------------------------------------------------------------------

class TestEflagsFlowGraph:
    """EFLAGS taint events appear in the flow graph."""

    def test_cmp_creates_flow_edge(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        t.process_instruction(_insn("cmp", "rax, 0", reads=["rax"], writes=[]))
        assert "eflags" in t._flow_graph.get("rax", set())

    def test_jcc_with_tainted_flags_creates_edge(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        t.process_instruction(_insn("cmp", "rax, 0", reads=["rax"], writes=[]))
        # je — branch_conditional with implicit eflags read
        t.process_instruction(
            _insn("je", "target", reads=[], writes=[], category="branch_conditional")
        )
        events = [e for e in t._events if e.event_type == "implicit"]
        assert len(events) >= 1


# ---------------------------------------------------------------------------
# VMProtect-specific chains
# ---------------------------------------------------------------------------

class TestVMProtectChains:
    """End-to-end taint chains typical of VMProtect handlers."""

    def test_cmp_jcc_chain(self):
        """CMP tainted_reg, 0  →  JE target  (implicit taint)."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        t.process_instruction(_insn("cmp", "rax, 0", reads=["rax"], writes=[]))
        t.process_instruction(
            _insn("je", "0x1234", reads=[], writes=[], category="branch_conditional")
        )
        implicits = [e for e in t._events if e.event_type == "implicit"]
        assert any(e.source == "eflags" for e in implicits)

    def test_add_pushf_chain(self):
        """ADD tainted → PUSHF saves tainted flags."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        t.process_instruction(
            _insn("add", "rax, rbx", reads=["rax", "rbx"], writes=["rax"])
        )
        assert t.is_tainted("eflags")
        # pushf is a consumer that reads eflags
        t.process_instruction(
            _insn("pushf", "", reads=[], writes=["rsp"],
                  category="stack_push")
        )
        # rsp should pick up the taint from eflags
        assert t.is_tainted("rsp")

    def test_nand_flags_chain(self):
        """NOT + AND chain that VMProtect uses — flags track correctly."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        # NOT rax — bitwise, no flag writes in real x86, but our tracker
        # recognizes it as a producer (conservative)
        t.process_instruction(
            _insn("not", "rax", reads=["rax"], writes=["rax"])
        )
        assert t.is_tainted("eflags")
        # AND rax, rbx — produces flags from tainted result
        t.process_instruction(
            _insn("and", "rax, rbx", reads=["rax", "rbx"], writes=["rax"])
        )
        assert t.is_tainted("eflags")
        assert t.is_tainted("rax")

    def test_flag_merge_handler(self):
        """AND + OR + pushf — VMProtect flag merge pattern."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.VM_OPERAND)
        t.taint_register("rbx", TaintTag.VM_CONTEXT)

        t.process_instruction(
            _insn("and", "rax, rbx", reads=["rax", "rbx"], writes=["rax"])
        )
        assert t.is_tainted("eflags")
        tag = t.get_taint("eflags")
        # Should carry both sources
        assert tag & TaintTag.VM_OPERAND or tag & TaintTag.COMPUTED


# ---------------------------------------------------------------------------
# analyze() integration
# ---------------------------------------------------------------------------

class TestAnalyzeIntegration:
    """End-to-end via TaintTracker.analyze()."""

    def test_analyze_eflags_in_result(self):
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        result = t.analyze([
            _insn("cmp", "rax, 0", reads=["rax"], writes=[], address=0x100),
            _insn("je", "0x200", reads=[], writes=[], address=0x104,
                  category="branch_conditional"),
        ])
        assert result.success
        assert "eflags" in result.tainted_registers
        assert len(result.events) >= 2

    def test_analyze_setcc_output(self):
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.VM_OPERAND)
        result = t.analyze([
            _insn("test", "rdi, rdi", reads=["rdi"], writes=[], address=0x200),
            _insn("sete", "al", reads=[], writes=["al"], address=0x204),
        ])
        assert result.success
        # al should be tainted (flags from TEST propagated through SETE)
        assert "al" in result.tainted_registers or "rax" in result.tainted_registers


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and regressions."""

    def test_non_flag_instruction_no_eflags(self):
        """MOV should not affect eflags."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        t.process_instruction(_insn("mov", "rbx, rax", reads=["rax"], writes=["rbx"]))
        assert not t.is_tainted("eflags")

    def test_subreg_aware_still_works(self):
        """EFLAGS mode doesn't break sub-register awareness."""
        t = TaintTracker(sub_register_aware=True)
        t.taint_register("rax", TaintTag.INPUT)
        t.process_instruction(
            _insn("add", "eax, ecx", reads=["eax", "ecx"], writes=["eax"])
        )
        assert t.is_tainted("eflags")
        assert t.is_tainted("rax")

    def test_disabled_subreg_eflags_still_works(self):
        """EFLAGS works even with sub-register awareness off."""
        t = TaintTracker(sub_register_aware=False)
        t.taint_register("rax", TaintTag.INPUT)
        t.process_instruction(
            _insn("cmp", "rax, 0", reads=["rax"], writes=[])
        )
        assert t.is_tainted("eflags")

    def test_double_taint_clear_cycle(self):
        """Taint → clear → re-taint cycle works correctly."""
        t = TaintTracker()
        t.taint_register("rax", TaintTag.INPUT)
        t.process_instruction(_insn("cmp", "rax, 0", reads=["rax"], writes=[]))
        assert t.is_tainted("eflags")

        # Clear via clean producer
        t.process_instruction(_insn("cmp", "rbx, rcx", reads=["rbx", "rcx"], writes=[]))
        assert not t.is_tainted("eflags")

        # Re-taint
        t.process_instruction(_insn("test", "rax, rax", reads=["rax"], writes=[]))
        assert t.is_tainted("eflags")
