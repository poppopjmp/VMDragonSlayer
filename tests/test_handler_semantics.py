"""Tests for handler semantics analysis."""

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)
from dragonslayer.analysis.handler_semantics import (
    analyse_handler_semantics,
    HandlerSemantic,
    OpcodeTableEntry,
    SemanticOpcodeTable,
    VMOperation,
    _classify_handler,
    _extract_mnemonic,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _ti(addr, disasm="nop", size=1):
    return TraceInstruction(
        address=addr, size=size, raw_bytes=b"\x90" * size, disassembly=disasm,
    )


def _boundary(addr, start, end, vip_delta=4, vip=0x100):
    return HandlerBoundary(
        vip_value=vip, handler_address=addr,
        trace_start=start, trace_end=end,
        instruction_count=end - start, vip_delta=vip_delta,
    )


# ---------------------------------------------------------------------------
# _extract_mnemonic
# ---------------------------------------------------------------------------

class TestExtractMnemonic:
    def test_simple(self):
        assert _extract_mnemonic("add rax, rbx") == "add"

    def test_empty(self):
        assert _extract_mnemonic("") == ""

    def test_single_word(self):
        assert _extract_mnemonic("nop") == "nop"


# ---------------------------------------------------------------------------
# _classify_handler
# ---------------------------------------------------------------------------

class TestClassifyHandler:
    def test_add_handler(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "pop rbx"),
            _ti(0x6004, "add rax, rbx"),
            _ti(0x6006, "push rax"),
            _ti(0x6008, "jmp rcx"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operation == VMOperation.ADD
        assert s.confidence > 0.3

    def test_xor_handler(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "pop rbx"),
            _ti(0x6004, "xor rax, rbx"),
            _ti(0x6006, "push rax"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operation == VMOperation.XOR

    def test_memory_load(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "mov rbx, [rax]"),
            _ti(0x6004, "push rbx"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operation == VMOperation.LOAD
        assert s.reads_memory is True

    def test_memory_store(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "pop rbx"),
            _ti(0x6004, "mov [rax], rbx"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operation == VMOperation.STORE
        assert s.writes_memory is True

    def test_nop_handler(self):
        insns = [_ti(0x6000, "nop"), _ti(0x6001, "nop")]
        s = _classify_handler(0x6000, insns)
        assert s.operation == VMOperation.NOP

    def test_empty_handler(self):
        s = _classify_handler(0x6000, [])
        assert s.operation == VMOperation.NOP

    def test_jcc_handler(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "pop rbx"),
            _ti(0x6004, "cmp rax, rbx"),
            _ti(0x6006, "je 0x7000"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operation in (VMOperation.JCC, VMOperation.CMP)

    def test_call_handler(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "call rax"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operation == VMOperation.CALL

    def test_operand_width_64bit(self):
        insns = [
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "add rax, rbx"),
            _ti(0x6004, "push rax"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operand_width == 8

    def test_operand_width_32bit(self):
        insns = [
            _ti(0x6000, "pop eax"),
            _ti(0x6002, "add eax, ebx"),
            _ti(0x6004, "push eax"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.operand_width == 4

    def test_modifies_flags(self):
        insns = [
            _ti(0x6000, "add rax, rbx"),
        ]
        s = _classify_handler(0x6000, insns)
        assert s.modifies_flags is True


# ---------------------------------------------------------------------------
# analyse_handler_semantics
# ---------------------------------------------------------------------------

class TestAnalyseHandlerSemantics:
    def test_basic_table(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x6000, "pop rax"),
            _ti(0x6002, "pop rbx"),
            _ti(0x6004, "add rax, rbx"),
            _ti(0x6006, "push rax"),
            # second handler
            _ti(0x7000, "pop rax"),
            _ti(0x7002, "pop rbx"),
            _ti(0x7004, "xor rax, rbx"),
            _ti(0x7006, "push rax"),
        ])
        boundaries = [
            _boundary(0x6000, 0, 4),
            _boundary(0x7000, 4, 8),
        ]
        table = analyse_handler_semantics(trace, boundaries)
        assert isinstance(table, SemanticOpcodeTable)
        assert table.handler_count == 2
        assert table.unique_operations == 2

    def test_deduplication(self):
        """Same handler address appearing twice should only produce one entry."""
        trace = ExecutionTrace(instructions=[
            _ti(0x6000, "add rax, rbx"),
            _ti(0x6000, "add rax, rbx"),  # same handler executed again
        ])
        boundaries = [
            _boundary(0x6000, 0, 1, vip=0x100),
            _boundary(0x6000, 1, 2, vip=0x104),
        ]
        table = analyse_handler_semantics(trace, boundaries)
        assert table.handler_count == 1

    def test_custom_opcode_assignments(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x6000, "add rax, rbx"),
        ])
        boundaries = [_boundary(0x6000, 0, 1)]
        table = analyse_handler_semantics(
            trace, boundaries,
            opcode_assignments={0x6000: 0x42},
        )
        assert table.entries[0].opcode == 0x42

    def test_lookup_opcode(self):
        trace = ExecutionTrace(instructions=[_ti(0x6000, "add rax, rbx")])
        boundaries = [_boundary(0x6000, 0, 1)]
        table = analyse_handler_semantics(
            trace, boundaries, opcode_assignments={0x6000: 0x10},
        )
        entry = table.lookup_opcode(0x10)
        assert entry is not None
        assert entry.handler_address == 0x6000

    def test_lookup_handler(self):
        trace = ExecutionTrace(instructions=[_ti(0x6000, "nop")])
        boundaries = [_boundary(0x6000, 0, 1)]
        table = analyse_handler_semantics(trace, boundaries)
        entry = table.lookup_handler(0x6000)
        assert entry is not None

    def test_operations_summary(self):
        trace = ExecutionTrace(instructions=[
            _ti(0x6000, "add rax, rbx"),
            _ti(0x7000, "xor rax, rbx"),
            _ti(0x8000, "add rcx, rdx"),
        ])
        boundaries = [
            _boundary(0x6000, 0, 1),
            _boundary(0x7000, 1, 2),
            _boundary(0x8000, 2, 3),
        ]
        table = analyse_handler_semantics(trace, boundaries)
        summary = table.operations_summary()
        assert VMOperation.ADD in summary

    def test_to_dict(self):
        trace = ExecutionTrace(instructions=[_ti(0x6000, "nop")])
        boundaries = [_boundary(0x6000, 0, 1)]
        table = analyse_handler_semantics(trace, boundaries)
        d = table.to_dict()
        assert "handler_count" in d
        assert "entries" in d

    def test_empty_boundaries(self):
        table = analyse_handler_semantics(ExecutionTrace(), [])
        assert table.handler_count == 0


# ---------------------------------------------------------------------------
# HandlerSemantic / OpcodeTableEntry
# ---------------------------------------------------------------------------

class TestDataClasses:
    def test_handler_semantic_to_dict(self):
        s = HandlerSemantic(
            handler_address=0x6000,
            operation=VMOperation.ADD,
            confidence=0.8,
        )
        d = s.to_dict()
        assert d["operation"] == "vm_add"

    def test_opcode_table_entry_to_dict(self):
        s = HandlerSemantic(handler_address=0x6000, operation=VMOperation.XOR)
        e = OpcodeTableEntry(opcode=0x10, handler_address=0x6000, semantic=s)
        d = e.to_dict()
        assert d["opcode"] == "0x10"
        assert d["operation"] == "vm_xor"
