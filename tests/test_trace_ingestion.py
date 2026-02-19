"""Tests for trace ingestion module."""

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceMemoryAccess,
    TraceControlFlow,
    HandlerMarker,
    parse_trace_text,
    from_shared_data,
    from_triton_result,
    from_angr_result,
    from_qiling_result,
)


# ---------------------------------------------------------------------------
# FORMAT.md text parser
# ---------------------------------------------------------------------------

class TestParseTraceText:
    SAMPLE = """\
# Sample trace
---
i: 0x401000 | 3 | 4801C0 | add rax, rax | rax=10,rbx=20
i: 0x401003 | 2 | 89C1 | mov ecx, eax |
m: R | 0x7FFE0000 | 4 | 0xDEADBEEF
m: W | 0x7FFE1000 | 8 | 0x123456
c: call | 0x401000 | 0x402000
c: ret  | 0x402010 | 0x401005
h: 0 | 0x500000 | arithmetic
h: 1 | 0x500100 | memory
---
"""

    def test_instructions(self):
        trace = parse_trace_text(self.SAMPLE)
        assert len(trace.instructions) == 2
        i0 = trace.instructions[0]
        assert i0.address == 0x401000
        assert i0.size == 3
        assert i0.raw_bytes == bytes.fromhex("4801C0")
        assert i0.disassembly == "add rax, rax"
        assert i0.registers == {"rax": 10, "rbx": 20}

    def test_memory(self):
        trace = parse_trace_text(self.SAMPLE)
        assert len(trace.memory_accesses) == 2
        assert trace.memory_accesses[0].type == "R"
        assert trace.memory_accesses[0].address == 0x7FFE0000
        assert trace.memory_accesses[1].type == "W"

    def test_control_flow(self):
        trace = parse_trace_text(self.SAMPLE)
        assert len(trace.control_flow) == 2
        assert trace.control_flow[0].type == "call"
        assert trace.control_flow[1].type == "ret"

    def test_handlers(self):
        trace = parse_trace_text(self.SAMPLE)
        assert len(trace.handlers) == 2
        assert trace.handlers[0].handler_type == "arithmetic"
        assert trace.handlers[1].address == 0x500100

    def test_source(self):
        trace = parse_trace_text(self.SAMPLE)
        assert trace.source == "file"

    def test_empty(self):
        trace = parse_trace_text("")
        assert len(trace.instructions) == 0

    def test_comments_and_delimiters_skipped(self):
        trace = parse_trace_text("# comment\n---\n")
        assert len(trace.instructions) == 0


# ---------------------------------------------------------------------------
# Dynamic plugin adapters
# ---------------------------------------------------------------------------

class TestFromTritonResult:
    def test_taint_flow_ingested(self):
        data = {
            "arch": "x86_64",
            "taint_flow": [
                {"address": 0x1000, "disasm": "mov rax, rbx", "tainted_reads": ["rbx"], "tainted_writes": ["rax"]},
                {"address": 0x1003, "disasm": "add rax, 1", "tainted_reads": ["rax"], "tainted_writes": ["rax"]},
            ],
            "path_constraints": ["(bvadd rax #x1)"],
            "tainted_registers_initial": ["rdi"],
        }
        trace = from_triton_result(data)
        assert trace.source == "triton"
        assert len(trace.instructions) == 2
        assert trace.instructions[0].address == 0x1000
        assert trace.metadata["arch"] == "x86_64"
        assert len(trace.metadata["path_constraints"]) == 1


class TestFromAngrResult:
    def test_functions_ingested(self):
        data = {
            "arch": "AMD64",
            "functions": [
                {"address": 0x401000, "name": "main", "block_count": 5},
                {"address": 0x401100, "name": "sub_401100", "block_count": 3},
            ],
            "handler_exploration": {
                "handler_details": [
                    {"dispatcher": 0x401000, "path_length": 10, "type": "arithmetic"},
                ],
            },
        }
        trace = from_angr_result(data)
        assert trace.source == "angr"
        assert len(trace.instructions) == 2
        assert len(trace.handlers) == 1
        assert trace.handlers[0].handler_type == "arithmetic"


class TestFromQilingResult:
    def test_blocks_ingested(self):
        data = {
            "executed_blocks": [
                {"start": 0x401000, "end": 0x401010},
                {"start": 0x401020, "end": 0x401030},
            ],
        }
        trace = from_qiling_result(data)
        assert trace.source == "qiling"
        assert len(trace.instructions) == 2
        assert trace.instructions[0].size == 0x10


class TestFromSharedData:
    def test_merges_all_sources(self):
        shared = {
            "triton": {
                "taint_flow": [{"address": 0x1000, "disasm": "nop"}],
            },
            "angr": {
                "functions": [{"address": 0x2000, "name": "fn"}],
            },
            "qiling": {
                "executed_blocks": [{"start": 0x3000, "end": 0x3010}],
            },
            "vm_discovery": {
                "protector": "VMProtect",
                "dispatcher_addresses": [0x5000],
            },
        }
        trace = from_shared_data(shared)
        assert len(trace.instructions) == 3
        assert "triton" in trace.source
        assert "angr" in trace.source
        assert "qiling" in trace.source
        assert trace.metadata["protector"] == "VMProtect"

    def test_empty_shared_data(self):
        trace = from_shared_data({})
        assert len(trace.instructions) == 0


# ---------------------------------------------------------------------------
# ExecutionTrace helpers
# ---------------------------------------------------------------------------

class TestExecutionTrace:
    def test_unique_addresses(self):
        trace = ExecutionTrace(instructions=[
            TraceInstruction(address=0x1000, size=2, raw_bytes=b"\x90\x90", disassembly="nop"),
            TraceInstruction(address=0x1002, size=1, raw_bytes=b"\xCC", disassembly="int3"),
        ])
        assert trace.unique_addresses() == {0x1000, 0x1002}

    def test_extract_code_regions_contiguous(self):
        trace = ExecutionTrace(instructions=[
            TraceInstruction(address=0x1000, size=2, raw_bytes=b"\x90\x90", disassembly="nop"),
            TraceInstruction(address=0x1002, size=1, raw_bytes=b"\xCC", disassembly="int3"),
        ])
        regions = trace.extract_code_regions()
        assert 0x1000 in regions
        assert regions[0x1000] == b"\x90\x90\xCC"

    def test_extract_code_regions_gap(self):
        trace = ExecutionTrace(instructions=[
            TraceInstruction(address=0x1000, size=1, raw_bytes=b"\x90", disassembly="nop"),
            TraceInstruction(address=0x2000, size=1, raw_bytes=b"\xCC", disassembly="int3"),
        ])
        regions = trace.extract_code_regions()
        assert len(regions) == 2

    def test_to_dict(self):
        trace = ExecutionTrace(source="test")
        d = trace.to_dict()
        assert d["source"] == "test"
        assert d["instruction_count"] == 0

    def test_to_lifted_instructions(self):
        trace = ExecutionTrace(instructions=[
            TraceInstruction(address=0x1000, size=3, raw_bytes=b"\x48\x01\xC0", disassembly="add rax, rax"),
        ])
        # Should not crash regardless of capstone availability
        result = trace.to_lifted_instructions()
        assert len(result) >= 1
        assert result[0].address == 0x1000
