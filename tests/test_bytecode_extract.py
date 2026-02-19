"""Tests for VM bytecode extraction."""

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceMemoryAccess,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)
from dragonslayer.analysis.bytecode_extract import (
    extract_bytecode,
    BytecodeStream,
    OpcodeMap,
    VMOpcode,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _boundaries_with_mem(
    vip_values: list[int],
    handler_addrs: list[int],
    deltas: list[int],
    categories: list[str] | None = None,
) -> list[HandlerBoundary]:
    cats = categories or [""] * len(vip_values)
    return [
        HandlerBoundary(
            vip_value=v, handler_address=h, trace_start=i * 10,
            trace_end=(i + 1) * 10, instruction_count=10,
            vip_delta=d, category=c,
        )
        for i, (v, h, d, c) in enumerate(zip(vip_values, handler_addrs, deltas, cats))
    ]


def _mem_reads(reads: list[tuple[int, int, int]]) -> list[TraceMemoryAccess]:
    """(address, size, value) → TraceMemoryAccess list."""
    return [
        TraceMemoryAccess(type="R", address=a, size=s, value=v)
        for a, s, v in reads
    ]


# ---------------------------------------------------------------------------
# extract_bytecode with memory reads
# ---------------------------------------------------------------------------

class TestExtractBytecodeWithMemory:
    def test_basic_extraction(self):
        boundaries = _boundaries_with_mem(
            vip_values=[0x1000, 0x1004, 0x1008],
            handler_addrs=[0x6000, 0x7000, 0x8000],
            deltas=[4, 4, 4],
        )
        # Simulate VM fetching opcode bytes at vIP addresses.
        mem = _mem_reads([
            (0x1000, 4, 0x03020100),  # bytes at 0x1000: 00 01 02 03
            (0x1004, 4, 0x07060504),  # bytes at 0x1004: 04 05 06 07
            (0x1008, 4, 0x0B0A0908),  # bytes at 0x1008: 08 09 0A 0B
        ])
        trace = ExecutionTrace(memory_accesses=mem)
        stream = extract_bytecode(trace, boundaries)

        assert stream.base_address == 0x1000
        assert stream.length == 12  # 0x1000..0x100B
        assert stream.opcode_count == 3
        assert stream.vip_direction == 1

    def test_opcode_values(self):
        boundaries = _boundaries_with_mem(
            vip_values=[0x100, 0x102],
            handler_addrs=[0x6000, 0x7000],
            deltas=[2, 2],
        )
        mem = _mem_reads([
            (0x100, 1, 0xAA),
            (0x101, 1, 0xBB),
            (0x102, 1, 0xCC),
            (0x103, 1, 0xDD),
        ])
        trace = ExecutionTrace(memory_accesses=mem)
        stream = extract_bytecode(trace, boundaries)

        assert stream.opcodes[0].value == 0xAA
        assert stream.opcodes[0].operand_bytes == bytes([0xBB])
        assert stream.opcodes[1].value == 0xCC

    def test_opcode_map_built(self):
        boundaries = _boundaries_with_mem(
            vip_values=[0x100, 0x101],
            handler_addrs=[0x6000, 0x7000],
            deltas=[1, 1],
            categories=["arithmetic", "memory"],
        )
        mem = _mem_reads([(0x100, 1, 0x10), (0x101, 1, 0x20)])
        trace = ExecutionTrace(memory_accesses=mem)
        stream = extract_bytecode(trace, boundaries)

        entry = stream.opcode_map.handler_for(0x10)
        assert entry is not None
        assert entry[0] == 0x6000
        assert entry[1] == "arithmetic"

    def test_gaps_detected(self):
        boundaries = _boundaries_with_mem(
            vip_values=[0x100, 0x110],  # big gap between
            handler_addrs=[0x6000, 0x7000],
            deltas=[1, 1],
        )
        mem = _mem_reads([(0x100, 1, 0xAA), (0x110, 1, 0xBB)])
        trace = ExecutionTrace(memory_accesses=mem)
        stream = extract_bytecode(trace, boundaries)

        assert len(stream.gaps) >= 1
        assert stream.length == 17  # 0x100..0x110

    def test_descending_vip(self):
        boundaries = _boundaries_with_mem(
            vip_values=[0x108, 0x104, 0x100],
            handler_addrs=[0x6000, 0x7000, 0x8000],
            deltas=[-4, -4, -4],
        )
        mem = _mem_reads([
            (0x108, 1, 0xAA),
            (0x104, 1, 0xBB),
            (0x100, 1, 0xCC),
        ])
        trace = ExecutionTrace(memory_accesses=mem)
        stream = extract_bytecode(trace, boundaries)
        assert stream.vip_direction == -1


# ---------------------------------------------------------------------------
# extract_bytecode without memory reads (boundary-only fallback)
# ---------------------------------------------------------------------------

class TestExtractBytecodeNoMemory:
    def test_synthetic_opcodes(self):
        boundaries = _boundaries_with_mem(
            vip_values=[0x100, 0x104, 0x108],
            handler_addrs=[0x6000, 0x7000, 0x6000],  # third reuses first handler
            deltas=[4, 4, 4],
        )
        trace = ExecutionTrace()  # no memory accesses
        stream = extract_bytecode(trace, boundaries)

        assert stream.opcode_count == 3
        # First and third opcodes should have same value (same handler).
        assert stream.opcodes[0].value == stream.opcodes[2].value
        assert stream.opcodes[0].value != stream.opcodes[1].value

    def test_empty_boundaries(self):
        stream = extract_bytecode(ExecutionTrace(), [])
        assert stream.length == 0
        assert stream.opcode_count == 0


# ---------------------------------------------------------------------------
# OpcodeMap
# ---------------------------------------------------------------------------

class TestOpcodeMap:
    def test_add_and_lookup(self):
        m = OpcodeMap()
        m.add(0x10, 0x6000, "arithmetic")
        assert m.handler_for(0x10) == (0x6000, "arithmetic")
        assert m.handler_for(0xFF) is None

    def test_duplicate_opcode_keeps_first(self):
        m = OpcodeMap()
        m.add(0x10, 0x6000, "arithmetic")
        m.add(0x10, 0x7000, "memory")  # different handler, same opcode
        assert m.handler_for(0x10) == (0x6000, "arithmetic")

    def test_to_dict(self):
        m = OpcodeMap()
        m.add(0x10, 0x6000, "arithmetic")
        d = m.to_dict()
        assert "0x10" in d
        assert d["0x10"]["handler"] == "0x6000"


# ---------------------------------------------------------------------------
# BytecodeStream
# ---------------------------------------------------------------------------

class TestBytecodeStream:
    def test_to_dict(self):
        stream = BytecodeStream(
            base_address=0x100,
            raw_bytes=b"\xAA\xBB",
            opcodes=[VMOpcode(offset=0, value=0xAA, handler_address=0x6000)],
        )
        d = stream.to_dict()
        assert d["base_address"] == "0x100"
        assert d["length"] == 2
        assert d["opcode_count"] == 1

    def test_opcode_at(self):
        op = VMOpcode(offset=5, value=0x42)
        stream = BytecodeStream(opcodes=[op])
        assert stream.opcode_at(5) is op
        assert stream.opcode_at(0) is None


# ---------------------------------------------------------------------------
# VMOpcode
# ---------------------------------------------------------------------------

class TestVMOpcode:
    def test_to_dict(self):
        op = VMOpcode(
            offset=0, value=0xAA, size=1, handler_address=0x6000,
            handler_category="arithmetic", operand_bytes=b"\x01\x02",
            vip_value=0x100,
        )
        d = op.to_dict()
        assert d["value"] == "0xaa"
        assert d["operand_size"] == 2
