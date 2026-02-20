"""
Phase 10 — Tests for the built-in Unicorn-based trace engine.
"""

import pytest
import struct

# Skip entire module if unicorn is not installed
unicorn = pytest.importorskip("unicorn")


from dragonslayer.analysis.trace_engine import (
    TraceEngine,
    TraceConfig,
    UNICORN_AVAILABLE,
)
from dragonslayer.analysis.trace_ingestion import ExecutionTrace


# ---------------------------------------------------------------------------
# Helpers — minimal x86 / x64 shellcode
# ---------------------------------------------------------------------------

def _nop_shellcode_64(count: int = 5) -> bytes:
    """Generate *count* NOPs followed by RET (x86-64)."""
    return b"\x90" * count + b"\xC3"


def _simple_mov_shellcode_64() -> bytes:
    """
    mov rax, 0x42       ; 48 C7 C0 42 00 00 00
    mov rbx, rax        ; 48 89 C3
    ret                 ; C3
    """
    return b"\x48\xC7\xC0\x42\x00\x00\x00" + b"\x48\x89\xC3" + b"\xC3"


def _add_shellcode_64() -> bytes:
    """
    mov rax, 10         ; 48 C7 C0 0A 00 00 00
    mov rbx, 20         ; 48 C7 C3 14 00 00 00
    add rax, rbx        ; 48 01 D8
    ret                 ; C3
    """
    return (
        b"\x48\xC7\xC0\x0A\x00\x00\x00"  # mov rax, 10
        + b"\x48\xC7\xC3\x14\x00\x00\x00"  # mov rbx, 20
        + b"\x48\x01\xD8"                    # add rax, rbx
        + b"\xC3"                             # ret
    )


def _memory_write_shellcode_64() -> bytes:
    """
    mov rax, 0x500000    ; movabs rax, imm64 would be long, use mov eax
    mov dword ptr [rax], 0xDEAD  ; C7 00 AD DE 00 00
    ret
    """
    # mov eax, 0x500000  (sets rax due to zero-extend)
    # mov dword ptr [rax], 0xDEAD
    # ret
    return (
        b"\xB8\x00\x00\x50\x00"           # mov eax, 0x500000
        + b"\xC7\x00\xAD\xDE\x00\x00"     # mov dword [rax], 0xDEAD
        + b"\xC3"                           # ret
    )


def _nop_shellcode_32(count: int = 3) -> bytes:
    return b"\x90" * count + b"\xC3"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTraceEngineAvailability:
    def test_available(self):
        assert TraceEngine.available() is True

    def test_default_config(self):
        engine = TraceEngine(arch="x86_64")
        assert engine.config.max_instructions == 10_000


class TestTraceEngineBasic64:
    """Test trace production with x86-64 shellcode."""

    def test_nop_trace(self):
        engine = TraceEngine(arch="x86_64")
        code = _nop_shellcode_64(5)
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        assert isinstance(trace, ExecutionTrace)
        assert trace.source == "unicorn"
        assert len(trace.instructions) >= 5  # 5 NOPs + RET

    def test_nop_trace_addresses(self):
        engine = TraceEngine(arch="x86_64")
        code = _nop_shellcode_64(3)
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # First instruction at entry
        assert trace.instructions[0].address == 0x400000
        # NOPs are 1 byte each
        if len(trace.instructions) > 1:
            assert trace.instructions[1].address == 0x400001

    def test_register_capture(self):
        engine = TraceEngine(arch="x86_64")
        code = _simple_mov_shellcode_64()
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        assert len(trace.instructions) >= 2
        # Register state should be captured
        regs = trace.instructions[0].registers
        assert "rsp" in regs

    def test_mov_rax(self):
        engine = TraceEngine(arch="x86_64")
        code = _simple_mov_shellcode_64()
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # After mov rax, 0x42, the register state of the *next* instruction
        # should reflect rax == 0x42
        # The hook fires *before* execution, so we check the instruction after mov
        if len(trace.instructions) >= 2:
            # Second instruction is "mov rbx, rax", its register snapshot
            # is taken *before* it executes, so rax should be 0x42
            regs = trace.instructions[1].registers
            assert regs.get("rax", 0) == 0x42

    def test_add_result(self):
        engine = TraceEngine(arch="x86_64")
        code = _add_shellcode_64()
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # After both MOVs and ADD, the RET instruction snapshot should show rax=30
        if len(trace.instructions) >= 4:
            regs = trace.instructions[3].registers  # ret
            assert regs.get("rax", 0) == 30

    def test_max_insns_limit(self):
        engine = TraceEngine(arch="x86_64")
        # Infinite loop: jmp $
        code = b"\xEB\xFE"
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000, max_insns=50)
        assert len(trace.instructions) <= 51  # allow slight overshoot

    def test_memory_access_capture(self):
        engine = TraceEngine(arch="x86_64")
        code = _memory_write_shellcode_64()
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # Should have at least one write access
        writes = [m for m in trace.memory_accesses if m.type == "W"]
        assert len(writes) > 0

    def test_metadata(self):
        engine = TraceEngine(arch="x86_64")
        code = _nop_shellcode_64(2)
        trace = engine.trace(code, entry_va=0x401000, image_base=0x400000)
        assert trace.metadata["arch"] == "x86_64"
        assert trace.metadata["entry_va"] == 0x401000
        assert trace.metadata["image_base"] == 0x400000

    def test_initial_regs(self):
        engine = TraceEngine(arch="x86_64")
        code = b"\xC3"  # just ret
        trace = engine.trace(
            code, entry_va=0x400000, image_base=0x400000,
            initial_regs={"rax": 0x1234},
        )
        if trace.instructions:
            assert trace.instructions[0].registers.get("rax", 0) == 0x1234


class TestTraceEngineBasic32:
    """Test trace production with x86-32 shellcode."""

    def test_nop_trace_32(self):
        engine = TraceEngine(arch="x86")
        code = _nop_shellcode_32(3)
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        assert isinstance(trace, ExecutionTrace)
        assert len(trace.instructions) >= 3

    def test_registers_32(self):
        engine = TraceEngine(arch="x86")
        code = _nop_shellcode_32(1)
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        if trace.instructions:
            regs = trace.instructions[0].registers
            assert "esp" in regs


class TestTraceEngineConfig:
    """Test TraceConfig options."""

    def test_no_register_capture(self):
        cfg = TraceConfig(capture_registers=False)
        engine = TraceEngine(arch="x86_64", config=cfg)
        code = _nop_shellcode_64(2)
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        if trace.instructions:
            assert trace.instructions[0].registers == {}

    def test_no_memory_capture(self):
        cfg = TraceConfig(capture_memory=False)
        engine = TraceEngine(arch="x86_64", config=cfg)
        code = _memory_write_shellcode_64()
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # No memory hooks installed
        assert len(trace.memory_accesses) == 0

    def test_stop_address(self):
        # mov rax, 0x42 (7 bytes); nop (1 byte at +7); ret (+8)
        code = b"\x48\xC7\xC0\x42\x00\x00\x00" + b"\x90" + b"\xC3"
        stop_at = 0x400007  # stop at nop
        cfg = TraceConfig(stop_addresses=[stop_at])
        engine = TraceEngine(arch="x86_64", config=cfg)
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # Should have stopped at or before the NOP
        addrs = [i.address for i in trace.instructions]
        assert 0x400008 not in addrs  # RET should not be reached


class TestTraceEngineParsedBinary:
    """Test trace_parsed() integration with ParsedBinary."""

    def test_trace_parsed(self):
        from dragonslayer.analysis.binary_format import ParsedBinary, Section, BinaryFormat

        code = _nop_shellcode_64(3)
        pb = ParsedBinary(
            format=BinaryFormat.PE,
            image_base=0x400000,
            entry_point=0x401000,
            sections=[Section(
                name=".text",
                virtual_address=0x1000,
                virtual_size=len(code),
                raw_offset=0,
                raw_size=len(code),
                executable=True,
            )],
        )
        engine = TraceEngine(arch="x86_64")
        trace = engine.trace_parsed(pb, code)
        assert isinstance(trace, ExecutionTrace)
        assert trace.source == "unicorn"


class TestTraceToLiftedInstructions:
    """Verify the trace integrates with the existing pipeline."""

    def test_to_lifted(self):
        engine = TraceEngine(arch="x86_64")
        code = _simple_mov_shellcode_64()
        trace = engine.trace(code, entry_va=0x400000, image_base=0x400000)
        # to_lifted_instructions should not raise
        lifted = trace.to_lifted_instructions()
        assert isinstance(lifted, list)
        assert len(lifted) > 0
