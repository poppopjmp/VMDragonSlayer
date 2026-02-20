"""Tests for Batch 3 – bytecode extraction reads real bytes via ParsedBinary.

Verifies that ``extract_bytecode()`` and ``_build_from_boundaries_only()``
use ``parsed_binary.read_va()`` to read real opcode + operand bytes from
the binary instead of fabricating synthetic sequential opcodes.
"""

import types
from typing import Optional

import pytest

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceMemoryAccess,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)
from dragonslayer.analysis.bytecode_extract import (
    _build_from_boundaries_only,
    extract_bytecode,
    BytecodeStream,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_boundary(vip, handler, delta, category=""):
    return HandlerBoundary(
        vip_value=vip,
        handler_address=handler,
        trace_start=0,
        trace_end=10,
        instruction_count=10,
        vip_delta=delta,
        category=category,
    )


class FakeParsedBinary:
    """Minimal mock that simulates ``ParsedBinary.read_va()``.

    *mapping*: base_va -> bytes.  Supports reads at any offset within the
    mapped range (like a real binary with contiguous sections).
    """

    def __init__(self, mapping: dict[int, bytes]):
        self._mapping = mapping

    def read_va(self, data: bytes, va: int, size: int) -> Optional[bytes]:
        # Direct hit.
        if va in self._mapping:
            chunk = self._mapping[va]
            return chunk[:size] if len(chunk) >= size else chunk

        # Check if *va* falls inside a mapped region.
        for base, content in self._mapping.items():
            if base <= va < base + len(content):
                offset = va - base
                remaining = content[offset:]
                return remaining[:size] if len(remaining) >= size else remaining
        return None


class FailingParsedBinary:
    """Always raises from read_va – used to test exception handling."""

    def read_va(self, data: bytes, va: int, size: int) -> Optional[bytes]:
        raise RuntimeError("read_va exploded")


# ---------------------------------------------------------------------------
# _build_from_boundaries_only – real byte reading
# ---------------------------------------------------------------------------


class TestBuildFromBoundariesRealBytes:
    """When parsed_binary and binary_data are supplied, opcodes
    should use real bytes from the binary."""

    def test_real_opcode_and_operands(self):
        boundaries = [
            _make_boundary(vip=0x1000, handler=0x6000, delta=3),
            _make_boundary(vip=0x1003, handler=0x7000, delta=3),
        ]
        binary = FakeParsedBinary({
            0x1000: bytes([0xAA, 0xBB, 0xCC]),
            0x1003: bytes([0xDD, 0xEE, 0xFF]),
        })
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x1000, bytecode_width=3,
            parsed_binary=binary, binary_data=b"ignored",
        )
        assert stream.opcodes[0].value == 0xAA
        assert stream.opcodes[0].operand_bytes == bytes([0xBB, 0xCC])
        assert stream.opcodes[1].value == 0xDD
        assert stream.opcodes[1].operand_bytes == bytes([0xEE, 0xFF])

    def test_real_bytes_in_raw_stream(self):
        """The raw_bytes stream should contain real opcode + operand bytes."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=2),
        ]
        binary = FakeParsedBinary({0x100: bytes([0x42, 0x99])})
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x100, bytecode_width=2,
            parsed_binary=binary, binary_data=b"",
        )
        assert stream.raw_bytes[0] == 0x42
        assert stream.raw_bytes[1] == 0x99

    def test_same_handler_different_real_opcodes(self):
        """Two boundaries with the same handler address should get
        independent real byte values (not forced to match)."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=1),
            _make_boundary(vip=0x101, handler=0x6000, delta=1),  # same handler
        ]
        binary = FakeParsedBinary({
            0x100: bytes([0x11]),
            0x101: bytes([0x22]),
        })
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x100, bytecode_width=1,
            parsed_binary=binary, binary_data=b"",
        )
        # Real opcodes should be different even though handler is the same.
        assert stream.opcodes[0].value == 0x11
        assert stream.opcodes[1].value == 0x22

    def test_fallback_when_read_va_returns_none(self):
        """If read_va returns None for an address, fall back to synthetic."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=1),
            _make_boundary(vip=0x101, handler=0x7000, delta=1),
        ]
        binary = FakeParsedBinary({
            0x100: bytes([0xAA]),
            # 0x101 is NOT in the mapping → read_va returns None
        })
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x100, bytecode_width=1,
            parsed_binary=binary, binary_data=b"",
        )
        # First opcode should be real.
        assert stream.opcodes[0].value == 0xAA
        # Second should be synthetic (sequential from 0).
        assert isinstance(stream.opcodes[1].value, int)

    def test_fallback_when_read_va_raises(self):
        """If read_va raises, fall back to synthetic gracefully."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=1),
        ]
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x100, bytecode_width=1,
            parsed_binary=FailingParsedBinary(), binary_data=b"",
        )
        assert stream.opcodes[0].value == 0  # synthetic first opcode

    def test_fallback_when_no_parsed_binary(self):
        """Without parsed_binary, behaviour is identical to original."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=2),
            _make_boundary(vip=0x102, handler=0x7000, delta=2),
            _make_boundary(vip=0x104, handler=0x6000, delta=2),  # reuses handler
        ]
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x100, bytecode_width=2,
        )
        # Synthetic: first and third have same handler → same opcode.
        assert stream.opcodes[0].value == stream.opcodes[2].value
        assert stream.opcodes[0].value != stream.opcodes[1].value
        # Operand bytes should be zero-filled.
        assert stream.opcodes[0].operand_bytes == b"\x00"

    def test_partial_read_falls_back(self):
        """If read_va returns fewer bytes than requested, fall back."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=4),
        ]
        binary = FakeParsedBinary({0x100: bytes([0xAA, 0xBB])})  # only 2 bytes, need 4
        stream = _build_from_boundaries_only(
            boundaries, direction=1, base=0x100, bytecode_width=4,
            parsed_binary=binary, binary_data=b"",
        )
        # Partial: 2 bytes < 4 width → falls back to synthetic.
        assert stream.opcodes[0].value == 0  # synthetic
        assert stream.opcodes[0].operand_bytes == b"\x00\x00\x00"


# ---------------------------------------------------------------------------
# extract_bytecode – binary supplementation of sparse trace memory
# ---------------------------------------------------------------------------


class TestExtractBytecodeWithBinary:
    """When trace memory is sparse, the binary should fill gaps."""

    def test_binary_supplements_missing_trace_memory(self):
        """Bytes missing from trace memory_accesses are read from binary."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=2),
            _make_boundary(vip=0x102, handler=0x7000, delta=2),
        ]
        # Trace only has data for 0x100; 0x101, 0x102, 0x103 are missing.
        mem = [TraceMemoryAccess(type="R", address=0x100, size=1, value=0xAA)]
        trace = ExecutionTrace(memory_accesses=mem)

        binary = FakeParsedBinary({
            0x101: bytes([0xBB]),
            0x102: bytes([0xCC]),
            0x103: bytes([0xDD]),
        })
        stream = extract_bytecode(
            trace, boundaries,
            parsed_binary=binary, binary_data=b"",
        )
        # 0x100 from trace, 0x101-0x103 from binary.
        assert stream.opcodes[0].value == 0xAA
        assert stream.opcodes[0].operand_bytes == bytes([0xBB])
        assert stream.opcodes[1].value == 0xCC
        assert stream.opcodes[1].operand_bytes == bytes([0xDD])

    def test_trace_memory_takes_precedence_over_binary(self):
        """When both trace and binary have data for an address,
        trace data wins."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=1),
        ]
        # Trace says byte is 0xAA, binary says 0xFF.
        mem = [TraceMemoryAccess(type="R", address=0x100, size=1, value=0xAA)]
        trace = ExecutionTrace(memory_accesses=mem)
        binary = FakeParsedBinary({0x100: bytes([0xFF])})

        stream = extract_bytecode(
            trace, boundaries,
            parsed_binary=binary, binary_data=b"",
        )
        assert stream.opcodes[0].value == 0xAA  # trace wins

    def test_no_binary_still_works(self):
        """extract_bytecode works without parsed_binary (backward compat)."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=1),
        ]
        mem = [TraceMemoryAccess(type="R", address=0x100, size=1, value=0x42)]
        trace = ExecutionTrace(memory_accesses=mem)
        stream = extract_bytecode(trace, boundaries)
        assert stream.opcodes[0].value == 0x42

    def test_empty_trace_with_binary_fallback(self):
        """When trace has no memory, fallback to _build_from_boundaries_only
        should pass parsed_binary through for real byte reading."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=2),
        ]
        trace = ExecutionTrace()  # no memory accesses
        binary = FakeParsedBinary({0x100: bytes([0xAB, 0xCD])})

        stream = extract_bytecode(
            trace, boundaries,
            parsed_binary=binary, binary_data=b"",
        )
        assert stream.opcodes[0].value == 0xAB
        assert stream.opcodes[0].operand_bytes == bytes([0xCD])

    def test_binary_supplement_exception_ignored(self):
        """If binary.read_va raises during supplementation, it's ignored."""
        boundaries = [
            _make_boundary(vip=0x100, handler=0x6000, delta=2),
        ]
        # Have trace data for 0x100 but not 0x101.
        mem = [TraceMemoryAccess(type="R", address=0x100, size=1, value=0xAA)]
        trace = ExecutionTrace(memory_accesses=mem)

        stream = extract_bytecode(
            trace, boundaries,
            parsed_binary=FailingParsedBinary(), binary_data=b"nope",
        )
        # Should still succeed; 0x101 just won't have data from binary.
        assert stream.opcodes[0].value == 0xAA

    def test_descending_vip_with_binary(self):
        """Binary reads work correctly with descending vIP direction."""
        boundaries = [
            _make_boundary(vip=0x108, handler=0x6000, delta=-4),
            _make_boundary(vip=0x104, handler=0x7000, delta=-4),
        ]
        trace = ExecutionTrace()
        binary = FakeParsedBinary({
            0x108: bytes([0xAA, 0xBB, 0xCC, 0xDD]),
            0x104: bytes([0xEE, 0xFF, 0x11, 0x22]),
        })
        stream = extract_bytecode(
            trace, boundaries,
            parsed_binary=binary, binary_data=b"",
        )
        assert stream.vip_direction == -1
        assert stream.opcodes[0].value == 0xAA
        assert stream.opcodes[1].value == 0xEE
