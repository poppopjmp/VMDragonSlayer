"""Tests for the shared binary format parser."""

import struct
import pytest

from dragonslayer.analysis.binary_format import (
    ParsedBinary,
    Section,
    BinaryFormat,
    Architecture,
    parse_binary,
    detect_format,
    _calculate_entropy,
    LIEF_AVAILABLE,
)


# ---------------------------------------------------------------------------
# Helpers — build minimal PE / ELF stubs
# ---------------------------------------------------------------------------

def _make_pe_stub(
    *,
    sections: list[tuple[bytes, int]] | None = None,
    image_base: int = 0x00400000,
) -> bytes:
    """Build a minimal PE32 stub with given sections.

    *sections* is a list of ``(name_bytes, characteristics)`` tuples.
    """
    if sections is None:
        sections = [(b".text\x00\x00\x00", 0x60000020)]  # exec+read+code

    num_sections = len(sections)
    pe_offset = 0x80  # typical real offset
    opt_hdr_size = 0x60  # minimal PE32 optional header
    section_table_off = pe_offset + 24 + opt_hdr_size

    # Build the buffer big enough
    total_size = section_table_off + num_sections * 40 + 512  # headroom
    buf = bytearray(total_size)

    # DOS header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_offset)

    # PE signature
    buf[pe_offset:pe_offset + 4] = b"PE\x00\x00"

    # COFF header
    struct.pack_into("<H", buf, pe_offset + 4, 0x14C)  # Machine: i386
    struct.pack_into("<H", buf, pe_offset + 6, num_sections)
    struct.pack_into("<H", buf, pe_offset + 20, opt_hdr_size)

    # Minimal Optional Header (PE32)
    struct.pack_into("<H", buf, pe_offset + 24, 0x10B)  # Magic: PE32
    struct.pack_into("<I", buf, pe_offset + 24 + 16, 0x1000)  # EntryPoint RVA
    struct.pack_into("<I", buf, pe_offset + 24 + 28, image_base)  # ImageBase

    # Section table
    raw_offset = total_size  # sections start after headers
    for i, (name, chars) in enumerate(sections):
        off = section_table_off + i * 40
        buf[off:off + 8] = name[:8].ljust(8, b"\x00")
        struct.pack_into("<I", buf, off + 8, 0x1000)  # VirtualSize
        struct.pack_into("<I", buf, off + 12, 0x1000 * (i + 1))  # VirtualAddr
        struct.pack_into("<I", buf, off + 16, 0x200)  # RawSize
        struct.pack_into("<I", buf, off + 20, raw_offset + i * 0x200)  # RawOffset
        struct.pack_into("<I", buf, off + 36, chars)

    # Append raw section data
    buf += b"\xCC" * (0x200 * num_sections)

    return bytes(buf)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDetectFormat:
    def test_pe(self):
        assert detect_format(b"MZ" + b"\x00" * 100) == BinaryFormat.PE

    def test_elf(self):
        assert detect_format(b"\x7fELF" + b"\x00" * 100) == BinaryFormat.ELF

    def test_unknown(self):
        assert detect_format(b"\x00" * 100) == BinaryFormat.UNKNOWN


class TestEntropy:
    def test_zeroes(self):
        assert _calculate_entropy(b"\x00" * 256) == 0.0

    def test_uniform(self):
        data = bytes(range(256))
        ent = _calculate_entropy(data)
        assert 7.9 < ent <= 8.0  # near-maximum entropy

    def test_empty(self):
        assert _calculate_entropy(b"") == 0.0


class TestParseBinary:
    def test_pe_sections(self):
        pe = _make_pe_stub(sections=[
            (b".text\x00\x00\x00", 0x60000020),
            (b".data\x00\x00\x00", 0xC0000040),
        ])
        parsed = parse_binary(pe)
        assert parsed.format == BinaryFormat.PE
        assert len(parsed.sections) == 2
        assert parsed.sections[0].name.startswith(".text")
        assert parsed.sections[0].executable is True
        assert parsed.sections[1].name.startswith(".data")
        assert parsed.sections[1].writable is True

    def test_pe_image_base(self):
        pe = _make_pe_stub(image_base=0x10000000)
        parsed = parse_binary(pe)
        assert parsed.image_base == 0x10000000

    def test_pe_architecture(self):
        pe = _make_pe_stub()
        parsed = parse_binary(pe)
        assert parsed.architecture == Architecture.X86

    def test_unknown_format(self):
        parsed = parse_binary(b"\x00" * 100)
        assert parsed.format == BinaryFormat.UNKNOWN
        assert len(parsed.sections) == 0

    def test_executable_ranges_fallback(self):
        """Unknown format: executable_ranges = entire binary."""
        parsed = parse_binary(b"\x00" * 50)
        assert parsed.executable_ranges() == [(0, 50)]

    def test_executable_ranges_pe(self):
        pe = _make_pe_stub(sections=[
            (b".text\x00\x00\x00", 0x60000020),  # exec
            (b".data\x00\x00\x00", 0xC0000040),  # not exec
        ])
        parsed = parse_binary(pe)
        ranges = parsed.executable_ranges()
        assert len(ranges) == 1  # only .text


class TestParsedBinaryHelpers:
    def test_to_dict(self):
        pe = _make_pe_stub()
        d = parse_binary(pe).to_dict()
        assert d["format"] == "PE"
        assert isinstance(d["sections"], list)

    def test_section_containing(self):
        pe = _make_pe_stub()
        parsed = parse_binary(pe)
        sec = parsed.sections[0]
        found = parsed.section_containing(sec.raw_offset + 1)
        assert found is not None
        assert found.name == sec.name
