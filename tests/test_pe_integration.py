"""
PE / Binary Integration Tests  (Batch 37)
==========================================

End-to-end tests that construct minimal PE binaries in memory, parse them
via :func:`parse_binary`, extract the ``.text`` section bytes, and run the
full pattern-recognition pipeline on them — exactly the path that
:meth:`Orchestrator._run_pattern_analysis` follows in production.

Test categories:
  1. PE construction + parsing round-trip
  2. Section extraction with embedded handler signatures
  3. Pattern recogniser on extracted bytes (raw hex path)
  4. Context-aware matcher on extracted bytes
  5. Orchestrator.analyze_binary() end-to-end
  6. Multi-section PEs (code + data + overlay)
  7. Edge cases: empty .text, non-PE magic, corrupt headers
"""

from __future__ import annotations

import struct
import pytest
from pathlib import Path
from typing import Dict, List, Optional

from dragonslayer.analysis.binary_format import (
    parse_binary,
    detect_format,
    BinaryFormat,
    ParsedBinary,
)
from dragonslayer.analysis.pattern_analysis.database import (
    Pattern,
    PatternDatabase,
)
from dragonslayer.analysis.pattern_analysis.recognizer import (
    PatternRecognizer,
    Match,
)
from dragonslayer.analysis.pattern_analysis.matcher import (
    PatternMatcher,
    MatchContext,
    RankedMatch,
)
from dragonslayer.core.orchestrator import Orchestrator


# ── PE stub builder ──────────────────────────────────────────────────

def _make_pe(
    *,
    text_payload: bytes = b"\xCC" * 0x200,
    extra_sections: list[tuple[bytes, int, bytes]] | None = None,
    image_base: int = 0x00400000,
    machine: int = 0x8664,  # AMD64 by default
) -> bytes:
    """Build a minimal PE with controllable *.text* content.

    Parameters
    ----------
    text_payload
        Raw bytes for the ``.text`` section.
    extra_sections
        ``[(name_8bytes, characteristics, payload), ...]``
    image_base
        PE ImageBase.
    machine
        COFF machine type (0x8664=AMD64, 0x14C=i386).
    """
    sections_meta: list[tuple[bytes, int, bytes]] = [
        (b".text\x00\x00\x00", 0x60000020, text_payload),
    ]
    if extra_sections:
        sections_meta.extend(extra_sections)

    num = len(sections_meta)
    pe_off = 0x80
    magic = 0x20B if machine == 0x8664 else 0x10B  # PE32+ vs PE32
    opt_size = 0x70 if magic == 0x20B else 0x60
    sec_table_off = pe_off + 24 + opt_size

    hdr_size = sec_table_off + num * 40
    # Align header to 0x200
    hdr_size = (hdr_size + 0x1FF) & ~0x1FF

    buf = bytearray(hdr_size)

    # DOS header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)

    # PE signature
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"

    # COFF header
    struct.pack_into("<H", buf, pe_off + 4, machine)
    struct.pack_into("<H", buf, pe_off + 6, num)
    struct.pack_into("<H", buf, pe_off + 20, opt_size)
    struct.pack_into("<H", buf, pe_off + 22, 0x22)  # Characteristics: executable

    # Optional header
    opt_start = pe_off + 24
    struct.pack_into("<H", buf, opt_start, magic)
    struct.pack_into("<I", buf, opt_start + 16, 0x1000)  # EP RVA
    if magic == 0x20B:
        struct.pack_into("<Q", buf, opt_start + 24, image_base)
    else:
        struct.pack_into("<I", buf, opt_start + 28, image_base)

    # Section table + raw data
    raw_offset = hdr_size
    for i, (name, chars, payload) in enumerate(sections_meta):
        off = sec_table_off + i * 40
        buf[off:off + 8] = name[:8].ljust(8, b"\x00")
        vsize = max(len(payload), 0x1000)
        struct.pack_into("<I", buf, off + 8, vsize)  # VirtualSize
        struct.pack_into("<I", buf, off + 12, 0x1000 * (i + 1))  # VirtualAddr
        raw_size = (len(payload) + 0x1FF) & ~0x1FF
        struct.pack_into("<I", buf, off + 16, raw_size)  # SizeOfRawData
        struct.pack_into("<I", buf, off + 20, raw_offset)  # PointerToRawData
        struct.pack_into("<I", buf, off + 36, chars)
        raw_offset += raw_size

    # Append section payloads (padded to 0x200 boundary)
    for _, _, payload in sections_meta:
        padded = payload + b"\x00" * ((0x200 - len(payload) % 0x200) % 0x200)
        buf.extend(padded)

    return bytes(buf)


# Known VMProtect-style byte sequences we'll embed in .text
_VMP_ADD64_BYTES = bytes.fromhex("488B4500480345084889450048836E0818")
_VMP_XOR64_BYTES = bytes.fromhex("488B4500483345084889450048836E0818")
_VMP_PUSH_BYTES  = bytes.fromhex("488B06488946004883EE08488B4500")
_VMP_JMP_BYTES   = bytes.fromhex("488B06480FB60E4801CE")

# Helper: build a .text section from multiple handler byte snippets
def _make_text_with_handlers(*handlers: bytes, gap: int = 16) -> bytes:
    """Concatenate handler byte snippets with INT3 gaps."""
    parts: list[bytes] = []
    for h in handlers:
        parts.append(h)
        parts.append(b"\xCC" * gap)
    payload = b"".join(parts)
    # Pad to at least 0x200
    if len(payload) < 0x200:
        payload += b"\xCC" * (0x200 - len(payload))
    return payload


# Helper pattern database with matching signatures
def _make_vmp_db() -> PatternDatabase:
    """Build a small PatternDatabase whose signatures match our embedded bytes."""
    db = PatternDatabase()
    db.add_pattern(Pattern(
        pattern_id="vmp_add64",
        name="VMP Add64",
        signature="48 8B 45 00 48 03 45 08 48 89 45 00",
        architecture="x64",
        handler_type="arithmetic",
        operation="vAdd64",
        confidence=0.92,
    ))
    db.add_pattern(Pattern(
        pattern_id="vmp_xor64",
        name="VMP Xor64",
        signature="48 8B 45 00 48 33 45 08 48 89 45 00",
        architecture="x64",
        handler_type="bitwise",
        operation="vXor64",
        confidence=0.91,
    ))
    db.add_pattern(Pattern(
        pattern_id="vmp_push",
        name="VMP Push",
        signature="48 8B 06 48 89 46 00 48 83 EE 08",
        architecture="x64",
        handler_type="stack",
        operation="vPush64",
        confidence=0.90,
    ))
    db.add_pattern(Pattern(
        pattern_id="vmp_jmp",
        name="VMP Jmp",
        signature="48 8B 06 48 0F B6 0E 48 01 CE",
        architecture="x64",
        handler_type="control_flow",
        operation="vJmp",
        confidence=0.88,
    ))
    return db


# =====================================================================
#  1. PE construction & parsing
# =====================================================================

class TestPEConstruction:
    """Verify our stub builder produces valid parseable PEs."""

    def test_format_detection(self):
        pe = _make_pe()
        assert detect_format(pe) == BinaryFormat.PE

    def test_parse_returns_parsed_binary(self):
        pe = _make_pe()
        pb = parse_binary(pe)
        assert isinstance(pb, ParsedBinary)

    def test_has_text_section(self):
        pe = _make_pe()
        pb = parse_binary(pe)
        names = [s.name for s in pb.sections]
        assert any(".text" in n for n in names)

    def test_executable_section_flag(self):
        pe = _make_pe()
        pb = parse_binary(pe)
        exec_secs = pb.executable_sections
        assert len(exec_secs) >= 1

    def test_x64_architecture(self):
        pe = _make_pe(machine=0x8664)
        pb = parse_binary(pe)
        arch = pb.architecture.value if hasattr(pb.architecture, 'value') else str(pb.architecture)
        assert arch.lower() in ("x64", "amd64", "x86_64")

    def test_x86_architecture(self):
        pe = _make_pe(machine=0x14C)
        pb = parse_binary(pe)
        arch = pb.architecture.value if hasattr(pb.architecture, 'value') else str(pb.architecture)
        assert arch.lower() in ("x86", "i386", "i686", "x86_32", "x32")

    def test_custom_image_base(self):
        pe = _make_pe(image_base=0x10000000)
        pb = parse_binary(pe)
        assert pb.image_base == 0x10000000


# =====================================================================
#  2. Section extraction with embedded handlers
# =====================================================================

class TestSectionExtraction:
    """Extract .text bytes and verify pattern bytes are present."""

    def test_text_payload_preserved(self):
        payload = _make_text_with_handlers(_VMP_ADD64_BYTES)
        pe = _make_pe(text_payload=payload)
        pb = parse_binary(pe)
        sections = pb.load_sections(pe)
        # Find the .text section data
        text_data = None
        for va, data in sections.items():
            text_data = data
            break
        assert text_data is not None
        assert _VMP_ADD64_BYTES in text_data

    def test_multiple_handlers_in_text(self):
        payload = _make_text_with_handlers(
            _VMP_ADD64_BYTES, _VMP_XOR64_BYTES, _VMP_PUSH_BYTES,
        )
        pe = _make_pe(text_payload=payload)
        pb = parse_binary(pe)
        sections = pb.load_sections(pe)
        text_data = next(iter(sections.values()))
        assert _VMP_ADD64_BYTES in text_data
        assert _VMP_XOR64_BYTES in text_data
        assert _VMP_PUSH_BYTES in text_data

    def test_multi_section_pe(self):
        payload = _make_text_with_handlers(_VMP_JMP_BYTES)
        pe = _make_pe(
            text_payload=payload,
            extra_sections=[
                (b".data\x00\x00\x00", 0xC0000040, b"\x00" * 0x100),
                (b".rdata\x00\x00", 0x40000040, b"\xAA" * 0x80),
            ],
        )
        pb = parse_binary(pe)
        assert len(pb.sections) >= 3


# =====================================================================
#  3. PatternRecognizer on extracted bytes
# =====================================================================

class TestRecognizerOnPEBytes:
    """PatternRecognizer.recognize() over hex-encoded .text bytes."""

    def test_recognize_add64_in_text(self):
        payload = _make_text_with_handlers(_VMP_ADD64_BYTES)
        pe = _make_pe(text_payload=payload)
        pb = parse_binary(pe)
        sections = pb.load_sections(pe)
        text_data = next(iter(sections.values()))

        hex_str = text_data.hex().upper()
        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.5)
        ops = {m.pattern.operation for m in matches}
        assert "vAdd64" in ops

    def test_recognize_multiple_handlers(self):
        payload = _make_text_with_handlers(
            _VMP_ADD64_BYTES, _VMP_XOR64_BYTES,
        )
        pe = _make_pe(text_payload=payload)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        hex_str = text_data.hex().upper()

        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.5)
        ops = {m.pattern.operation for m in matches}
        assert "vAdd64" in ops
        assert "vXor64" in ops

    def test_recognize_push(self):
        payload = _make_text_with_handlers(_VMP_PUSH_BYTES)
        pe = _make_pe(text_payload=payload)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        hex_str = text_data.hex().upper()

        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.5)
        ops = {m.pattern.operation for m in matches}
        assert "vPush64" in ops

    def test_no_match_when_no_handlers(self):
        pe = _make_pe(text_payload=b"\xCC" * 0x200)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        hex_str = text_data.hex().upper()

        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.7)
        assert len(matches) == 0


# =====================================================================
#  4. PatternMatcher (context-aware) on PE bytes
# =====================================================================

class TestMatcherOnPEBytes:
    """PatternMatcher.match() on hex-encoded PE .text bytes."""

    def test_match_with_context(self):
        payload = _make_text_with_handlers(_VMP_ADD64_BYTES)
        pe = _make_pe(text_payload=payload)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        hex_str = text_data.hex().upper()

        db = _make_vmp_db()
        matcher = PatternMatcher(db, use_yara=False)
        ctx = MatchContext(
            preceding_mnemonics=["add", "sub"],
            registers_read=["rax"],
        )
        results = matcher.match(hex_str, context=ctx, min_confidence=0.3)
        assert len(results) >= 1
        assert all(isinstance(r, RankedMatch) for r in results)

    def test_batch_match_sequence(self):
        handlers = [_VMP_ADD64_BYTES, _VMP_XOR64_BYTES, _VMP_PUSH_BYTES]
        hex_list = [h.hex().upper() for h in handlers]

        db = _make_vmp_db()
        matcher = PatternMatcher(db, use_yara=False)
        results = matcher.match_handler_sequence(hex_list, min_confidence=0.3)
        assert len(results) == 3
        # At least the first two should have matches
        ops_0 = {r.pattern.operation for r in results[0]}
        ops_1 = {r.pattern.operation for r in results[1]}
        assert "vAdd64" in ops_0
        assert "vXor64" in ops_1


# =====================================================================
#  5. Orchestrator.analyze_binary() end-to-end
# =====================================================================

class TestOrchestratorE2E:
    """End-to-end through Orchestrator.analyze_binary()."""

    def test_analyze_with_embedded_handlers(self):
        payload = _make_text_with_handlers(
            _VMP_ADD64_BYTES, _VMP_XOR64_BYTES, _VMP_PUSH_BYTES,
        )
        pe = _make_pe(text_payload=payload)

        orch = Orchestrator()
        result = orch.analyze_binary(pe, analysis_type="pattern_analysis")

        assert result.success is True
        # The pattern_analysis engine should have run
        pa_result = None
        for er in result.engine_results:
            if er.engine == "pattern_analysis":
                pa_result = er
                break
        assert pa_result is not None
        assert pa_result.success is True
        # Should find some matches (depends on DB loaded)
        assert "total_matches" in pa_result.data

    def test_analyze_empty_pe(self):
        pe = _make_pe(text_payload=b"\xCC" * 0x200)
        orch = Orchestrator()
        result = orch.analyze_binary(pe, analysis_type="pattern_analysis")
        assert result.success is True

    def test_analyze_returns_result_dict(self):
        pe = _make_pe(text_payload=_make_text_with_handlers(_VMP_ADD64_BYTES))
        orch = Orchestrator()
        result = orch.analyze_binary(pe, analysis_type="pattern_analysis")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "engine_results" in d or "engines" in d or "results" in d


# =====================================================================
#  6. Multi-section handling
# =====================================================================

class TestMultiSection:
    """PE with code + data + resource sections."""

    def test_only_exec_sections_scanned(self):
        text = _make_text_with_handlers(_VMP_ADD64_BYTES)
        # .data with same bytes but non-executable
        data_sec = (b".data\x00\x00\x00", 0xC0000040, _VMP_ADD64_BYTES + b"\x00" * 0x100)
        pe = _make_pe(text_payload=text, extra_sections=[data_sec])
        pb = parse_binary(pe)
        exec_secs = pb.executable_sections
        # Only .text should be executable
        names = [s.name for s in exec_secs]
        assert any(".text" in n for n in names)
        # .data should not be in executable sections
        for s in exec_secs:
            assert ".data" not in s.name

    def test_extract_only_code_sections(self):
        text = _make_text_with_handlers(_VMP_XOR64_BYTES)
        data_sec = (b".rdata\x00\x00", 0x40000040, b"\xAA" * 0x200)
        pe = _make_pe(text_payload=text, extra_sections=[data_sec])
        pb = parse_binary(pe)
        text_sections = [s for s in pb.sections if s.executable]
        assert len(text_sections) >= 1


# =====================================================================
#  7. Edge cases
# =====================================================================

class TestBinaryEdgeCases:
    """Edge cases for binary parsing and pattern matching."""

    def test_non_pe_format_detection(self):
        assert detect_format(b"NOTAPE" + b"\x00" * 100) == BinaryFormat.UNKNOWN

    def test_elf_detection(self):
        assert detect_format(b"\x7fELF" + b"\x00" * 100) == BinaryFormat.ELF

    def test_tiny_payload(self):
        pe = _make_pe(text_payload=b"\x90")  # single NOP
        pb = parse_binary(pe)
        assert pb is not None
        sections = pb.load_sections(pe)
        assert len(sections) >= 1

    def test_large_text_section(self):
        big = b"\xCC" * 0x10000 + _VMP_ADD64_BYTES + b"\xCC" * 0x100
        pe = _make_pe(text_payload=big)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        assert _VMP_ADD64_BYTES in text_data

    def test_handler_at_section_start(self):
        pe = _make_pe(text_payload=_VMP_PUSH_BYTES + b"\xCC" * 0x1E0)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        hex_str = text_data.hex().upper()
        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.5)
        assert any(m.pattern.operation == "vPush64" for m in matches)

    def test_handler_at_section_end(self):
        padding = b"\xCC" * (0x200 - len(_VMP_JMP_BYTES))
        pe = _make_pe(text_payload=padding + _VMP_JMP_BYTES)
        pb = parse_binary(pe)
        text_data = next(iter(pb.load_sections(pe).values()))
        hex_str = text_data.hex().upper()
        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.5)
        assert any(m.pattern.operation == "vJmp" for m in matches)


# =====================================================================
#  8. Hex-encoding path (same as orchestrator)
# =====================================================================

class TestHexEncodingPath:
    """Verify the .hex().upper() path used by the orchestrator."""

    def test_raw_bytes_to_hex_round_trip(self):
        payload = _VMP_ADD64_BYTES
        hex_str = payload.hex().upper()
        recovered = bytes.fromhex(hex_str)
        assert recovered == payload

    def test_hex_str_matches_pattern_recogniser(self):
        """Simulate the exact path: bytes → hex → recognize()."""
        payload = _make_text_with_handlers(_VMP_ADD64_BYTES, _VMP_XOR64_BYTES)
        hex_str = payload.hex().upper()

        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize(hex_str, min_confidence=0.5)
        ops = {m.pattern.operation for m in matches}
        assert "vAdd64" in ops

    def test_empty_hex(self):
        db = _make_vmp_db()
        recog = PatternRecognizer(db, use_yara=False)
        matches = recog.recognize("", min_confidence=0.5)
        assert matches == []
