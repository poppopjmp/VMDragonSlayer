"""
Shared Binary Format Parser
============================

Provides a unified :class:`ParsedBinary` view over PE, ELF and Mach-O
files using `LIEF <https://lief-project.github.io/>`_ when available,
with a lightweight ``struct``-based fallback for PE/ELF.

Usage::

    from dragonslayer.analysis.binary_format import parse_binary

    parsed = parse_binary(raw_bytes)
    for sec in parsed.sections:
        print(sec.name, sec.executable, sec.entropy)
"""

from __future__ import annotations

import logging
import math
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional LIEF import
# ---------------------------------------------------------------------------
try:
    import lief  # type: ignore[import-untyped]

    LIEF_AVAILABLE = True
except ImportError:
    lief = None  # type: ignore[assignment]
    LIEF_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class BinaryFormat(Enum):
    PE = "PE"
    ELF = "ELF"
    MACHO = "MACHO"
    UNKNOWN = "UNKNOWN"


class Architecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


@dataclass
class Section:
    """One section of a parsed binary."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int = 0
    entropy: float = 0.0
    executable: bool = False
    writable: bool = False
    readable: bool = True

    def file_range(self) -> Tuple[int, int]:
        """Return ``(raw_offset, raw_offset + raw_size)``."""
        return (self.raw_offset, self.raw_offset + self.raw_size)


@dataclass
class ImportEntry:
    """One imported function."""
    library: str
    name: str
    ordinal: Optional[int] = None


@dataclass
class ExportEntry:
    """One exported symbol."""
    name: str
    address: int
    ordinal: int = 0


@dataclass
class ParsedBinary:
    """Format-agnostic view of a binary file."""
    format: BinaryFormat = BinaryFormat.UNKNOWN
    architecture: Architecture = Architecture.UNKNOWN
    image_base: int = 0
    entry_point: int = 0
    sections: List[Section] = field(default_factory=list)
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)
    raw_size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    # -- convenience helpers ------------------------------------------------

    @property
    def executable_sections(self) -> List[Section]:
        """Sections with the executable flag set."""
        return [s for s in self.sections if s.executable]

    @property
    def writable_sections(self) -> List[Section]:
        return [s for s in self.sections if s.writable]

    def executable_ranges(self) -> List[Tuple[int, int]]:
        """File-offset ranges of executable sections.

        Falls back to ``[(0, raw_size)]`` when no sections have the exec flag.
        """
        ranges = [s.file_range() for s in self.executable_sections]
        return ranges if ranges else [(0, self.raw_size)]

    def section_containing(self, file_offset: int) -> Optional[Section]:
        """Return the section that contains *file_offset*, or ``None``."""
        for sec in self.sections:
            start, end = sec.file_range()
            if start <= file_offset < end:
                return sec
        return None

    def section_at_va(self, va: int) -> Optional[Section]:
        """Return the section containing virtual address *va*, or ``None``."""
        rva = va - self.image_base
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(sec.virtual_size, sec.raw_size):
                return sec
        return None

    def va_to_offset(self, va: int) -> Optional[int]:
        """Convert a virtual address to a file offset, or ``None``."""
        sec = self.section_at_va(va)
        if sec is None:
            return None
        rva = va - self.image_base
        return sec.raw_offset + (rva - sec.virtual_address)

    def offset_to_va(self, offset: int) -> Optional[int]:
        """Convert a file offset to a virtual address, or ``None``."""
        sec = self.section_containing(offset)
        if sec is None:
            return None
        return self.image_base + sec.virtual_address + (offset - sec.raw_offset)

    def load_sections(self, data: bytes) -> Dict[int, bytes]:
        """Map each section into a dict keyed by virtual address.

        Returns ``{va: section_bytes}`` for each section whose raw data
        is present in *data*.
        """
        loaded: Dict[int, bytes] = {}
        for sec in self.sections:
            start = sec.raw_offset
            end = start + sec.raw_size
            if start < len(data) and sec.raw_size > 0:
                sec_data = data[start:min(end, len(data))]
                va = self.image_base + sec.virtual_address
                loaded[va] = sec_data
        return loaded

    def read_va(self, data: bytes, va: int, size: int) -> Optional[bytes]:
        """Read *size* bytes from the binary at virtual address *va*.

        *data* is the full raw binary content.  Returns ``None`` if the
        address does not map to a valid file offset.
        """
        off = self.va_to_offset(va)
        if off is None or off < 0 or off + size > len(data):
            return None
        return data[off:off + size]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format.value,
            "architecture": self.architecture.value,
            "image_base": self.image_base,
            "entry_point": self.entry_point,
            "sections": [
                {
                    "name": s.name,
                    "virtual_address": s.virtual_address,
                    "virtual_size": s.virtual_size,
                    "raw_offset": s.raw_offset,
                    "raw_size": s.raw_size,
                    "entropy": round(s.entropy, 4),
                    "executable": s.executable,
                    "writable": s.writable,
                }
                for s in self.sections
            ],
            "imports_count": len(self.imports),
            "exports_count": len(self.exports),
            "raw_size": self.raw_size,
        }


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq if c > 0
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_binary(data: bytes) -> ParsedBinary:
    """Parse *data* and return a :class:`ParsedBinary`.

    Uses LIEF when available, otherwise a lightweight struct-based parser
    for PE and ELF.
    """
    if LIEF_AVAILABLE:
        return _parse_with_lief(data)
    return _parse_with_struct(data)


def detect_format(data: bytes) -> BinaryFormat:
    """Detect the binary format from magic bytes."""
    if len(data) >= 2 and data[:2] == b"MZ":
        return BinaryFormat.PE
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return BinaryFormat.ELF
    if len(data) >= 4 and data[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return BinaryFormat.MACHO
    return BinaryFormat.UNKNOWN


# ---------------------------------------------------------------------------
# LIEF backend
# ---------------------------------------------------------------------------

def _parse_with_lief(data: bytes) -> ParsedBinary:
    """Parse using LIEF (preferred – supports PE, ELF, Mach-O)."""
    try:
        binary = lief.parse(data)
    except Exception:
        logger.warning("LIEF parse failed – falling back to struct parser", exc_info=True)
        return _parse_with_struct(data)

    if binary is None:
        return _parse_with_struct(data)

    fmt = detect_format(data)
    arch = _lief_arch(binary)
    image_base = _lief_image_base(binary, fmt)
    entry = _lief_entry_point(binary, fmt)
    sections = _lief_sections(binary, data)
    imports = _lief_imports(binary, fmt)
    exports = _lief_exports(binary, fmt)

    return ParsedBinary(
        format=fmt,
        architecture=arch,
        image_base=image_base,
        entry_point=entry,
        sections=sections,
        imports=imports,
        exports=exports,
        raw_size=len(data),
    )


def _lief_arch(binary: Any) -> Architecture:
    try:
        header = binary.header
        machine = getattr(header, "machine_type", None) or getattr(header, "machine", None)
        if machine is None:
            return Architecture.UNKNOWN
        name = str(machine).lower()
        if "amd64" in name or "x86_64" in name or "x64" in name:
            return Architecture.X64
        if "386" in name or "i386" in name or "x86" in name:
            return Architecture.X86
        if "aarch64" in name or "arm64" in name:
            return Architecture.ARM64
        if "arm" in name:
            return Architecture.ARM
    except Exception:
        pass
    return Architecture.UNKNOWN


def _lief_image_base(binary: Any, fmt: BinaryFormat) -> int:
    try:
        if fmt == BinaryFormat.PE:
            return binary.optional_header.imagebase
        if fmt == BinaryFormat.ELF:
            return binary.imagebase
    except Exception:
        pass
    return 0


def _lief_entry_point(binary: Any, fmt: BinaryFormat) -> int:
    try:
        return binary.entrypoint
    except Exception:
        return 0


def _lief_sections(binary: Any, data: bytes) -> List[Section]:
    result: List[Section] = []
    try:
        for sec in binary.sections:
            name = sec.name or ""
            vaddr = getattr(sec, "virtual_address", 0)
            vsize = getattr(sec, "virtual_size", getattr(sec, "size", 0))
            raw_off = getattr(sec, "offset", 0)
            raw_sz = getattr(sec, "size", 0)
            chars = getattr(sec, "characteristics", 0)
            # PE characteristics
            executable = bool(chars & 0x20000000) if chars else False
            writable = bool(chars & 0x80000000) if chars else False
            # ELF flags
            flags = getattr(sec, "flags_list", None)
            if flags:
                flag_names = [str(f).lower() for f in flags]
                if any("execinstr" in f for f in flag_names):
                    executable = True
                if any("write" in f for f in flag_names):
                    writable = True

            sec_data = data[raw_off:raw_off + raw_sz] if raw_off + raw_sz <= len(data) else b""
            entropy = _calculate_entropy(sec_data)

            result.append(Section(
                name=name,
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_offset=raw_off,
                raw_size=raw_sz,
                characteristics=chars,
                entropy=entropy,
                executable=executable,
                writable=writable,
            ))
    except Exception:
        logger.debug("LIEF section extraction failed", exc_info=True)
    return result


def _lief_imports(binary: Any, fmt: BinaryFormat) -> List[ImportEntry]:
    result: List[ImportEntry] = []
    try:
        if fmt == BinaryFormat.PE:
            for imp in binary.imports:
                lib = imp.name or "unknown"
                for entry in imp.entries:
                    name = entry.name or f"Ordinal_{entry.data}"
                    result.append(ImportEntry(library=lib, name=name))
        elif fmt == BinaryFormat.ELF:
            for sym in getattr(binary, "imported_symbols", []):
                result.append(ImportEntry(library="", name=sym.name))
    except Exception:
        logger.debug("LIEF import extraction failed", exc_info=True)
    return result


def _lief_exports(binary: Any, fmt: BinaryFormat) -> List[ExportEntry]:
    result: List[ExportEntry] = []
    try:
        if fmt == BinaryFormat.PE and binary.has_exports:
            for entry in binary.get_export().entries:
                result.append(ExportEntry(
                    name=entry.name or "",
                    address=entry.address,
                    ordinal=entry.ordinal,
                ))
        elif fmt == BinaryFormat.ELF:
            for sym in getattr(binary, "exported_symbols", []):
                result.append(ExportEntry(
                    name=sym.name,
                    address=sym.value,
                ))
    except Exception:
        logger.debug("LIEF export extraction failed", exc_info=True)
    return result


# ---------------------------------------------------------------------------
# Struct-based fallback (PE + ELF only, no external deps)
# ---------------------------------------------------------------------------

def _parse_with_struct(data: bytes) -> ParsedBinary:
    """Minimal struct-based parser for PE and ELF."""
    fmt = detect_format(data)
    if fmt == BinaryFormat.PE:
        return _parse_pe_struct(data)
    if fmt == BinaryFormat.ELF:
        return _parse_elf_struct(data)
    return ParsedBinary(format=fmt, raw_size=len(data))


def _parse_pe_struct(data: bytes) -> ParsedBinary:
    """Parse PE format using struct only."""
    sections: List[Section] = []
    image_base = 0
    entry_point = 0
    arch = Architecture.UNKNOWN

    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return ParsedBinary(format=BinaryFormat.PE, raw_size=len(data))

        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        if machine == 0x8664:
            arch = Architecture.X64
        elif machine == 0x14C:
            arch = Architecture.X86

        num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]

        # Optional header
        opt_off = pe_off + 24
        if opt_off + 2 <= len(data):
            magic = struct.unpack_from("<H", data, opt_off)[0]
            if magic == 0x20B:  # PE32+
                entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
                image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
            elif magic == 0x10B:  # PE32
                entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
                image_base = struct.unpack_from("<I", data, opt_off + 28)[0]

        section_table_off = pe_off + 24 + opt_hdr_size
        for i in range(min(num_sections, 96)):
            off = section_table_off + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8].rstrip(b"\x00")
            vsize = struct.unpack_from("<I", data, off + 8)[0]
            vaddr = struct.unpack_from("<I", data, off + 12)[0]
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_offset = struct.unpack_from("<I", data, off + 20)[0]
            chars = struct.unpack_from("<I", data, off + 36)[0]

            sec_data = data[raw_offset:raw_offset + raw_size]
            entropy = _calculate_entropy(sec_data) if sec_data else 0.0

            sections.append(Section(
                name=name_raw.decode(errors="replace"),
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=chars,
                entropy=entropy,
                executable=bool(chars & 0x20000000),
                writable=bool(chars & 0x80000000),
            ))
    except (struct.error, IndexError):
        pass

    return ParsedBinary(
        format=BinaryFormat.PE,
        architecture=arch,
        image_base=image_base,
        entry_point=entry_point,
        sections=sections,
        raw_size=len(data),
    )


def _parse_elf_struct(data: bytes) -> ParsedBinary:
    """Parse ELF format using struct only."""
    sections: List[Section] = []
    arch = Architecture.UNKNOWN
    entry_point = 0

    try:
        ei_class = data[4]  # 1=32-bit, 2=64-bit

        if ei_class == 1:
            arch_raw = struct.unpack_from("<H", data, 0x12)[0]
            entry_point = struct.unpack_from("<I", data, 0x18)[0]
            e_shoff = struct.unpack_from("<I", data, 0x20)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
            e_shnum = struct.unpack_from("<H", data, 0x30)[0]
            _unpack_sec = _elf32_section
        elif ei_class == 2:
            arch_raw = struct.unpack_from("<H", data, 0x12)[0]
            entry_point = struct.unpack_from("<Q", data, 0x18)[0]
            e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
            e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
            _unpack_sec = _elf64_section
        else:
            return ParsedBinary(format=BinaryFormat.ELF, raw_size=len(data))

        if arch_raw == 0x3E:
            arch = Architecture.X64
        elif arch_raw == 0x03:
            arch = Architecture.X86
        elif arch_raw == 0xB7:
            arch = Architecture.ARM64
        elif arch_raw == 0x28:
            arch = Architecture.ARM

        SHF_EXECINSTR = 0x4
        SHF_WRITE = 0x1

        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(data):
                break
            sec_info = _unpack_sec(data, off)
            if sec_info is None:
                continue
            sh_flags, sh_offset, sh_size = sec_info

            sec_data = data[sh_offset:sh_offset + sh_size]
            entropy = _calculate_entropy(sec_data) if sec_data else 0.0

            sections.append(Section(
                name=f"section_{i}",  # name requires string table lookup
                virtual_address=0,
                virtual_size=sh_size,
                raw_offset=sh_offset,
                raw_size=sh_size,
                entropy=entropy,
                executable=bool(sh_flags & SHF_EXECINSTR),
                writable=bool(sh_flags & SHF_WRITE),
            ))
    except (struct.error, IndexError):
        pass

    return ParsedBinary(
        format=BinaryFormat.ELF,
        architecture=arch,
        entry_point=entry_point,
        sections=sections,
        raw_size=len(data),
    )


def _elf32_section(data: bytes, off: int) -> Optional[tuple]:
    sh_flags = struct.unpack_from("<I", data, off + 8)[0]
    sh_offset = struct.unpack_from("<I", data, off + 16)[0]
    sh_size = struct.unpack_from("<I", data, off + 20)[0]
    return (sh_flags, sh_offset, sh_size)


def _elf64_section(data: bytes, off: int) -> Optional[tuple]:
    sh_flags = struct.unpack_from("<Q", data, off + 8)[0]
    sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
    sh_size = struct.unpack_from("<Q", data, off + 32)[0]
    return (sh_flags, sh_offset, sh_size)
