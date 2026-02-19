"""
ELF Binary Analyser
====================

Ported from ``repos/stage3/working/elf-analyzer/analyzer.py``.

Extracts ELF headers, sections (with entropy), symbol imports/exports,
dynamic library dependencies, segments, and security features
(PIE, RELRO, NX, stack canary).

Dependency: ``pyelftools``.
"""

from __future__ import annotations

import logging
import math
import os
import tempfile
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_ELFTOOLS = False
try:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    from elftools.elf.sections import SymbolTableSection  # type: ignore[import-untyped]
    from elftools.elf.dynamic import DynamicSection  # type: ignore[import-untyped]
    _HAS_ELFTOOLS = True
except ImportError:
    pass


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@register_plugin
class ELFAnalyzer(Plugin):
    """ELF header, section, symbol, library, and security-feature extraction."""

    name = "elf_analyzer"
    stage = Stage.STATIC
    description = "ELF binary analysis: headers, sections, symbols, security"

    @classmethod
    def available(cls) -> bool:
        return _HAS_ELFTOOLS

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        if file_data[:4] != b"\x7fELF":
            return self._make_result(
                success=False,
                error="Not an ELF file",
                duration=time.monotonic() - t0,
            )

        tmp_path: Optional[str] = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".elf")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path)
            context.shared_data["elf_analyzer"] = result
            return self._make_result(
                success=result.get("valid", False),
                data=result,
                duration=time.monotonic() - t0,
            )
        except Exception as exc:
            logger.exception("ELF analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @staticmethod
    def _analyze(file_path: str) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)

            result: Dict[str, Any] = {
                "valid": True,
                "class": elf.elfclass,
                "endian": "little" if elf.little_endian else "big",
                "type": str(elf["e_type"]),
                "machine": str(elf["e_machine"]),
                "entry_point": hex(elf["e_entry"]),
            }

            # Sections
            sections: List[Dict[str, Any]] = []
            section_info: Dict[str, Dict[str, Any]] = {}
            for sec in elf.iter_sections():
                sec_data: Dict[str, Any] = {
                    "name": sec.name,
                    "type": str(sec["sh_type"]),
                    "size": sec["sh_size"],
                    "offset": sec["sh_offset"],
                    "flags": hex(sec["sh_flags"]),
                }
                sections.append(sec_data)
                if sec["sh_size"] > 0 and sec.name in (".text", ".data", ".rodata", ".bss"):
                    try:
                        data = sec.data()
                        section_info[sec.name] = {
                            "size": sec["sh_size"],
                            "entropy": round(_entropy(data), 2),
                        }
                    except Exception:
                        pass
            result["sections"] = sections
            result["section_count"] = len(sections)
            result["section_info"] = section_info

            # Symbols
            imports: List[str] = []
            exports: List[str] = []
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if not sym.name:
                            continue
                        if sym["st_shndx"] == "SHN_UNDEF" and sym["st_value"] == 0:
                            if sym.name not in imports:
                                imports.append(sym.name)
                        elif sym["st_info"]["bind"] == "STB_GLOBAL" and sym["st_shndx"] != "SHN_UNDEF":
                            if sym.name not in exports:
                                exports.append(sym.name)
            result["imports"] = sorted(imports)
            result["exports"] = sorted(exports)

            # Dynamic libraries
            libraries: List[str] = []
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            libraries.append(tag.needed)
            result["libraries"] = libraries

            # Segments
            segments: List[Dict[str, Any]] = []
            for seg in elf.iter_segments():
                segments.append({
                    "type": str(seg["p_type"]),
                    "vaddr": hex(seg["p_vaddr"]),
                    "filesz": seg["p_filesz"],
                    "memsz": seg["p_memsz"],
                    "flags": hex(seg["p_flags"]),
                })
            result["segments"] = segments

            # Security features
            security: Dict[str, bool] = {
                "pie": result["type"] == "ET_DYN",
                "relro": False,
                "nx": False,
                "stack_canary": "__stack_chk_fail" in imports,
            }
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_GNU_RELRO":
                    security["relro"] = True
                if seg["p_type"] == "PT_GNU_STACK":
                    security["nx"] = (seg["p_flags"] & 0x1) == 0
            result["security"] = security

            return result
