"""
PE File Analyser
=================

Ported from ``repos/stage3/working/pe-analyzer/analyzer.py``.

Extracts DOS/NT/File/Optional headers, sections (with entropy),
imports, exports, and imphash from PE files.

Dependency: ``pefile``.
"""

from __future__ import annotations

import logging
import math
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_PEFILE = False
try:
    import pefile  # type: ignore[import-untyped]
    _HAS_PEFILE = True
except ImportError:
    pass


@register_plugin
class PEAnalyzer(Plugin):
    """PE header, section, import/export extraction."""

    name = "pe_analyzer"
    stage = Stage.STATIC
    description = "PE file analysis: headers, sections, imports, exports, imphash"

    @classmethod
    def available(cls) -> bool:
        return _HAS_PEFILE

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        if file_data[:2] != b"MZ":
            return self._make_result(
                success=False,
                error="Not a PE file",
                duration=time.monotonic() - t0,
            )

        tmp_path: Optional[str] = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".exe")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path)
            context.shared_data["pe_analyzer"] = result
            return self._make_result(
                success=result.get("valid", False),
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("PE analysis failed")
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
        result: Dict[str, Any] = {"valid": False, "sections": [], "imports": {}, "exports": []}

        pe = pefile.PE(file_path)

        if pe.DOS_HEADER.e_magic != 0x5A4D or pe.NT_HEADERS.Signature != 0x4550:
            result["error"] = "Invalid PE signature"
            return result

        result["valid"] = True

        result["dos_header"] = {
            "e_magic": hex(pe.DOS_HEADER.e_magic),
            "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
        }
        result["file_header"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
        }
        result["optional_header"] = {
            "magic": hex(pe.OPTIONAL_HEADER.Magic),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        }

        for section in pe.sections:
            result["sections"].append({
                "name": section.Name.decode("utf-8", errors="replace").rstrip("\x00"),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "characteristics": hex(section.Characteristics),
                "entropy": round(section.get_entropy(), 4),
            })

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="replace"))
                    else:
                        funcs.append(f"Ordinal_{imp.ordinal}")
                result["imports"][dll] = funcs
            result["imphash"] = pe.get_imphash()

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                result["exports"].append({
                    "name": exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal_{exp.ordinal}",
                    "ordinal": exp.ordinal,
                    "address": hex(exp.address),
                })

        return result
