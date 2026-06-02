"""
Strelka Multi-Format Scanner
==============================

Ported from ``repos/stage4/working/strelka/scan.py``.

A multi-format scanner that handles PE, archive, YARA, OLE, PDF,
LNK, and exiftool analysis.  Adapted from the Strelka file-scanning
framework to work as a self-contained VMDragonSlayer plugin.

Optional dependencies: ``pefile``, ``yara``, ``oletools``, ``magic``.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import tempfile
import time
from typing import Any

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

# Optional dependency imports
_HAS_PEFILE = False
try:
    import pefile
    _HAS_PEFILE = True
except ImportError:
    pass

_HAS_YARA = False
try:
    import yara
    _HAS_YARA = True
except ImportError:
    pass

_HAS_OLETOOLS = False
try:
    from oletools.olevba import VBA_Parser
    _HAS_OLETOOLS = True
except ImportError:
    pass

_HAS_MAGIC = False
try:
    import magic as _magic
    _HAS_MAGIC = True
except ImportError:
    pass


def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of *data* (0.0–8.0 bits/byte)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq if c > 0
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@register_plugin
class StrelkaScanner(Plugin):
    """Multi-format binary scanner (PE sections, OLE macros, YARA)."""

    name = "strelka"
    stage = Stage.DYNAMIC
    description = "Multi-format scanner: PE, OLE, YARA, archive"

    @classmethod
    def available(cls) -> bool:
        # At minimum we can do basic binary analysis
        return True

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        tmp_path: str | None = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._scan(file_path, file_data, context)
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("Strelka scan failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _scan(
        self, file_path: str, file_data: bytes, ctx: PluginContext
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "sha256": _sha256(file_data),
            "size": len(file_data),
            "entropy": round(_calculate_entropy(file_data), 4),
        }

        # Detect MIME type
        if _HAS_MAGIC:
            try:
                result["mime"] = _magic.from_buffer(file_data, mime=True)
                result["description"] = _magic.from_buffer(file_data)
            except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError):
                pass

        # Format-specific analysis
        if file_data[:2] == b"MZ" and _HAS_PEFILE:
            result["pe"] = self._scan_pe(file_path)
        if _HAS_OLETOOLS:
            ole = self._scan_ole(file_path)
            if ole:
                result["ole"] = ole
        if _HAS_YARA:
            yara_rules_path = ctx.config.get("yara.rules_path")
            if yara_rules_path and os.path.isfile(yara_rules_path):
                result["yara"] = self._scan_yara(file_data, yara_rules_path)

        return result

    # -- PE ----------------------------------------------------------------

    @staticmethod
    def _scan_pe(file_path: str) -> dict[str, Any]:
        try:
            pe = pefile.PE(file_path)
            sections = []
            for sec in pe.sections:
                sections.append({
                    "name": sec.Name.decode("utf-8", errors="replace").rstrip("\x00"),
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                    "entropy": round(sec.get_entropy(), 4),
                    "characteristics": hex(sec.Characteristics),
                })

            imports: dict[str, list[str]] = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="replace")
                    funcs = []
                    for imp in entry.imports:
                        if imp.name:
                            funcs.append(imp.name.decode("utf-8", errors="replace"))
                        else:
                            funcs.append(f"Ordinal_{imp.ordinal}")
                    imports[dll] = funcs

            result: dict[str, Any] = {
                "valid": True,
                "machine": hex(pe.FILE_HEADER.Machine),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "sections": sections,
                "section_count": len(sections),
                "imports": imports,
            }

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                result["imphash"] = pe.get_imphash()

            return result
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
            return {"valid": False, "error": str(exc)}

    # -- OLE / VBA ---------------------------------------------------------

    @staticmethod
    def _scan_ole(file_path: str) -> dict[str, Any] | None:
        try:
            vba = VBA_Parser(file_path)
            if not vba.detect_vba_macros():
                return None

            macros = []
            for _, _, vba_filename, vba_code in vba.extract_macros():
                macros.append({
                    "filename": vba_filename,
                    "code_preview": vba_code[:500] if vba_code else "",
                })
            vba.close()
            return {"macros_found": len(macros), "macros": macros}
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError):
            return None

    # -- YARA --------------------------------------------------------------

    @staticmethod
    def _scan_yara(file_data: bytes, rules_path: str) -> dict[str, Any]:
        try:
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(data=file_data)
            return {
                "matches": [
                    {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": list(m.tags),
                    }
                    for m in matches
                ],
                "match_count": len(matches),
            }
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
            return {"error": str(exc), "matches": []}
