"""
Mach-O Binary Analyser
======================

Ported from ``repos/stage3/working/macho-analyzer/analyzer.py``.

Extracts Mach-O headers, load commands, segments, dylib dependencies,
RPATHs, UUID, code signature, encryption, PIE flag, and handles
universal/fat binaries.

Dependency: ``macholib``.
"""

from __future__ import annotations

import logging
import os
import struct
import tempfile
import time
from typing import Any, Dict, List, Optional, Set

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_MACHOLIB = False
try:
    from macholib.MachO import MachO  # type: ignore[import-untyped]
    from macholib import mach_o       # type: ignore[import-untyped]
    _HAS_MACHOLIB = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constant tables (defined locally so we don't depend on macholib at import)
# ---------------------------------------------------------------------------

_CPU_TYPE_NAMES: Dict[int, str] = {
    7:          "x86",
    7 | 0x01000000: "x86_64",
    12:         "ARM",
    12 | 0x01000000: "ARM64",
    18:         "PowerPC",
    18 | 0x01000000: "PowerPC64",
}

_FILE_TYPE_NAMES: Dict[int, str] = {}

_LOAD_CMD_NAMES: Dict[int, str] = {}


def _init_constant_tables() -> None:
    """Populate constant tables from macholib symbols at first use."""
    global _FILE_TYPE_NAMES, _LOAD_CMD_NAMES  # noqa: PLW0603
    if _FILE_TYPE_NAMES:
        return
    _FILE_TYPE_NAMES.update({
        getattr(mach_o, "MH_OBJECT", 0x1): "MH_OBJECT",
        getattr(mach_o, "MH_EXECUTE", 0x2): "MH_EXECUTE",
        getattr(mach_o, "MH_FVMLIB", 0x3): "MH_FVMLIB",
        getattr(mach_o, "MH_CORE", 0x4): "MH_CORE",
        getattr(mach_o, "MH_PRELOAD", 0x5): "MH_PRELOAD",
        getattr(mach_o, "MH_DYLIB", 0x6): "MH_DYLIB",
        getattr(mach_o, "MH_DYLINKER", 0x7): "MH_DYLINKER",
        getattr(mach_o, "MH_BUNDLE", 0x8): "MH_BUNDLE",
        getattr(mach_o, "MH_DSYM", 0xA): "MH_DSYM",
        0xB: "MH_KEXT_BUNDLE",
        0xC: "MH_FILESET",
        0xD: "MH_GPU_EXECUTE",
        0xE: "MH_GPU_DYLIB",
    })
    # Load-command name map
    for attr_name in dir(mach_o):
        if attr_name.startswith("LC_"):
            _LOAD_CMD_NAMES[getattr(mach_o, attr_name)] = attr_name


def _lc_name(cmd: int) -> str:
    return _LOAD_CMD_NAMES.get(cmd, f"UNKNOWN_{hex(cmd)}")


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

_MACHO_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE,
                 0xCAFEBABE, 0xBEBAFECA}


@register_plugin
class MachOAnalyzer(Plugin):
    """Mach-O binary analysis: headers, load commands, segments, security."""

    name = "macho_analyzer"
    stage = Stage.STATIC
    description = "Mach-O binary analysis: headers, segments, security"

    @classmethod
    def available(cls) -> bool:
        return _HAS_MACHOLIB

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        if len(file_data) < 4:
            return self._make_result(success=False, error="File too small",
                                     duration=time.monotonic() - t0)

        magic = struct.unpack(">I", file_data[:4])[0]
        if magic not in _MACHO_MAGICS:
            return self._make_result(success=False, error="Not a Mach-O file",
                                     duration=time.monotonic() - t0)

        _init_constant_tables()

        tmp_path: Optional[str] = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".macho")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path)
            context.shared_data["macho_analyzer"] = result
            return self._make_result(
                success=result.get("valid", False),
                data=result,
                duration=time.monotonic() - t0,
            )
        except Exception as exc:
            logger.exception("Mach-O analysis failed")
            return self._make_result(success=False, error=str(exc),
                                     duration=time.monotonic() - t0)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ------------------------------------------------------------------

    @staticmethod
    def _analyze(file_path: str) -> Dict[str, Any]:
        macho = MachO(file_path)

        result: Dict[str, Any] = {
            "valid": True,
            "file": os.path.basename(file_path),
            "universal": len(macho.headers) > 1,
            "arch_count": len(macho.headers),
        }

        architectures: List[Dict[str, Any]] = []
        all_libraries: Set[str] = set()
        all_rpaths: Set[str] = set()

        for header in macho.headers:
            arch = MachOAnalyzer._analyze_arch(header)
            architectures.append(arch)
            all_libraries.update(arch.get("libraries", []))
            all_rpaths.update(arch.get("rpaths", []))

        result["architectures"] = architectures

        if len(architectures) == 1:
            result.update(architectures[0])
        else:
            result["libraries"] = sorted(all_libraries)
            result["library_count"] = len(all_libraries)
            result["rpaths"] = sorted(all_rpaths) if all_rpaths else []

        return result

    @staticmethod
    def _analyze_arch(header: Any) -> Dict[str, Any]:  # noqa: C901 – ported as-is
        cpu_type = header.header.cputype
        result: Dict[str, Any] = {
            "cpu_type": _CPU_TYPE_NAMES.get(cpu_type, f"UNKNOWN_{cpu_type}"),
            "cpu_subtype": header.header.cpusubtype,
            "filetype": _FILE_TYPE_NAMES.get(header.header.filetype,
                                              f"UNKNOWN_{header.header.filetype}"),
            "flags": hex(header.header.flags),
            "is_64bit": header.MH_MAGIC in (
                getattr(mach_o, "MH_MAGIC_64", 0xFEEDFACF),
                getattr(mach_o, "MH_CIGAM_64", 0xCFFAEDFE),
            ),
        }

        libraries: List[str] = []
        rpaths: List[str] = []
        segments: List[Dict[str, Any]] = []
        load_cmds: List[str] = []
        uuid_str: Optional[str] = None
        min_os_version: Optional[str] = None
        source_version_str: Optional[str] = None
        has_code_signature = False
        has_encryption = False
        entry_point: Optional[str] = None

        LC_LOAD_DYLIB      = getattr(mach_o, "LC_LOAD_DYLIB", 0xC)
        LC_LOAD_WEAK_DYLIB = getattr(mach_o, "LC_LOAD_WEAK_DYLIB", 0x80000018)
        LC_REEXPORT_DYLIB  = getattr(mach_o, "LC_REEXPORT_DYLIB", 0x8000001F)
        LC_LAZY_LOAD_DYLIB = getattr(mach_o, "LC_LAZY_LOAD_DYLIB", 0x20)
        LC_RPATH            = getattr(mach_o, "LC_RPATH", 0x8000001C)
        LC_SEGMENT          = getattr(mach_o, "LC_SEGMENT", 0x1)
        LC_SEGMENT_64       = getattr(mach_o, "LC_SEGMENT_64", 0x19)
        LC_UUID             = getattr(mach_o, "LC_UUID", 0x1B)
        LC_CODE_SIGNATURE   = getattr(mach_o, "LC_CODE_SIGNATURE", 0x1D)
        LC_ENCRYPTION_INFO  = getattr(mach_o, "LC_ENCRYPTION_INFO", 0x21)
        LC_ENCRYPTION_INFO_64 = getattr(mach_o, "LC_ENCRYPTION_INFO_64", 0x2C)
        LC_MAIN             = getattr(mach_o, "LC_MAIN", 0x80000028)
        LC_VERSION_MIN_MACOSX   = getattr(mach_o, "LC_VERSION_MIN_MACOSX", 0x24)
        LC_VERSION_MIN_IPHONEOS = getattr(mach_o, "LC_VERSION_MIN_IPHONEOS", 0x25)
        LC_VERSION_MIN_TVOS     = getattr(mach_o, "LC_VERSION_MIN_TVOS", 0x2F)
        LC_VERSION_MIN_WATCHOS  = getattr(mach_o, "LC_VERSION_MIN_WATCHOS", 0x30)
        LC_SOURCE_VERSION       = getattr(mach_o, "LC_SOURCE_VERSION", 0x2A)

        DYLIB_CMDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB}
        SEG_CMDS = {LC_SEGMENT, LC_SEGMENT_64}
        VER_CMDS = {LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS,
                    LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS}

        for cmd in header.commands:
            cmd_type = cmd[0].cmd
            load_cmds.append(_lc_name(cmd_type))

            if cmd_type in DYLIB_CMDS:
                try:
                    libraries.append(cmd[2].decode("utf-8").rstrip("\x00"))
                except Exception:
                    pass

            elif cmd_type == LC_RPATH:
                try:
                    rpaths.append(cmd[2].decode("utf-8").rstrip("\x00"))
                except Exception:
                    pass

            elif cmd_type in SEG_CMDS:
                try:
                    segments.append({
                        "name": cmd[1].segname.decode("utf-8").rstrip("\x00"),
                        "vmaddr": hex(cmd[1].vmaddr),
                        "vmsize": cmd[1].vmsize,
                        "fileoff": cmd[1].fileoff,
                        "filesize": cmd[1].filesize,
                        "maxprot": hex(cmd[1].maxprot),
                        "initprot": hex(cmd[1].initprot),
                    })
                except Exception:
                    pass

            elif cmd_type == LC_UUID:
                try:
                    ub = cmd[1].uuid
                    uuid_str = "-".join([
                        ub[:4].hex(), ub[4:6].hex(), ub[6:8].hex(),
                        ub[8:10].hex(), ub[10:16].hex(),
                    ])
                except Exception:
                    pass

            elif cmd_type in VER_CMDS:
                try:
                    v = cmd[1].version
                    min_os_version = f"{(v >> 16) & 0xFFFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"
                except Exception:
                    pass

            elif cmd_type == LC_SOURCE_VERSION:
                try:
                    v = cmd[1].version
                    source_version_str = (
                        f"{(v >> 40) & 0xFFFFFF}.{(v >> 30) & 0x3FF}."
                        f"{(v >> 20) & 0x3FF}.{(v >> 10) & 0x3FF}.{v & 0x3FF}"
                    )
                except Exception:
                    pass

            elif cmd_type == LC_CODE_SIGNATURE:
                has_code_signature = True

            elif cmd_type in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                try:
                    has_encryption = cmd[1].cryptid != 0
                except Exception:
                    pass

            elif cmd_type == LC_MAIN:
                try:
                    entry_point = hex(cmd[1].entryoff)
                except Exception:
                    pass

        result["load_commands"] = load_cmds
        result["load_command_count"] = len(load_cmds)
        result["libraries"] = libraries
        result["library_count"] = len(libraries)
        if rpaths:
            result["rpaths"] = rpaths
        result["segments"] = segments
        result["segment_count"] = len(segments)
        if uuid_str:
            result["uuid"] = uuid_str
        if min_os_version:
            result["min_os_version"] = min_os_version
        if source_version_str:
            result["source_version"] = source_version_str
        if entry_point:
            result["entry_point"] = entry_point

        MH_PIE = getattr(mach_o, "MH_PIE", 0x200000)
        MH_NO_HEAP_EXECUTION = getattr(mach_o, "MH_NO_HEAP_EXECUTION", 0x1000000)
        result["security"] = {
            "code_signature": has_code_signature,
            "encrypted": has_encryption,
            "pie": bool(header.header.flags & MH_PIE),
            "no_heap_execution": bool(header.header.flags & MH_NO_HEAP_EXECUTION),
        }

        return result
