"""
VM Discovery — Detector
=======================

Heuristic-based detection of virtual-machine obfuscation in binary samples.
This is the *local* detector that runs without external tools (no angr,
no disassembler).  It examines raw bytes for structural cues:

* PE / ELF magic and section headers
* Known VM section names (``.vmp0``, ``.themida``, …)
* Entropy analysis (packed / encrypted regions)
* Watermark strings (``VMProtect``, ``Themida``, …)
* Import table anomalies (common VM-related API imports)
* Dispatcher pattern heuristics (indirect jump tables)

The heavier dynamic detection (CFG recovery, symbolic execution) is
handled by Stage-4 plugins (angr, triton, qiling).
"""

from __future__ import annotations

import logging
import math
import struct
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known VM-related section names
VM_SECTION_NAMES: List[bytes] = [
    b".vmp0", b".vmp1", b".vmp2", b".vmp3",   # VMProtect
    b".themida", b".winlice",                   # Themida / WinLicense
    b".enigma1", b".enigma2",                   # Enigma Protector
    b".cvirt",                                  # Code Virtualizer
    b".perplex",                                # Perplex
    b".petite",                                 # Petite
    b".aspack",                                 # ASPack
    b".adata",                                  # common in packed binaries
    b"UPX0", b"UPX1", b"UPX2",                 # UPX
]

# Watermark / signature strings
WATERMARK_STRINGS: List[bytes] = [
    b"VMProtect", b"vmp_", b"VMProtect begin", b"VMProtect end",
    b"Themida", b"WinLicense",
    b"Enigma protector",
    b"Code Virtualizer",
    b"Obsidium",
    b"PECompact",
    b".oreans", b"oreans32.dll",
]

# Imports that often appear in VM-protected binaries
VM_IMPORT_INDICATORS: List[bytes] = [
    b"VirtualAlloc", b"VirtualProtect", b"VirtualFree",
    b"NtQueryInformationProcess", b"IsDebuggerPresent",
    b"NtSetInformationThread", b"CheckRemoteDebuggerPresent",
    b"GetTickCount", b"QueryPerformanceCounter",
    b"OutputDebugString", b"NtQuerySystemInformation",
    b"CreateToolhelp32Snapshot",
]

# Dispatcher-related byte patterns (indirect jump through register)
DISPATCHER_PATTERNS: List[tuple[bytes, str]] = [
    (b"\xff\xe0", "jmp eax"),
    (b"\xff\xe1", "jmp ecx"),
    (b"\xff\xe2", "jmp edx"),
    (b"\xff\xe3", "jmp ebx"),
    (b"\xff\x24\x85", "jmp [eax*4+disp32]"),       # jump table
    (b"\xff\x24\x8d", "jmp [ecx*4+disp32]"),
    (b"\xff\x24\x95", "jmp [edx*4+disp32]"),
    (b"\xff\x24\x9d", "jmp [ebx*4+disp32]"),
    (b"\x0f\x1f\x44\x00", "nop dword [rax+rax]"),  # padding in VM stubs
]


# ---------------------------------------------------------------------------
# PE Section Header Parsing (minimal, no pefile dependency)
# ---------------------------------------------------------------------------

def _parse_pe_sections(data: bytes) -> List[Dict[str, Any]]:
    """
    Extract PE section headers from raw bytes without pefile.

    Returns a list of dicts: {name, virtual_size, virtual_address,
    raw_size, raw_offset, characteristics, entropy}.
    """
    sections: List[Dict[str, Any]] = []
    if len(data) < 64 or data[:2] != b"MZ":
        return sections

    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data):
            return sections
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return sections

        # COFF header
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]

        section_table_offset = pe_offset + 24 + opt_hdr_size
        SECTION_HDR_SIZE = 40

        for i in range(min(num_sections, 96)):  # cap at 96 to avoid abuse
            off = section_table_offset + i * SECTION_HDR_SIZE
            if off + SECTION_HDR_SIZE > len(data):
                break

            name_raw = data[off:off + 8].rstrip(b"\x00")
            vsize = struct.unpack_from("<I", data, off + 8)[0]
            vaddr = struct.unpack_from("<I", data, off + 12)[0]
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_offset = struct.unpack_from("<I", data, off + 20)[0]
            characteristics = struct.unpack_from("<I", data, off + 36)[0]

            # Calculate section entropy
            sec_data = data[raw_offset:raw_offset + raw_size] if raw_offset + raw_size <= len(data) else b""
            entropy = _calculate_entropy(sec_data) if sec_data else 0.0

            sections.append({
                "name": name_raw.decode(errors="replace"),
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics,
                "entropy": round(entropy, 4),
                "executable": bool(characteristics & 0x20000000),
                "writable": bool(characteristics & 0x80000000),
            })

    except (struct.error, IndexError):
        pass

    return sections


# ---------------------------------------------------------------------------
# Entropy calculation
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


def _block_entropy_analysis(
    data: bytes,
    block_size: int = 4096,
) -> Dict[str, Any]:
    """
    Analyse entropy across the entire binary in blocks.

    Returns stats: total_blocks, high_entropy_blocks, ratio, avg_entropy.
    """
    if len(data) < block_size:
        ent = _calculate_entropy(data)
        return {
            "total_blocks": 1,
            "high_entropy_blocks": 1 if ent > 7.5 else 0,
            "ratio": 1.0 if ent > 7.5 else 0.0,
            "avg_entropy": round(ent, 4),
        }

    total = 0
    high = 0
    ent_sum = 0.0
    for i in range(0, len(data) - block_size + 1, block_size):
        block = data[i:i + block_size]
        ent = _calculate_entropy(block)
        ent_sum += ent
        total += 1
        if ent > 7.5:
            high += 1

    avg = ent_sum / total if total else 0.0
    return {
        "total_blocks": total,
        "high_entropy_blocks": high,
        "ratio": round(high / total, 4) if total else 0.0,
        "avg_entropy": round(avg, 4),
    }


# ---------------------------------------------------------------------------
# Dispatcher detection
# ---------------------------------------------------------------------------

def _find_dispatchers(data: bytes, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Scan for indirect-jump patterns that may indicate a VM dispatcher.

    Returns list of {offset, pattern_bytes, mnemonic}.
    """
    found: List[Dict[str, Any]] = []
    for pattern, mnemonic in DISPATCHER_PATTERNS:
        start = 0
        while len(found) < limit:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            found.append({
                "offset": idx,
                "pattern_bytes": pattern.hex().upper(),
                "mnemonic": mnemonic,
            })
            start = idx + 1
    return found[:limit]


# ---------------------------------------------------------------------------
# VMDetector
# ---------------------------------------------------------------------------

class VMDetector:
    """
    Heuristic VM-obfuscation detector.

    Usage::

        detector = VMDetector()
        result = detector.detect(binary_data)
        if result["vm_detected"]:
            print(result["protector"], result["confidence"])
    """

    def detect(self, data: bytes) -> Dict[str, Any]:
        """
        Run all heuristics on *data* and return a detection result dict.

        Keys:
            vm_detected (bool): Whether a VM protector was detected.
            confidence (float): Overall confidence score (0..1).
            protector (str): Most likely protector name, or "unknown".
            file_type (str): "PE", "ELF", or "unknown".
            indicators (list): Detailed indicator dicts.
            sections (list): Parsed section headers (PE only).
            entropy (dict): Block entropy statistics.
            dispatchers (list): Suspected dispatcher locations.
        """
        indicators: List[Dict[str, Any]] = []

        # --- File type identification ------------------------------------
        is_pe = data[:2] == b"MZ"
        is_elf = data[:4] == b"\x7fELF"
        file_type = "PE" if is_pe else ("ELF" if is_elf else "unknown")
        indicators.append({"check": "file_type", "value": file_type})

        # --- Section analysis (PE) ----------------------------------------
        sections = _parse_pe_sections(data) if is_pe else []
        vm_sections_found: List[str] = []
        high_entropy_sections: List[str] = []

        for sec in sections:
            for vm_name in VM_SECTION_NAMES:
                if vm_name.decode(errors="replace") in sec["name"]:
                    vm_sections_found.append(sec["name"])
            if sec["entropy"] > 7.0:
                high_entropy_sections.append(sec["name"])

        # Also check raw byte scan for section names (works for non-PE too)
        for sec_name in VM_SECTION_NAMES:
            if sec_name in data and sec_name.decode(errors="replace") not in vm_sections_found:
                vm_sections_found.append(sec_name.decode(errors="replace"))

        if vm_sections_found:
            indicators.append({
                "check": "vm_sections",
                "sections": vm_sections_found,
            })
        if high_entropy_sections:
            indicators.append({
                "check": "high_entropy_sections",
                "sections": high_entropy_sections,
            })

        # --- Entropy analysis ---------------------------------------------
        entropy_stats = _block_entropy_analysis(data)
        indicators.append({
            "check": "entropy",
            **entropy_stats,
        })

        # --- Watermark / signature strings --------------------------------
        found_watermarks: List[str] = []
        for wm in WATERMARK_STRINGS:
            if wm in data:
                found_watermarks.append(wm.decode(errors="replace"))
        if found_watermarks:
            indicators.append({
                "check": "watermarks",
                "found": found_watermarks,
            })

        # --- Import anomalies ---------------------------------------------
        found_imports: List[str] = []
        for imp in VM_IMPORT_INDICATORS:
            if imp in data:
                found_imports.append(imp.decode())
        if found_imports:
            indicators.append({
                "check": "vm_imports",
                "found": found_imports,
            })

        # --- Dispatcher patterns ------------------------------------------
        dispatchers = _find_dispatchers(data)
        if dispatchers:
            indicators.append({
                "check": "dispatchers",
                "count": len(dispatchers),
                "samples": dispatchers[:5],
            })

        # --- Confidence scoring -------------------------------------------
        score = 0.0
        protector = "unknown"

        if vm_sections_found:
            score += 0.35
            # Identify protector from section names
            for sec in vm_sections_found:
                if "vmp" in sec.lower():
                    protector = "VMProtect"
                elif "themida" in sec.lower() or "winlice" in sec.lower():
                    protector = "Themida"
                elif "enigma" in sec.lower():
                    protector = "Enigma"
                elif "cvirt" in sec.lower():
                    protector = "Code Virtualizer"

        if found_watermarks:
            score += 0.25
            for wm in found_watermarks:
                if "VMProtect" in wm or "vmp_" in wm:
                    protector = "VMProtect"
                elif "Themida" in wm or "WinLicense" in wm:
                    protector = "Themida"
                elif "Enigma" in wm:
                    protector = "Enigma"
                elif "Code Virtualizer" in wm:
                    protector = "Code Virtualizer"

        if entropy_stats["ratio"] > 0.6:
            score += 0.20
        elif entropy_stats["ratio"] > 0.3:
            score += 0.10

        if high_entropy_sections:
            score += 0.10

        if len(dispatchers) > 3:
            score += 0.10
        elif len(dispatchers) > 0:
            score += 0.05

        if found_imports:
            anti_debug_apis = {"IsDebuggerPresent", "NtQueryInformationProcess",
                               "CheckRemoteDebuggerPresent", "NtSetInformationThread"}
            if anti_debug_apis.intersection(found_imports):
                score += 0.10
            if len(found_imports) >= 3:
                score += 0.05

        if is_pe or is_elf:
            score += 0.05

        score = min(score, 1.0)
        vm_detected = score >= 0.30

        return {
            "vm_detected": vm_detected,
            "confidence": round(score, 4),
            "protector": protector,
            "file_type": file_type,
            "indicators": indicators,
            "sections": sections,
            "entropy": entropy_stats,
            "dispatchers": dispatchers[:10],
        }
