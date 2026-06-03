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
from typing import Any

from dragonslayer.analysis.binary_format import (
    _calculate_entropy,
    parse_binary,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known VM-related section names
VM_SECTION_NAMES: list[bytes] = [
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
WATERMARK_STRINGS: list[bytes] = [
    b"VMProtect", b"vmp_", b"VMProtect begin", b"VMProtect end",
    b"Themida", b"WinLicense",
    b"Enigma protector",
    b"Code Virtualizer",
    b"Obsidium",
    b"PECompact",
    b".oreans", b"oreans32.dll",
]

# Imports that often appear in VM-protected binaries
VM_IMPORT_INDICATORS: list[bytes] = [
    b"VirtualAlloc", b"VirtualProtect", b"VirtualFree",
    b"NtQueryInformationProcess", b"IsDebuggerPresent",
    b"NtSetInformationThread", b"CheckRemoteDebuggerPresent",
    b"GetTickCount", b"QueryPerformanceCounter",
    b"OutputDebugString", b"NtQuerySystemInformation",
    b"CreateToolhelp32Snapshot",
]

# Dispatcher-related byte patterns (indirect jump through register)
DISPATCHER_PATTERNS: list[tuple[bytes, str]] = [
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

def _parse_pe_sections(data: bytes) -> list[dict[str, Any]]:
    """
    Extract PE section headers using the shared binary parser.

    Returns a list of dicts matching the legacy format for backwards
    compatibility.
    """
    parsed = parse_binary(data)
    return [
        {
            "name": sec.name,
            "virtual_size": sec.virtual_size,
            "virtual_address": sec.virtual_address,
            "raw_size": sec.raw_size,
            "raw_offset": sec.raw_offset,
            "characteristics": sec.characteristics,
            "entropy": round(sec.entropy, 4),
            "executable": sec.executable,
            "writable": sec.writable,
        }
        for sec in parsed.sections
    ]


def _block_entropy_analysis(
    data: bytes,
    block_size: int = 4096,
) -> dict[str, Any]:
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

def _find_dispatchers(data: bytes, limit: int = 50) -> list[dict[str, Any]]:
    """
    Scan for indirect-jump patterns that may indicate a VM dispatcher.

    Returns list of {offset, pattern_bytes, mnemonic}.
    """
    found: list[dict[str, Any]] = []
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

    def detect(self, data: bytes) -> dict[str, Any]:
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
        indicators: list[dict[str, Any]] = []

        # --- File type identification ------------------------------------
        is_pe = data[:2] == b"MZ"
        is_elf = data[:4] == b"\x7fELF"
        file_type = "PE" if is_pe else ("ELF" if is_elf else "unknown")
        indicators.append({"check": "file_type", "value": file_type})

        # --- Section analysis (PE) ----------------------------------------
        sections = _parse_pe_sections(data) if is_pe else []
        vm_sections_found: list[str] = []
        high_entropy_sections: list[str] = []

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
        found_watermarks: list[str] = []
        for wm in WATERMARK_STRINGS:
            if wm in data:
                found_watermarks.append(wm.decode(errors="replace"))
        if found_watermarks:
            indicators.append({
                "check": "watermarks",
                "found": found_watermarks,
            })

        # --- Import anomalies ---------------------------------------------
        found_imports: list[str] = []
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
            for found_sec in vm_sections_found:
                if "vmp" in found_sec.lower():
                    protector = "VMProtect"
                elif "themida" in found_sec.lower() or "winlice" in found_sec.lower():
                    protector = "Themida"
                elif "enigma" in found_sec.lower():
                    protector = "Enigma"
                elif "cvirt" in found_sec.lower():
                    protector = "Code Virtualizer"

        if found_watermarks:
            score += 0.25
            for wm_name in found_watermarks:
                if "VMProtect" in wm_name or "vmp_" in wm_name:
                    protector = "VMProtect"
                elif "Themida" in wm_name or "WinLicense" in wm_name:
                    protector = "Themida"
                elif "Enigma" in wm_name:
                    protector = "Enigma"
                elif "Code Virtualizer" in wm_name:
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

        # Protector-agnostic structural fallback: when the signature-based
        # score is weak (i.e. no known protector matched), emulate the binary
        # and look for generic VM-interpreter structure (dispatch loop +
        # monotonic vIP + indirect dispatch).  This is what lets the system
        # flag *unknown / custom* VMs.
        structural: dict[str, Any] = {}
        if score < 0.5:
            structural = self._structural_scan(data)
            if structural.get("is_vm"):
                score = max(score, float(structural["confidence"]))
                if protector == "unknown":
                    protector = "generic_vm"
                for ev in structural.get("evidence", []):
                    indicators.append({"check": "structural", "detail": ev})

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
            "structural": structural,
        }

    def _structural_scan(self, data: bytes) -> dict[str, Any]:
        """Best-effort generic VM-structure detection via built-in emulation.

        Returns ``{}`` when the Unicorn backend is unavailable or the binary
        can't be traced.
        """
        try:
            from ..trace_engine import UNICORN_AVAILABLE, TraceConfig, TraceEngine

            if not UNICORN_AVAILABLE:
                return {}
            from ..binary_format import parse_binary
            from .structural import analyse_vm_structure

            pb = parse_binary(data)
            entry = int(getattr(pb, "entry_point", 0) or 0)
            base = int(getattr(pb, "image_base", 0) or 0) or 0x400000
            arch = "x86_64" if "64" in str(getattr(pb, "architecture", "")) else "x86"
            if not entry:
                return {}
            trace = TraceEngine(arch=arch, config=TraceConfig(max_instructions=4000)).trace(
                data, entry_va=entry, image_base=base,
            )
            return analyse_vm_structure(trace)
        except Exception:  # best-effort: emulating arbitrary input
            return {}
