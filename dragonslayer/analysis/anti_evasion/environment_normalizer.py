"""
Environment Normalizer
======================

Detects and neutralises common anti-analysis / anti-debug techniques used
by VM-protected binaries.  Designed to run as a pre-processing step
before dynamic analysis so that emulators and symbolic executors operate
in an "expected" environment.

Capabilities
------------
* **Anti-debug API detection** — scans imports and instruction patterns
  for ``IsDebuggerPresent``, ``NtQueryInformationProcess``, ``rdtsc``
  timing checks, etc.
* **Environment fingerprint detection** — VMware / VBox artefact checks,
  MAC address prefixes, registry keys, file-system sentinels.
* **Patch generation** — produces binary patches (NOP / forced-jump) that
  neutralise detected anti-analysis guards.
* **Integration with pipeline shared_data** — reads ``vm_discovery`` and
  ``pattern_matches``; writes ``anti_evasion`` results.

Usage::

    from dragonslayer.analysis.anti_evasion.environment_normalizer import (
        EnvironmentNormalizer,
    )

    normalizer = EnvironmentNormalizer()
    report = normalizer.analyze(binary_data)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from dragonslayer.analysis.binary_format import parse_binary

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class EvasionCategory(Enum):
    ANTI_DEBUG = "anti_debug"
    TIMING_CHECK = "timing_check"
    ENVIRONMENT_CHECK = "environment_check"
    ANTI_VM = "anti_vm"
    ANTI_SANDBOX = "anti_sandbox"
    ANTI_DISASSEMBLY = "anti_disassembly"
    SELF_MODIFYING = "self_modifying"


@dataclass
class EvasionIndicator:
    """A single detected anti-analysis indicator."""
    category: EvasionCategory
    name: str
    description: str
    offset: int = 0
    confidence: float = 0.0
    severity: str = "medium"  # low, medium, high, critical
    patchable: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the evasion indicator to a JSON-compatible dict."""
        return {
            "category": self.category.value,
            "name": self.name,
            "description": self.description,
            "offset": self.offset,
            "confidence": self.confidence,
            "severity": self.severity,
            "patchable": self.patchable,
            "metadata": self.metadata,
        }


@dataclass
class Patch:
    """A suggested binary patch to neutralise an indicator."""
    offset: int
    original: bytes
    replacement: bytes
    description: str
    indicator_name: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise the patch to a JSON-compatible dict with hex-encoded bytes."""
        return {
            "offset": self.offset,
            "original": self.original.hex(),
            "replacement": self.replacement.hex(),
            "description": self.description,
            "indicator_name": self.indicator_name,
        }


@dataclass
class NormalizationReport:
    """Result of the anti-evasion analysis."""
    indicators: list[EvasionIndicator] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    category_counts: dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0  # 0.0–1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full normalisation report to a JSON-compatible dict."""
        return {
            "indicators": [i.to_dict() for i in self.indicators],
            "patches": [p.to_dict() for p in self.patches],
            "category_counts": self.category_counts,
            "risk_score": self.risk_score,
            "total_indicators": len(self.indicators),
            "total_patches": len(self.patches),
        }


# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

# Import names that indicate anti-debug behaviour
_ANTI_DEBUG_IMPORTS: dict[bytes, tuple[str, str]] = {
    b"IsDebuggerPresent": ("IsDebuggerPresent", "Direct debugger detection"),
    b"CheckRemoteDebuggerPresent": ("CheckRemoteDebugger", "Remote debugger detection"),
    b"NtQueryInformationProcess": ("NtQueryInformationProcess", "NT process info query (debug flags)"),
    b"NtQuerySystemInformation": ("NtQuerySystemInformation", "System info query (process list)"),
    b"OutputDebugString": ("OutputDebugString", "Debug string output (side-channel)"),
    b"NtSetInformationThread": ("NtSetInformationThread", "Thread hiding from debugger"),
    b"NtClose": ("NtClose_antidebug", "Invalid handle exception trick"),
    b"GetTickCount": ("GetTickCount", "Timing-based anti-debug"),
    b"QueryPerformanceCounter": ("QueryPerformanceCounter", "High-res timing check"),
    b"SetUnhandledExceptionFilter": ("SEH_antidebug", "SEH-based debugger detection"),
    b"RaiseException": ("RaiseException", "Exception-based anti-debug"),
    b"VirtualProtect": ("VirtualProtect", "Memory permission manipulation"),
}

# VM / sandbox environment artefact strings
_ENV_ARTEFACTS: dict[bytes, tuple[str, EvasionCategory]] = {
    b"VMware": ("VMware detection", EvasionCategory.ANTI_VM),
    b"VBox": ("VirtualBox detection", EvasionCategory.ANTI_VM),
    b"VBOX": ("VirtualBox detection", EvasionCategory.ANTI_VM),
    b"Virtual": ("Virtual machine detection", EvasionCategory.ANTI_VM),
    b"QEMU": ("QEMU detection", EvasionCategory.ANTI_VM),
    b"Xen": ("Xen hypervisor detection", EvasionCategory.ANTI_VM),
    b"Hyper-V": ("Hyper-V detection", EvasionCategory.ANTI_VM),
    b"Sandboxie": ("Sandboxie detection", EvasionCategory.ANTI_SANDBOX),
    b"SbieDll": ("Sandboxie DLL detection", EvasionCategory.ANTI_SANDBOX),
    b"cuckoomon": ("Cuckoo sandbox detection", EvasionCategory.ANTI_SANDBOX),
    b"dbghelp": ("Debug helper DLL detection", EvasionCategory.ANTI_DEBUG),
    b"sbiedll": ("Sandboxie low-level", EvasionCategory.ANTI_SANDBOX),
    b"\\\\SICE": ("SoftICE device detection", EvasionCategory.ANTI_DEBUG),
    b"\\\\NTICE": ("SoftICE NT detection", EvasionCategory.ANTI_DEBUG),
    b"wine_get_unix_file_name": ("Wine/Linux detection", EvasionCategory.ANTI_VM),
}

# Byte patterns for timing / anti-debug instructions
_INSTRUCTION_PATTERNS: list[tuple[bytes, str, EvasionCategory, str, bool]] = [
    # (pattern, name, category, description, patchable)
    (b"\x0f\x31", "rdtsc", EvasionCategory.TIMING_CHECK,
     "RDTSC timing check (read Time Stamp Counter)", True),
    (b"\x0f\xa2", "cpuid", EvasionCategory.ENVIRONMENT_CHECK,
     "CPUID — can detect hypervisor bit", False),
    (b"\x0f\x01\xd0", "xgetbv", EvasionCategory.ENVIRONMENT_CHECK,
     "XGETBV — extended CPU state query", False),
    (b"\xcd\x01", "int1", EvasionCategory.ANTI_DEBUG,
     "INT 1 — single-step trap (debugger detection)", True),
    (b"\xcd\x03", "int3_cd03", EvasionCategory.ANTI_DEBUG,
     "INT 3 via CD 03 — breakpoint trap", True),
    (b"\xcc", "int3", EvasionCategory.ANTI_DEBUG,
     "INT 3 breakpoint instruction", False),
    (b"\xf1", "icebp", EvasionCategory.ANTI_DEBUG,
     "ICEBP / INT1 — in-circuit emulator breakpoint", True),
    (b"\x64\xa1\x30\x00\x00\x00", "peb_access_fs30", EvasionCategory.ANTI_DEBUG,
     "PEB access via fs:[0x30] — BeingDebugged flag read", True),
    (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "peb_access_gs60", EvasionCategory.ANTI_DEBUG,
     "PEB access via gs:[0x60] — 64-bit BeingDebugged", True),
]

# Anti-disassembly patterns (junk byte insertion, overlapping instructions)
_ANTI_DISASM_PATTERNS: list[tuple[bytes, str, str]] = [
    (b"\xeb\xff", "jmp_overlap", "JMP $+1 — overlapping instruction trick"),
    (b"\xe8\x00\x00\x00\x00", "call_next", "CALL $+5 — position-independent code / anti-disasm"),
    (b"\x74\x01\xe8", "conditional_junk", "JZ $+3 over CALL — conditional junk insertion"),
]

# Confidence overrides for anti-disasm patterns that are also common in
# legitimate code (e.g. PIC thunks).  Maps pattern name → confidence.
_ANTI_DISASM_CONFIDENCE: dict[str, float] = {
    "call_next": 0.30,   # very common in PIC / __x86.get_pc_thunk
    "jmp_overlap": 0.70,
    "conditional_junk": 0.70,
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class EnvironmentNormalizer:
    """
    Scans a binary for anti-analysis techniques and generates patches.

    By default, instruction-pattern scanning is restricted to executable
    sections (identified from PE/ELF headers) to avoid false positives
    from data that happens to match opcode byte sequences.
    """

    def __init__(self, *, generate_patches: bool = True) -> None:
        self._generate_patches = generate_patches

    # -- public API ---------------------------------------------------------

    def analyze(self, binary_data: bytes) -> NormalizationReport:
        """
        Analyse *binary_data* for anti-evasion indicators.

        Returns
        -------
        NormalizationReport
        """
        indicators: list[EvasionIndicator] = []
        patches: list[Patch] = []

        # Determine executable section ranges
        exec_ranges = self._identify_executable_sections(binary_data)

        # 1. Import-based detection (full binary — searches for name strings)
        indicators.extend(self._scan_imports(binary_data))

        # 2. Instruction-pattern detection (executable sections only)
        instr_indicators, instr_patches = self._scan_instructions(
            binary_data, exec_ranges,
        )
        indicators.extend(instr_indicators)
        patches.extend(instr_patches)

        # 3. Environment artefact strings (full binary — string matching)
        indicators.extend(self._scan_artefact_strings(binary_data))

        # 4. Anti-disassembly patterns (executable sections only)
        indicators.extend(self._scan_anti_disasm(binary_data, exec_ranges))

        # 5. Self-modifying code indicators (full binary — import names)
        indicators.extend(self._scan_self_modifying(binary_data))

        # Build category counts & risk score
        category_counts: dict[str, int] = {}
        for ind in indicators:
            key = ind.category.value
            category_counts[key] = category_counts.get(key, 0) + 1

        risk = self._compute_risk(indicators)

        return NormalizationReport(
            indicators=indicators,
            patches=patches,
            category_counts=category_counts,
            risk_score=risk,
        )

    def apply_patches(
        self,
        binary_data: bytes,
        patches: list[Patch],
    ) -> bytes:
        """
        Apply patches to *binary_data* and return the modified copy.

        Patches are applied in offset order.  Overlapping patches are skipped.
        """
        data = bytearray(binary_data)
        patched_ranges: list[tuple[int, int]] = []

        for p in sorted(patches, key=lambda x: x.offset):
            end = p.offset + len(p.original)
            # Check overlap
            if any(s <= p.offset < e or s < end <= e for s, e in patched_ranges):
                logger.warning("Skipping overlapping patch at 0x%X (%s)", p.offset, p.description)
                continue
            # Verify original bytes
            if data[p.offset : end] != p.original:
                logger.warning(
                    "Byte mismatch at 0x%X for patch %s — skipping",
                    p.offset,
                    p.description,
                )
                continue
            data[p.offset : end] = p.replacement
            patched_ranges.append((p.offset, end))
            logger.info("Applied patch at 0x%X: %s", p.offset, p.description)

        return bytes(data)

    # -- scanners -----------------------------------------------------------

    @staticmethod
    def _identify_executable_sections(
        data: bytes,
    ) -> list[tuple[int, int]]:
        """
        Parse PE or ELF headers to extract (offset, end) ranges of
        executable sections.

        Falls back to the entire binary if the format is unrecognised so
        that non-PE/ELF inputs still get scanned.

        Delegates to :func:`~dragonslayer.analysis.binary_format.parse_binary`
        for the heavy lifting.
        """
        parsed = parse_binary(data)
        return parsed.executable_ranges()

    @staticmethod
    def _in_exec_range(offset: int, exec_ranges: list[tuple[int, int]]) -> bool:
        """Check whether *offset* falls within any executable section."""
        return any(start <= offset < end for start, end in exec_ranges)

    def _scan_imports(self, data: bytes) -> list[EvasionIndicator]:
        """Scan for anti-debug API import names in the binary."""
        results: list[EvasionIndicator] = []
        for sig, (name, desc) in _ANTI_DEBUG_IMPORTS.items():
            idx = data.find(sig)
            if idx != -1:
                results.append(EvasionIndicator(
                    category=EvasionCategory.ANTI_DEBUG,
                    name=name,
                    description=desc,
                    offset=idx,
                    confidence=0.85,
                    severity="high" if b"Debugger" in sig else "medium",
                    patchable=False,
                ))
        return results

    def _scan_instructions(
        self,
        data: bytes,
        exec_ranges: list[tuple[int, int]] | None = None,
    ) -> tuple[list[EvasionIndicator], list[Patch]]:
        """Scan executable sections for anti-debug / timing instruction patterns."""
        indicators: list[EvasionIndicator] = []
        patches: list[Patch] = []
        ranges = exec_ranges or [(0, len(data))]

        for pattern, name, category, desc, patchable in _INSTRUCTION_PATTERNS:
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                # Only flag if the match is within an executable section
                if not self._in_exec_range(idx, ranges):
                    offset = idx + len(pattern)
                    continue
                indicators.append(EvasionIndicator(
                    category=category,
                    name=name,
                    description=desc,
                    offset=idx,
                    confidence=0.90,
                    severity="high" if category == EvasionCategory.ANTI_DEBUG else "medium",
                    patchable=patchable,
                ))
                if patchable and self._generate_patches:
                    nop_bytes = b"\x90" * len(pattern)
                    patches.append(Patch(
                        offset=idx,
                        original=pattern,
                        replacement=nop_bytes,
                        description=f"NOP out {name} at 0x{idx:X}",
                        indicator_name=name,
                    ))
                offset = idx + len(pattern)
        return indicators, patches

    def _scan_artefact_strings(self, data: bytes) -> list[EvasionIndicator]:
        """Scan for VM/sandbox environment artefact strings."""
        results: list[EvasionIndicator] = []
        seen: set[str] = set()
        for sig, (name, category) in _ENV_ARTEFACTS.items():
            idx = data.find(sig)
            if idx != -1 and name not in seen:
                seen.add(name)
                results.append(EvasionIndicator(
                    category=category,
                    name=name,
                    description=f"Found artefact string '{sig.decode(errors='replace')}' at offset 0x{idx:X}",
                    offset=idx,
                    confidence=0.75,
                    severity="medium",
                    patchable=False,
                ))
        return results

    def _scan_anti_disasm(
        self,
        data: bytes,
        exec_ranges: list[tuple[int, int]] | None = None,
    ) -> list[EvasionIndicator]:
        """Scan executable sections for anti-disassembly tricks."""
        results: list[EvasionIndicator] = []
        ranges = exec_ranges or [(0, len(data))]

        for pattern, name, desc in _ANTI_DISASM_PATTERNS:
            offset = 0
            count = 0
            while count < 50:  # cap per pattern
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                if not self._in_exec_range(idx, ranges):
                    offset = idx + len(pattern)
                    continue
                count += 1
                results.append(EvasionIndicator(
                    category=EvasionCategory.ANTI_DISASSEMBLY,
                    name=name,
                    description=desc,
                    offset=idx,
                    confidence=_ANTI_DISASM_CONFIDENCE.get(name, 0.70),
                    severity="low",
                    patchable=False,
                ))
                offset = idx + len(pattern)
        return results

    def _scan_self_modifying(self, data: bytes) -> list[EvasionIndicator]:
        """
        Detect indicators of self-modifying code (SMC).

        Heuristic: look for ``VirtualProtect`` combined with write to
        executable sections, or ``WriteProcessMemory`` targeting self.
        """
        results: list[EvasionIndicator] = []
        if b"VirtualProtect" in data and b"WriteProcessMemory" in data:
            results.append(EvasionIndicator(
                category=EvasionCategory.SELF_MODIFYING,
                name="smc_virtualprotect_write",
                description="VirtualProtect + WriteProcessMemory — likely self-modifying code",
                confidence=0.80,
                severity="high",
                patchable=False,
            ))
        # VirtualAlloc + VirtualProtect combo
        if b"VirtualAlloc" in data and b"VirtualProtect" in data:
            results.append(EvasionIndicator(
                category=EvasionCategory.SELF_MODIFYING,
                name="smc_alloc_protect",
                description="VirtualAlloc + VirtualProtect — dynamic code generation",
                confidence=0.65,
                severity="medium",
                patchable=False,
            ))
        return results

    # -- scoring ------------------------------------------------------------

    @staticmethod
    def _compute_risk(indicators: list[EvasionIndicator]) -> float:
        """Compute a 0.0–1.0 risk score from detected indicators."""
        if not indicators:
            return 0.0

        severity_weights = {"low": 0.1, "medium": 0.25, "high": 0.5, "critical": 1.0}
        total = sum(
            severity_weights.get(i.severity, 0.25) * i.confidence
            for i in indicators
        )
        # Sigmoid-like clamping
        import math
        return round(min(1.0 - math.exp(-total / 3.0), 1.0), 4)
