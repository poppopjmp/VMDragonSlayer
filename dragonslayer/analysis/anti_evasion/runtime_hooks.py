"""
Anti-Evasion Runtime Hooks
============================

Provides *runtime* anti-evasion hooks that intercept anti-analysis
APIs, timing instructions, and environment probes during dynamic
execution.  Where :mod:`environment_normalizer` performs *static*
detection and patch generation, this module supplies hook descriptors
that Qiling, angr, and Triton plugins install at analysis time so
that the target binary never observes a debugger or emulator.

Hook Categories
---------------

* **Timing normalisation** — ``rdtsc`` / ``rdtscp`` return monotonically
  increasing but credible values so delta-time checks pass.
* **CPUID masking** — hypervisor-present bit (ECX.31) cleared; vendor
  string set to ``GenuineIntel``.
* **Debug flag suppression** — ``IsDebuggerPresent`` → 0,
  ``NtQueryInformationProcess(ProcessDebugPort)`` → 0,
  PEB.BeingDebugged → 0.
* **Environment normalisation** — ``GetTickCount`` / ``QueryPerformanceCounter``
  return plausible values; sandbox-detection registry keys suppressed.

Usage::

    from dragonslayer.analysis.anti_evasion.runtime_hooks import (
        build_hook_set,
        apply_hooks_to_qiling,
        apply_hooks_to_angr,
        apply_hooks_to_triton,
    )

    hooks = build_hook_set(categories={"timing", "debug", "cpuid", "env"})
    apply_hooks_to_qiling(ql, hooks)
"""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Data types
# ═══════════════════════════════════════════════════════════════════════════

class HookCategory(Enum):
    """Hook category for selective installation."""
    TIMING = "timing"
    CPUID = "cpuid"
    DEBUG = "debug"
    ENV = "env"


@dataclass
class HookDescriptor:
    """Describes a single anti-evasion hook.

    A hook descriptor is engine-agnostic: it specifies *what* to intercept
    and *what* to return, and the ``apply_hooks_to_*`` functions translate
    it into the engine's native hook mechanism.
    """
    name: str
    category: HookCategory
    description: str
    # For API hooks: the API / function name to intercept
    api_name: str = ""
    # For instruction hooks: the opcode bytes to intercept
    opcode_bytes: bytes = b""
    # Fixed return value for API hooks (None = use callback)
    return_value: Optional[int] = None
    # For register-result hooks (e.g. CPUID): register → value
    register_results: Dict[str, int] = field(default_factory=dict)
    # Priority: lower = installed first
    priority: int = 50
    # Metadata for engine-specific behaviour
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the hook descriptor to a JSON-compatible dict."""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "api_name": self.api_name,
            "return_value": self.return_value,
        }


@dataclass
class HookSet:
    """A collection of hook descriptors to install."""
    hooks: List[HookDescriptor] = field(default_factory=list)
    categories: Set[HookCategory] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the hook set to a JSON-compatible dict."""
        return {
            "hook_count": len(self.hooks),
            "categories": sorted(c.value for c in self.categories),
            "hooks": [h.to_dict() for h in self.hooks],
        }

    def by_category(self, cat: HookCategory) -> List[HookDescriptor]:
        """Return hooks belonging to the given :class:`HookCategory`."""
        return [h for h in self.hooks if h.category == cat]


@dataclass
class HookInstallResult:
    """Result of applying hooks to an engine."""
    installed: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)

    @property
    def success_count(self) -> int:
        """Number of hooks successfully installed."""
        return len(self.installed)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the installation result to a JSON-compatible dict."""
        return {
            "installed_count": len(self.installed),
            "installed": self.installed,
            "skipped": self.skipped,
            "errors": self.errors,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Hook definitions
# ═══════════════════════════════════════════════════════════════════════════

# --- Timing hooks ---

_RDTSC_HOOK = HookDescriptor(
    name="rdtsc_normalize",
    category=HookCategory.TIMING,
    description="RDTSC returns monotonic credible timestamps (small delta)",
    opcode_bytes=b"\x0f\x31",
    register_results={},  # filled dynamically
    priority=10,
    metadata={"instruction": "rdtsc", "initial_tsc": 0x1_0000_0000, "delta": 100},
)

_RDTSCP_HOOK = HookDescriptor(
    name="rdtscp_normalize",
    category=HookCategory.TIMING,
    description="RDTSCP returns credible timestamps + processor ID",
    opcode_bytes=b"\x0f\x01\xf9",
    register_results={},
    priority=10,
    metadata={"instruction": "rdtscp", "initial_tsc": 0x1_0000_0000, "delta": 100},
)

_GET_TICK_COUNT_HOOK = HookDescriptor(
    name="GetTickCount_normalize",
    category=HookCategory.TIMING,
    description="GetTickCount returns plausible monotonic value",
    api_name="GetTickCount",
    return_value=None,  # dynamic: base + elapsed
    priority=20,
    metadata={"base_tick": 60000},
)

_QPC_HOOK = HookDescriptor(
    name="QueryPerformanceCounter_normalize",
    category=HookCategory.TIMING,
    description="QueryPerformanceCounter returns plausible value",
    api_name="QueryPerformanceCounter",
    return_value=1,  # success
    priority=20,
    metadata={"base_counter": 0x100000},
)

# --- CPUID hooks ---

_CPUID_HOOK = HookDescriptor(
    name="cpuid_mask_hypervisor",
    category=HookCategory.CPUID,
    description="CPUID clears hypervisor-present bit (ECX.31) and spoofs GenuineIntel",
    opcode_bytes=b"\x0f\xa2",
    register_results={},  # dynamic per leaf
    priority=10,
    metadata={
        "instruction": "cpuid",
        # Leaf 0: vendor string "GenuineIntel"
        "leaf0_ebx": 0x756e6547,  # "Genu"
        "leaf0_edx": 0x49656e69,  # "ineI"
        "leaf0_ecx": 0x6c65746e,  # "ntel"
        # Leaf 1: clear hypervisor bit (ECX bit 31)
        "leaf1_ecx_mask": 0x7FFFFFFF,
    },
)

# --- Debug hooks ---

_IS_DEBUGGER_PRESENT_HOOK = HookDescriptor(
    name="IsDebuggerPresent_zero",
    category=HookCategory.DEBUG,
    description="IsDebuggerPresent returns 0",
    api_name="IsDebuggerPresent",
    return_value=0,
    priority=10,
)

_CHECK_REMOTE_DEBUGGER_HOOK = HookDescriptor(
    name="CheckRemoteDebuggerPresent_zero",
    category=HookCategory.DEBUG,
    description="CheckRemoteDebuggerPresent sets pbDebuggerPresent to 0",
    api_name="CheckRemoteDebuggerPresent",
    return_value=1,  # TRUE (success), but writes 0 to output param
    priority=10,
    metadata={"writes_zero_to_param2": True},
)

_NT_QUERY_INFO_HOOK = HookDescriptor(
    name="NtQueryInformationProcess_clean",
    category=HookCategory.DEBUG,
    description="NtQueryInformationProcess returns clean values for debug queries",
    api_name="NtQueryInformationProcess",
    return_value=0,  # STATUS_SUCCESS
    priority=10,
    metadata={
        "ProcessDebugPort": 7,  # info class for debug port
        "ProcessDebugObjectHandle": 0x1E,
    },
)

_PEB_BEING_DEBUGGED_HOOK = HookDescriptor(
    name="peb_being_debugged_clear",
    category=HookCategory.DEBUG,
    description="PEB.BeingDebugged byte cleared to 0 on access",
    opcode_bytes=b"",  # memory hook, not instruction hook
    priority=5,
    metadata={"peb_offset_32": 0x30, "peb_offset_64": 0x60, "being_debugged_offset": 2},
)

_NT_SET_INFO_THREAD_HOOK = HookDescriptor(
    name="NtSetInformationThread_nop",
    category=HookCategory.DEBUG,
    description="NtSetInformationThread(HideFromDebugger) returns success without hiding",
    api_name="NtSetInformationThread",
    return_value=0,  # STATUS_SUCCESS
    priority=15,
)

_OUTPUT_DEBUG_STRING_HOOK = HookDescriptor(
    name="OutputDebugString_nop",
    category=HookCategory.DEBUG,
    description="OutputDebugStringA/W returns success without side-channel leak",
    api_name="OutputDebugStringA",
    return_value=1,
    priority=30,
)

# --- Environment hooks ---

_VIRTUAL_PROTECT_MONITOR = HookDescriptor(
    name="VirtualProtect_monitor",
    category=HookCategory.ENV,
    description="VirtualProtect calls logged (self-modifying code detection)",
    api_name="VirtualProtect",
    return_value=None,  # pass through, but log
    priority=40,
    metadata={"log_only": True},
)

_REG_QUERY_HOOK = HookDescriptor(
    name="RegQueryValueEx_sanitize",
    category=HookCategory.ENV,
    description="RegQueryValueEx hides VM/sandbox registry artefacts",
    api_name="RegQueryValueExW",
    return_value=None,
    priority=30,
    metadata={
        "blocked_substrings": [
            "VMware", "VBox", "VBOX", "Virtual", "QEMU", "Sandboxie",
        ],
    },
)

_GET_MODULE_HANDLE_HOOK = HookDescriptor(
    name="GetModuleHandle_sanitize",
    category=HookCategory.ENV,
    description="GetModuleHandle denies sandbox DLLs (sbiedll, cuckoomon)",
    api_name="GetModuleHandleA",
    return_value=None,
    priority=30,
    metadata={
        "blocked_modules": [
            "sbiedll.dll", "cuckoomon.dll", "dbghelp.dll",
            "api_log.dll", "pstorec.dll",
        ],
    },
)


# All known hook descriptors in priority order.
_ALL_HOOKS: List[HookDescriptor] = sorted([
    _RDTSC_HOOK, _RDTSCP_HOOK, _GET_TICK_COUNT_HOOK, _QPC_HOOK,
    _CPUID_HOOK,
    _IS_DEBUGGER_PRESENT_HOOK, _CHECK_REMOTE_DEBUGGER_HOOK,
    _NT_QUERY_INFO_HOOK, _PEB_BEING_DEBUGGED_HOOK,
    _NT_SET_INFO_THREAD_HOOK, _OUTPUT_DEBUG_STRING_HOOK,
    _VIRTUAL_PROTECT_MONITOR, _REG_QUERY_HOOK, _GET_MODULE_HANDLE_HOOK,
], key=lambda h: h.priority)


# ═══════════════════════════════════════════════════════════════════════════
# Hook set builder
# ═══════════════════════════════════════════════════════════════════════════

def build_hook_set(
    categories: Optional[Set[str]] = None,
    *,
    exclude_names: Optional[Set[str]] = None,
) -> HookSet:
    """Build a :class:`HookSet` from the registered hook descriptors.

    Args:
        categories: If provided, only include hooks from these categories.
            Valid values: ``"timing"``, ``"cpuid"``, ``"debug"``, ``"env"``.
            If ``None``, all categories are included.
        exclude_names: Hook names to exclude (e.g. ``{"rdtsc_normalize"}``).

    Returns:
        A :class:`HookSet` ready for installation.
    """
    if categories is not None:
        cats = {HookCategory(c) for c in categories}
    else:
        cats = set(HookCategory)

    exclude = exclude_names or set()

    hooks = [
        h for h in _ALL_HOOKS
        if h.category in cats and h.name not in exclude
    ]

    return HookSet(
        hooks=hooks,
        categories={h.category for h in hooks},
    )


def build_hook_set_from_report(
    report: Any,
    *,
    min_confidence: float = 0.5,
) -> HookSet:
    """Build hooks based on an :class:`EnvironmentNormalizer` report.

    Only creates hooks for categories where indicators were detected
    with confidence ≥ *min_confidence*.

    Args:
        report: A ``NormalizationReport`` (or its ``.to_dict()`` output).
        min_confidence: Minimum indicator confidence to trigger hooks.

    Returns:
        A :class:`HookSet` tailored to the binary's evasion profile.
    """
    if hasattr(report, "to_dict"):
        d = report.to_dict()
    elif isinstance(report, dict):
        d = report
    else:
        return HookSet()

    indicators = d.get("indicators", [])
    if not indicators:
        return HookSet()

    # Map report categories → hook categories
    _CAT_MAP: Dict[str, Set[HookCategory]] = {
        "timing_check": {HookCategory.TIMING},
        "anti_debug": {HookCategory.DEBUG},
        "environment_check": {HookCategory.CPUID, HookCategory.ENV},
        "anti_vm": {HookCategory.CPUID, HookCategory.ENV},
        "anti_sandbox": {HookCategory.ENV},
        "self_modifying": {HookCategory.ENV},
    }

    needed_cats: Set[HookCategory] = set()
    for ind in indicators:
        cat_str = ind.get("category", "") if isinstance(ind, dict) else getattr(ind, "category", "")
        if hasattr(cat_str, "value"):
            cat_str = cat_str.value
        conf = ind.get("confidence", 0) if isinstance(ind, dict) else getattr(ind, "confidence", 0)
        if conf >= min_confidence:
            for hc in _CAT_MAP.get(cat_str, set()):
                needed_cats.add(hc)

    if not needed_cats:
        return HookSet()

    return build_hook_set(categories={c.value for c in needed_cats})


# ═══════════════════════════════════════════════════════════════════════════
# Timing state manager
# ═══════════════════════════════════════════════════════════════════════════

class TimingState:
    """Tracks monotonically increasing synthetic timestamps.

    Each call to :meth:`next_tsc` returns a credible TSC value with a
    small, realistic delta (~100–500 cycles per instruction).
    """

    def __init__(
        self,
        initial: int = 0x1_0000_0000,
        delta_range: Tuple[int, int] = (80, 300),
    ) -> None:
        self._tsc = initial
        self._delta_min, self._delta_max = delta_range
        self._tick_base = 60_000  # milliseconds
        self._call_count = 0

    def next_tsc(self) -> int:
        """Return the next synthetic TSC value."""
        import random
        self._tsc += random.randint(self._delta_min, self._delta_max)
        return self._tsc

    def split_edx_eax(self, tsc: int) -> Tuple[int, int]:
        """Split a 64-bit TSC into (edx, eax) for RDTSC result."""
        eax = tsc & 0xFFFFFFFF
        edx = (tsc >> 32) & 0xFFFFFFFF
        return edx, eax

    def next_tick(self) -> int:
        """Return the next monotonic tick count (ms)."""
        self._call_count += 1
        return self._tick_base + self._call_count * 16  # ~16ms per call


# ═══════════════════════════════════════════════════════════════════════════
# Engine-specific hook application
# ═══════════════════════════════════════════════════════════════════════════

def apply_hooks_to_qiling(
    ql: Any,
    hook_set: HookSet,
) -> HookInstallResult:
    """Install hooks into a Qiling emulator instance.

    For each :class:`HookDescriptor` in *hook_set*:

    * **API hooks**: ``ql.os.set_api(api_name, callback)``
    * **Instruction hooks**: ``ql.hook_insn()`` for RDTSC / CPUID
    * **Memory hooks**: PEB.BeingDebugged byte zeroing

    Args:
        ql: A Qiling instance (the real Qiling object).
        hook_set: The hook set to install.

    Returns:
        :class:`HookInstallResult` with installed / skipped / error info.
    """
    result = HookInstallResult()
    timing = TimingState()

    for hook in hook_set.hooks:
        try:
            if hook.name == "rdtsc_normalize":
                _install_qiling_rdtsc(ql, timing)
                result.installed.append(hook.name)

            elif hook.name == "cpuid_mask_hypervisor":
                _install_qiling_cpuid(ql, hook)
                result.installed.append(hook.name)

            elif hook.api_name and hook.return_value is not None:
                _install_qiling_api_hook(ql, hook)
                result.installed.append(hook.name)

            elif hook.metadata.get("log_only"):
                result.skipped.append(hook.name)

            else:
                result.skipped.append(hook.name)

        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
            result.errors[hook.name] = str(exc)
            logger.debug("Failed to install Qiling hook %s: %s", hook.name, exc)

    return result


def _install_qiling_rdtsc(ql: Any, timing: TimingState) -> None:
    """Install RDTSC hook that returns synthetic timestamps."""

    def _rdtsc_hook(ql_inner: Any) -> None:
        tsc = timing.next_tsc()
        edx, eax = timing.split_edx_eax(tsc)
        ql_inner.arch.regs.write("eax", eax)
        ql_inner.arch.regs.write("edx", edx)

    ql.hook_insn(_rdtsc_hook, 0x0F31)  # RDTSC opcode value


def _install_qiling_cpuid(ql: Any, hook: HookDescriptor) -> None:
    """Install CPUID hook that masks hypervisor bit."""
    try:
        def _cpuid_hook(ql_inner: Any) -> None:
            leaf = ql_inner.arch.regs.read("eax")
            if leaf == 0:
                ql_inner.arch.regs.write("ebx", hook.metadata["leaf0_ebx"])
                ql_inner.arch.regs.write("edx", hook.metadata["leaf0_edx"])
                ql_inner.arch.regs.write("ecx", hook.metadata["leaf0_ecx"])
            elif leaf == 1:
                ecx = ql_inner.arch.regs.read("ecx")
                ecx &= hook.metadata["leaf1_ecx_mask"]
                ql_inner.arch.regs.write("ecx", ecx)

        ql.hook_insn(_cpuid_hook, 0x0FA2)
    except (ValueError, TypeError, AttributeError, RuntimeError):
        logger.debug("Qiling CPUID hook installation failed")
        raise


def _install_qiling_api_hook(ql: Any, hook: HookDescriptor) -> None:
    """Install a simple API hook that returns a fixed value."""
    ret_val = hook.return_value

    def _api_hook(ql_inner: Any) -> int:
        return ret_val if ret_val is not None else 0

    try:
        ql.os.set_api(hook.api_name, _api_hook)
    except (ValueError, TypeError, AttributeError, RuntimeError):
        logger.debug("Qiling API hook for %s failed", hook.api_name)
        raise


def apply_hooks_to_angr(
    proj: Any,
    hook_set: HookSet,
) -> HookInstallResult:
    """Install hooks as angr SimProcedures.

    For each API hook in *hook_set*, creates a ``SimProcedure`` that
    returns the specified value and hooks the corresponding symbol in
    the angr project.

    Args:
        proj: An angr ``Project`` instance.
        hook_set: The hook set to install.

    Returns:
        :class:`HookInstallResult`.
    """
    result = HookInstallResult()

    for hook in hook_set.hooks:
        if not hook.api_name:
            result.skipped.append(hook.name)
            continue

        try:
            _install_angr_api_hook(proj, hook)
            result.installed.append(hook.name)
        except (ImportError, ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
            result.errors[hook.name] = str(exc)
            logger.debug("Failed to install angr hook %s: %s", hook.name, exc)

    return result


def _install_angr_api_hook(proj: Any, hook: HookDescriptor) -> None:
    """Create and hook an angr SimProcedure for an API."""
    try:
        import angr  # type: ignore

        ret_val = hook.return_value if hook.return_value is not None else 0

        class AntiEvasionProc(angr.SimProcedure):
            def run(self, *args: Any, **kwargs: Any) -> Any:
                return ret_val

        proj.hook_symbol(hook.api_name, AntiEvasionProc())
    except ImportError:
        raise
    except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
        # Symbol may not exist in the binary
        logger.debug("angr hook_symbol(%s) failed: %s", hook.api_name, exc)
        raise


def apply_hooks_to_triton(
    tc: Any,
    hook_set: HookSet,
    *,
    is_64: bool = True,
) -> HookInstallResult:
    """Install hooks into a Triton context.

    Triton doesn't support API-level hooking (it works at the instruction
    level), so this function:

    * Registers instruction callbacks for RDTSC and CPUID.
    * Returns skipped info for API-level hooks (those must be handled
      by patching the binary or by the caller's instruction loop).

    Args:
        tc: A ``TritonContext`` instance.
        hook_set: The hook set to install.
        is_64: Whether the architecture is 64-bit.

    Returns:
        :class:`HookInstallResult`.
    """
    result = HookInstallResult()
    timing = TimingState()

    for hook in hook_set.hooks:
        try:
            if hook.name == "rdtsc_normalize":
                _install_triton_rdtsc(tc, timing, is_64)
                result.installed.append(hook.name)
            elif hook.name == "cpuid_mask_hypervisor":
                _install_triton_cpuid(tc, hook, is_64)
                result.installed.append(hook.name)
            elif hook.api_name:
                # Triton can't directly hook APIs — skip with note
                result.skipped.append(hook.name)
            else:
                result.skipped.append(hook.name)
        except (ImportError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
            result.errors[hook.name] = str(exc)

    return result


def _install_triton_rdtsc(tc: Any, timing: TimingState, is_64: bool) -> None:
    """Install Triton RDTSC callback."""
    try:
        from triton import CALLBACK, OPCODE  # type: ignore

        def _rdtsc_cb(ctx: Any, insn: Any) -> None:
            if insn.getType() == OPCODE.X86.RDTSC:
                tsc = timing.next_tsc()
                edx, eax = timing.split_edx_eax(tsc)
                ctx.setConcreteRegisterValue(ctx.registers.eax, eax)
                ctx.setConcreteRegisterValue(ctx.registers.edx, edx)

        tc.addCallback(CALLBACK.BEFORE, _rdtsc_cb)
    except ImportError:
        raise
    except (ValueError, TypeError, AttributeError, RuntimeError):
        logger.debug("Triton RDTSC callback installation failed")
        raise


def _install_triton_cpuid(tc: Any, hook: HookDescriptor, is_64: bool) -> None:
    """Install Triton CPUID callback."""
    try:
        from triton import CALLBACK, OPCODE  # type: ignore

        def _cpuid_cb(ctx: Any, insn: Any) -> None:
            if insn.getType() == OPCODE.X86.CPUID:
                leaf = int(ctx.getConcreteRegisterValue(ctx.registers.eax))
                if leaf == 0:
                    ctx.setConcreteRegisterValue(
                        ctx.registers.ebx, hook.metadata["leaf0_ebx"]
                    )
                    ctx.setConcreteRegisterValue(
                        ctx.registers.edx, hook.metadata["leaf0_edx"]
                    )
                    ctx.setConcreteRegisterValue(
                        ctx.registers.ecx, hook.metadata["leaf0_ecx"]
                    )
                elif leaf == 1:
                    ecx = int(ctx.getConcreteRegisterValue(ctx.registers.ecx))
                    ecx &= hook.metadata["leaf1_ecx_mask"]
                    ctx.setConcreteRegisterValue(ctx.registers.ecx, ecx)

        tc.addCallback(CALLBACK.BEFORE, _cpuid_cb)
    except ImportError:
        raise
    except (ValueError, TypeError, AttributeError, RuntimeError):
        logger.debug("Triton CPUID callback installation failed")
        raise


# ═══════════════════════════════════════════════════════════════════════════
# Integration with EnvironmentNormalizer
# ═══════════════════════════════════════════════════════════════════════════

def hooks_for_binary(binary_data: bytes) -> HookSet:
    """Convenience: scan a binary and return the appropriate hook set.

    Combines :class:`~environment_normalizer.EnvironmentNormalizer`
    detection with :func:`build_hook_set_from_report`.

    Args:
        binary_data: Raw binary bytes.

    Returns:
        A :class:`HookSet` tailored to the binary's evasion profile.
        Falls back to a full hook set if the normalizer is unavailable.
    """
    try:
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EnvironmentNormalizer,
        )
        normalizer = EnvironmentNormalizer(generate_patches=False)
        report = normalizer.analyze(binary_data)
        hook_set = build_hook_set_from_report(report)
        if hook_set.hooks:
            return hook_set
    except (ImportError, ValueError, TypeError, AttributeError, RuntimeError):
        logger.debug("EnvironmentNormalizer failed, using full hook set")

    return build_hook_set()
