"""
Built-in Trace Engine
=====================

Produces :class:`~dragonslayer.analysis.trace_ingestion.ExecutionTrace`
from a loaded binary using the Unicorn emulation engine.

This fills the critical gap where the framework could *consume* traces
but could not *produce* them without external tooling.

Usage::

    from dragonslayer.analysis.trace_engine import TraceEngine

    engine = TraceEngine(arch="x86_64")
    trace = engine.trace(binary_data, entry_va=0x401000, max_insns=5000)
    # trace is an ExecutionTrace ready for pipeline consumption
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Unicorn + Capstone imports
# ---------------------------------------------------------------------------
try:
    from unicorn import (
        Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64,
        UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_UNMAPPED, UC_MEM_WRITE, UC_MEM_READ,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP,
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
        UC_X86_REG_EIP,
    )
    UNICORN_AVAILABLE = True
except ImportError:  # pragma: no cover
    UNICORN_AVAILABLE = False

try:
    import capstone  # type: ignore[import-untyped]
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceMemoryAccess,
    TraceControlFlow,
)


# ---------------------------------------------------------------------------
# Disassembler helper
# ---------------------------------------------------------------------------

def _make_disassembler(arch: str):
    """Create a Capstone disassembler, or None if not available."""
    if not CAPSTONE_AVAILABLE:
        return None
    if "64" in arch:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def _disassemble_one(cs, code: bytes, address: int) -> Tuple[str, int]:
    """Disassemble one instruction, return (disasm_text, size)."""
    if cs is not None:
        for insn in cs.disasm(code, address, count=1):
            return f"{insn.mnemonic} {insn.op_str}".strip(), insn.size
    # Fallback — no disassembler
    return f"db 0x{code[0]:02x}" if code else "db 0x00", max(len(code), 1)


# ---------------------------------------------------------------------------
# Register mappings
# ---------------------------------------------------------------------------

_REGS_64 = {
    "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX,
    "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
    "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
    "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9,
    "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
    "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
    "rip": UC_X86_REG_RIP,
} if UNICORN_AVAILABLE else {}

_REGS_32 = {
    "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX,
    "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
    "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
    "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP,
    "eip": UC_X86_REG_EIP,
} if UNICORN_AVAILABLE else {}


# ---------------------------------------------------------------------------
# Trace Engine
# ---------------------------------------------------------------------------

_DEFAULT_STACK_ADDR_64 = 0x7FFF_0000_0000
_DEFAULT_STACK_ADDR_32 = 0x7FFF_0000
_STACK_SIZE = 0x10000  # 64 KiB

# How much unmapped space to auto-map on access
_AUTO_MAP_SIZE = 0x1000


@dataclass
class TraceConfig:
    """Configurable parameters for trace production."""
    max_instructions: int = 10_000
    capture_registers: bool = True
    capture_memory: bool = True
    stack_address: int = 0       # 0 = use default for arch
    stack_size: int = _STACK_SIZE
    auto_map_unmapped: bool = True
    stop_addresses: List[int] = field(default_factory=list)


class TraceEngine:
    """Lightweight Unicorn-based trace producer.

    Creates :class:`ExecutionTrace` objects compatible with the
    rest of the VMDragonSlayer analysis pipeline.

    Parameters
    ----------
    arch : str
        ``"x86_64"`` or ``"x86"`` (32-bit).
    config : TraceConfig | None
        Optional configuration.  Uses defaults when ``None``.
    """

    def __init__(self, arch: str = "x86_64", config: Optional[TraceConfig] = None):
        if not UNICORN_AVAILABLE:
            raise RuntimeError(
                "Unicorn engine is required for TraceEngine. "
                "Install with: pip install unicorn"
            )
        self.arch = arch
        self.config = config or TraceConfig()
        self._is_64 = "64" in arch
        self._cs = _make_disassembler(arch)

        # Unicorn engine setup
        mode = UC_MODE_64 if self._is_64 else UC_MODE_32
        self._uc = Uc(UC_ARCH_X86, mode)
        self._reg_map = _REGS_64 if self._is_64 else _REGS_32
        self._word_size = 8 if self._is_64 else 4
        self._bit_width = 64 if self._is_64 else 32

        # Trace buffers (populated by hooks)
        self._instructions: List[TraceInstruction] = []
        self._mem_accesses: List[TraceMemoryAccess] = []
        self._control_flow: List[TraceControlFlow] = []
        self._insn_count = 0
        self._prev_addr: Optional[int] = None
        self._mapped_regions: List[Tuple[int, int]] = []

    @staticmethod
    def available() -> bool:
        """Return True if Unicorn is installed."""
        return UNICORN_AVAILABLE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def trace(
        self,
        data: bytes,
        entry_va: int,
        *,
        image_base: int = 0x400000,
        max_insns: Optional[int] = None,
        initial_regs: Optional[Dict[str, int]] = None,
    ) -> ExecutionTrace:
        """Produce an execution trace from raw binary content.

        Parameters
        ----------
        data : bytes
            The raw binary content (PE/ELF or raw shellcode).
        entry_va : int
            Virtual address where execution starts.
        image_base : int
            Base address to map *data* at.
        max_insns : int | None
            Override ``config.max_instructions``.
        initial_regs : dict | None
            Register preset values (e.g. ``{"rsi": 0x1234}``).

        Returns
        -------
        ExecutionTrace
            Ready for pipeline consumption.
        """
        max_insns = max_insns or self.config.max_instructions

        # Reset state
        self._instructions.clear()
        self._mem_accesses.clear()
        self._control_flow.clear()
        self._insn_count = 0
        self._prev_addr = None

        # Re-create engine (fresh state)
        mode = UC_MODE_64 if self._is_64 else UC_MODE_32
        self._uc = Uc(UC_ARCH_X86, mode)
        self._mapped_regions.clear()

        # Map binary
        self._map_region(image_base, data)

        # Setup stack
        stack_addr = self.config.stack_address
        if stack_addr == 0:
            stack_addr = _DEFAULT_STACK_ADDR_64 if self._is_64 else _DEFAULT_STACK_ADDR_32
        self._map_zero(stack_addr, self.config.stack_size)

        sp_reg = "rsp" if self._is_64 else "esp"
        sp_val = stack_addr + self.config.stack_size // 2  # middle of stack
        self._write_reg(sp_reg, sp_val)

        # Write a sentinel return address on the stack
        sentinel = 0xDEAD_DEAD_DEAD_DEAD if self._is_64 else 0xDEAD_DEAD
        pack_fmt = "<Q" if self._is_64 else "<I"
        self._uc.mem_write(sp_val, struct.pack(pack_fmt, sentinel))

        # Apply initial registers
        if initial_regs:
            for reg_name, val in initial_regs.items():
                self._write_reg(reg_name.lower(), val)

        # Install hooks
        self._uc.hook_add(UC_HOOK_CODE, self._hook_code)
        if self.config.capture_memory:
            self._uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
            self._uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        if self.config.auto_map_unmapped:
            self._uc.hook_add(
                UC_HOOK_MEM_UNMAPPED,
                self._hook_unmapped,
            )

        # Emulate
        try:
            end_addr = image_base + len(data)
            self._uc.emu_start(
                entry_va,
                end_addr,
                count=max_insns,
            )
        except Exception as exc:
            logger.debug("Emulation stopped: %s", exc)

        return ExecutionTrace(
            instructions=list(self._instructions),
            memory_accesses=list(self._mem_accesses),
            control_flow=list(self._control_flow),
            source="unicorn",
            metadata={
                "arch": self.arch,
                "image_base": image_base,
                "entry_va": entry_va,
                "insn_count": self._insn_count,
            },
        )

    def trace_parsed(
        self,
        parsed_binary,
        data: bytes,
        *,
        entry_va: Optional[int] = None,
        max_insns: Optional[int] = None,
    ) -> ExecutionTrace:
        """Trace a parsed binary using its metadata.

        Parameters
        ----------
        parsed_binary : ParsedBinary
            A binary parsed via :func:`parse_binary`.
        data : bytes
            The raw binary content.
        entry_va : int | None
            Override entry point (defaults to ``parsed_binary.entry_point``).
        max_insns : int | None
            Instruction limit.
        """
        if entry_va is None:
            entry_va = parsed_binary.entry_point

        return self.trace(
            data,
            entry_va=entry_va,
            image_base=parsed_binary.image_base,
            max_insns=max_insns,
        )

    # ------------------------------------------------------------------
    # Memory mapping helpers
    # ------------------------------------------------------------------

    def _map_region(self, base: int, data: bytes) -> None:
        """Map *data* at *base*, page-aligned."""
        aligned_base = base & ~0xFFF
        end = base + len(data)
        aligned_end = (end + 0xFFF) & ~0xFFF
        size = aligned_end - aligned_base

        if not self._region_overlaps(aligned_base, size):
            self._uc.mem_map(aligned_base, size)
            self._mapped_regions.append((aligned_base, size))

        self._uc.mem_write(base, data)

    def _map_zero(self, base: int, size: int) -> None:
        """Map zero-filled memory."""
        aligned_base = base & ~0xFFF
        aligned_size = ((size + 0xFFF) & ~0xFFF) + (base - aligned_base)
        aligned_size = (aligned_size + 0xFFF) & ~0xFFF

        if not self._region_overlaps(aligned_base, aligned_size):
            self._uc.mem_map(aligned_base, aligned_size)
            self._mapped_regions.append((aligned_base, aligned_size))

    def _region_overlaps(self, base: int, size: int) -> bool:
        end = base + size
        for rb, rs in self._mapped_regions:
            if base < rb + rs and end > rb:
                return True
        return False

    # ------------------------------------------------------------------
    # Register helpers
    # ------------------------------------------------------------------

    def _read_reg(self, name: str) -> int:
        uc_id = self._reg_map.get(name)
        if uc_id is not None:
            return self._uc.reg_read(uc_id)
        return 0

    def _write_reg(self, name: str, value: int) -> None:
        uc_id = self._reg_map.get(name)
        if uc_id is not None:
            self._uc.reg_write(uc_id, value)

    def _read_all_regs(self) -> Dict[str, int]:
        return {name: self._uc.reg_read(uc_id) for name, uc_id in self._reg_map.items()}

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def _hook_code(self, uc, address: int, size: int, user_data) -> None:
        """Called before each instruction executes."""
        self._insn_count += 1
        if self._insn_count > self.config.max_instructions:
            uc.emu_stop()
            return

        # Check stop addresses
        if address in self.config.stop_addresses:
            uc.emu_stop()
            return

        # Read raw bytes
        try:
            raw = bytes(uc.mem_read(address, size))
        except Exception:
            raw = b""

        # Disassemble
        disasm, _ = _disassemble_one(self._cs, raw, address)

        # Capture register state
        regs = self._read_all_regs() if self.config.capture_registers else {}

        self._instructions.append(TraceInstruction(
            address=address,
            size=size,
            raw_bytes=raw,
            disassembly=disasm,
            registers=regs,
        ))

        # Control-flow edges
        if self._prev_addr is not None:
            mnemonic = disasm.split()[0].lower() if disasm else ""
            if mnemonic.startswith("j"):
                cf_type = "jcc" if mnemonic != "jmp" else "jmp"
            elif mnemonic == "call":
                cf_type = "call"
            elif mnemonic == "ret":
                cf_type = "ret"
            else:
                cf_type = ""
            if cf_type:
                self._control_flow.append(TraceControlFlow(
                    type=cf_type, source=self._prev_addr, target=address,
                ))
        self._prev_addr = address

    def _hook_mem_read(self, uc, access, address: int, size: int, value, user_data) -> None:
        self._mem_accesses.append(TraceMemoryAccess(
            type="R", address=address, size=size, value=0,
        ))

    def _hook_mem_write(self, uc, access, address: int, size: int, value, user_data) -> None:
        self._mem_accesses.append(TraceMemoryAccess(
            type="W", address=address, size=size, value=value,
        ))

    def _hook_unmapped(self, uc, access, address: int, size: int, value, user_data) -> bool:
        """Auto-map unmapped memory regions on access."""
        aligned = address & ~0xFFF
        map_size = max(_AUTO_MAP_SIZE, ((size + 0xFFF) & ~0xFFF))
        try:
            if not self._region_overlaps(aligned, map_size):
                uc.mem_map(aligned, map_size)
                self._mapped_regions.append((aligned, map_size))
            return True  # resume execution
        except Exception:
            return False  # stop
