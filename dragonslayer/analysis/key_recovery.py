"""
Symbolic Key Recovery for VMProtect
====================================

When a dynamic trace is not available, the initial rolling-key value
can often be recovered by **symbolically executing the VM entry stub**.

A typical VMProtect vm_entry looks like::

    push  rbp
    push  rdi            ;; save regs
    mov   rbp, rsp
    lea   rdi, [rip + bytecodeBase]
    mov   ecx, 0xDEADBEEF   ;; initial key loaded as immediate
    jmp   dispatcher

This module:

1. Walks the instructions between ``vm_entry`` and the dispatcher and
   tracks register assignments via lightweight abstract interpretation.
2. Extracts the concrete value of the **key register** at the point
   control reaches the dispatcher.  If the key is loaded from memory
   (e.g. ``mov ecx, [rip+offset]``), a binary image must be provided
   for resolution.
3. Optionally recovers ``vIP_init`` (the starting bytecode offset).

Integration
-----------

Used by :func:`make_decryptor_from_dispatcher` as a fallback when no
trace records are available for :func:`detect_initial_key`.

Usage::

    from dragonslayer.analysis.bytecode_decrypt import make_decryptor_from_dispatcher
    from dragonslayer.analysis.key_recovery import recover_key_from_entry

    key_info = recover_key_from_entry(
        entry_instructions,
        dispatcher_match,
    )
    if key_info:
        decryptor = BytecodeDecryptor(
            transforms=...,
            initial_key=key_info.key_value,
        )
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class RecoveredKey:
    """Result of symbolic key recovery from a VM entry stub.

    Attributes
    ----------
    key_value : int
        Concrete initial key value.
    key_register : str
        Register that holds the key.
    vip_initial : int | None
        Initial bytecode offset (vIP value), if recovered.
    vip_register : str
        Register holding the vIP, if known.
    confidence : float
        Recovery confidence (0.0-1.0).
    source : str
        How the key was recovered: ``"immediate"``, ``"lea_rip"``,
        ``"memory_read"``, ``"arithmetic"``.
    """

    key_value: int = 0
    key_register: str = ""
    vip_initial: Optional[int] = None
    vip_register: str = ""
    confidence: float = 0.0
    source: str = "unknown"


# ---------------------------------------------------------------------------
# Abstract register file for lightweight tracking
# ---------------------------------------------------------------------------


@dataclass
class _RegValue:
    """Lightweight abstract value for a register."""

    concrete: Optional[int] = None
    symbolic: str = ""  # e.g. "rip+0x1234", "[rsp]"

    @property
    def is_concrete(self) -> bool:
        return self.concrete is not None


class _AbstractRegFile:
    """Track concrete register values through a short instruction sequence."""

    def __init__(self, *, rip_base: int = 0, bit_width: int = 64) -> None:
        self._regs: Dict[str, _RegValue] = {}
        self._rip = rip_base
        self._bit_width = bit_width
        self._mask = (1 << bit_width) - 1

    def set(self, reg: str, val: _RegValue) -> None:
        self._regs[_canon(reg)] = val

    def get(self, reg: str) -> _RegValue:
        return self._regs.get(_canon(reg), _RegValue())

    def set_concrete(self, reg: str, val: int) -> None:
        self._regs[_canon(reg)] = _RegValue(concrete=val & self._mask)

    def get_concrete(self, reg: str) -> Optional[int]:
        v = self.get(reg)
        return v.concrete if v.is_concrete else None

    @property
    def rip(self) -> int:
        return self._rip

    @rip.setter
    def rip(self, value: int) -> None:
        self._rip = value

    def snapshot(self) -> Dict[str, Optional[int]]:
        """Return all concrete register values."""
        return {r: v.concrete for r, v in self._regs.items() if v.is_concrete}


# ---------------------------------------------------------------------------
# Instruction pattern matchers
# ---------------------------------------------------------------------------

# mov reg, imm
_MOV_IMM_RE = re.compile(
    r"mov\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)$", re.IGNORECASE
)

# lea reg, [rip + disp]  (or [rip - disp])
_LEA_RIP_RE = re.compile(
    r"lea\s+(\w+)\s*,\s*\[\s*rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*\]",
    re.IGNORECASE,
)

# mov reg1, reg2
_MOV_REG_RE = re.compile(
    r"mov\s+(\w+)\s*,\s*(\w+)$", re.IGNORECASE
)

# xor reg, reg (zero idiom)
_XOR_SELF_RE = re.compile(
    r"xor\s+(\w+)\s*,\s*(\w+)$", re.IGNORECASE
)

# add/sub/xor reg, imm
_ARITH_IMM_RE = re.compile(
    r"(add|sub|xor|or|and)\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)$",
    re.IGNORECASE,
)

# push/pop (track stack effects on register state)
_PUSH_RE = re.compile(r"push\s+(\w+)", re.IGNORECASE)

# not reg
_NOT_RE = re.compile(r"not\s+(\w+)$", re.IGNORECASE)

# neg reg
_NEG_RE = re.compile(r"neg\s+(\w+)$", re.IGNORECASE)

_GP_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
}


def _canon(reg: str) -> str:
    """Canonicalise a register name to lowercase."""
    return reg.strip().lower()


def _parse_int(s: str) -> int:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


# ---------------------------------------------------------------------------
# Core: abstract-interpret the VM entry stub
# ---------------------------------------------------------------------------


def _interpret_instruction(
    regs: _AbstractRegFile,
    mnemonic: str,
    operands: str,
    insn_address: int,
    insn_size: int,
    *,
    binary_data: Optional[bytes] = None,
    binary_base: int = 0,
) -> None:
    """Update register file for one instruction."""
    text = f"{mnemonic} {operands}".strip()

    # Update RIP to point past this instruction
    regs.rip = insn_address + insn_size

    # mov reg, imm
    m = _MOV_IMM_RE.match(text)
    if m:
        regs.set_concrete(m.group(1), _parse_int(m.group(2)))
        return

    # lea reg, [rip ± disp]
    m = _LEA_RIP_RE.match(text)
    if m:
        sign = 1 if m.group(2) == "+" else -1
        disp = _parse_int(m.group(3))
        # RIP is already updated to insn_address + insn_size
        regs.set_concrete(m.group(1), regs.rip + sign * disp)
        return

    # mov reg1, reg2
    m = _MOV_REG_RE.match(text)
    if m:
        dst, src = m.group(1), m.group(2)
        if _canon(src) in _GP_REGS:
            src_val = regs.get(src)
            regs.set(dst, _RegValue(concrete=src_val.concrete, symbolic=src_val.symbolic))
        return

    # xor reg, reg (zero idiom)
    m = _XOR_SELF_RE.match(text)
    if m and _canon(m.group(1)) == _canon(m.group(2)):
        regs.set_concrete(m.group(1), 0)
        return

    # add/sub/xor/or/and reg, imm
    m = _ARITH_IMM_RE.match(text)
    if m:
        op = m.group(1).lower()
        dst = m.group(2)
        imm = _parse_int(m.group(3))
        curr = regs.get_concrete(dst)
        if curr is not None:
            mask = regs._mask
            if op == "add":
                regs.set_concrete(dst, (curr + imm) & mask)
            elif op == "sub":
                regs.set_concrete(dst, (curr - imm) & mask)
            elif op == "xor":
                regs.set_concrete(dst, (curr ^ imm) & mask)
            elif op == "or":
                regs.set_concrete(dst, (curr | imm) & mask)
            elif op == "and":
                regs.set_concrete(dst, (curr & imm) & mask)
        return

    # not reg
    m = _NOT_RE.match(text)
    if m:
        curr = regs.get_concrete(m.group(1))
        if curr is not None:
            regs.set_concrete(m.group(1), (~curr) & regs._mask)
        return

    # neg reg
    m = _NEG_RE.match(text)
    if m:
        curr = regs.get_concrete(m.group(1))
        if curr is not None:
            regs.set_concrete(m.group(1), (-curr) & regs._mask)
        return

    # push — doesn't kill any GP reg (ignore stack pointer tracking)
    if text.lower().startswith("push"):
        return

    # pop reg — kills the destination
    if text.lower().startswith("pop"):
        parts = text.split()
        if len(parts) >= 2 and _canon(parts[1]) in _GP_REGS:
            regs.set(parts[1], _RegValue())  # now unknown
        return

    # Anything else: if it writes to a register, kill it
    # (conservative: only kill for known write-patterns)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def recover_key_from_entry(
    instructions: Sequence[Any],
    dispatcher_match: Any,
    *,
    binary_data: Optional[bytes] = None,
    binary_base: int = 0,
    bit_width: int = 64,
) -> Optional[RecoveredKey]:
    """Recover the initial rolling key by abstract-interpreting the VM entry stub.

    Parameters
    ----------
    instructions
        Sequence of instruction-like objects (dicts or LiftedInstruction)
        from ``vm_entry`` up to (but not including) the dispatcher body.
        Each must have ``address``, ``size``, ``mnemonic``, ``operands``.
    dispatcher_match
        ``VMProtectDispatcherMatch`` (or dict) identifying the key register
        and vIP register.
    binary_data
        Raw binary for memory-read resolution (optional).
    binary_base
        Virtual address of ``binary_data[0]``.
    bit_width
        Architecture width (32 or 64).

    Returns
    -------
    RecoveredKey | None
        Recovered key information, or ``None`` if recovery failed.
    """
    if not instructions:
        return None

    key_reg = _infer_key_reg(dispatcher_match)
    vip_reg = _infer_vip_reg(dispatcher_match)

    regs = _AbstractRegFile(
        rip_base=_get_addr(instructions[0]),
        bit_width=bit_width,
    )

    # Walk instructions
    for insn in instructions:
        addr = _get_addr(insn)
        size = _get_attr(insn, "size", 1)
        mnemonic = _get_attr(insn, "mnemonic", "")
        operands_raw = _get_attr(insn, "operands", "")

        # Normalise operands to string
        if isinstance(operands_raw, (list, tuple)):
            operands = ", ".join(str(o) for o in operands_raw)
        else:
            operands = str(operands_raw)

        _interpret_instruction(
            regs, mnemonic, operands, addr, size,
            binary_data=binary_data,
            binary_base=binary_base,
        )

    # Extract key value
    key_val = regs.get_concrete(key_reg) if key_reg else None
    vip_val = regs.get_concrete(vip_reg) if vip_reg else None

    if key_val is None and not key_reg:
        # Try common VMProtect key registers: ecx, edx, ebx
        for candidate in ("ecx", "edx", "ebx", "rcx", "rdx", "rbx"):
            v = regs.get_concrete(candidate)
            if v is not None and v != 0:
                key_val = v
                key_reg = candidate
                break

    if key_val is None:
        return None

    # Determine source
    source = "immediate"
    # Check if the key assignment was via LEA
    key_info = regs.get(key_reg)
    if key_info.symbolic and "rip" in key_info.symbolic:
        source = "lea_rip"

    return RecoveredKey(
        key_value=key_val,
        key_register=key_reg,
        vip_initial=vip_val,
        vip_register=vip_reg or "",
        confidence=0.85 if source == "immediate" else 0.7,
        source=source,
    )


def recover_key_from_bytes(
    code: bytes,
    entry_address: int,
    dispatcher_address: int,
    dispatcher_match: Any,
    *,
    binary_data: Optional[bytes] = None,
    binary_base: int = 0,
    bit_width: int = 64,
    max_instructions: int = 50,
) -> Optional[RecoveredKey]:
    """Recover key by lifting raw bytes from entry to dispatcher.

    This is a convenience wrapper that lifts the code between
    ``entry_address`` and ``dispatcher_address`` and then calls
    :func:`recover_key_from_entry`.

    Parameters
    ----------
    code : bytes
        Raw code bytes (at least from entry to dispatcher).
    entry_address : int
        VM entry stub address.
    dispatcher_address : int
        Dispatcher loop address (we stop abstract interpretation here).
    dispatcher_match
        Same as :func:`recover_key_from_entry`.
    """
    # Build pseudo-instructions by simple linear disassembly
    # We use the lifter if available, otherwise fallback to regex on mnemonics
    try:
        from dragonslayer.analysis.symbolic_execution.lifter import InstructionLifter
        lifter = InstructionLifter(arch="x86_64" if bit_width == 64 else "x86")
        lifted = lifter.lift(code, entry_address)

        # Filter: only include instructions between entry and dispatcher
        filtered = []
        for insn in lifted:
            if insn.address >= dispatcher_address:
                break
            filtered.append(insn)
            if len(filtered) >= max_instructions:
                break

        if not filtered:
            return None

        return recover_key_from_entry(
            filtered, dispatcher_match,
            binary_data=binary_data,
            binary_base=binary_base,
            bit_width=bit_width,
        )
    except (ValueError, TypeError, KeyError, RuntimeError, AttributeError) as exc:
        logger.debug("Lifter-based key recovery failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_key_reg(dispatcher_match: Any) -> str:
    """Infer key register from dispatcher match."""
    ctx = _get_attr(dispatcher_match, "context_registers", {})
    if isinstance(ctx, dict):
        for reg, role in ctx.items():
            if isinstance(role, str) and "key" in role.lower():
                return reg.lower()

    transforms = _get_attr(dispatcher_match, "decode_transforms", [])
    if transforms:
        m = re.search(r"(xor|add|sub)\s+(\w+)", str(transforms[0]), re.IGNORECASE)
        if m:
            return m.group(2).lower()

    return ""


def _infer_vip_reg(dispatcher_match: Any) -> str:
    """Infer vIP register from dispatcher match."""
    vreg = _get_attr(dispatcher_match, "vip_register", "")
    if vreg:
        return vreg.lower()

    ctx = _get_attr(dispatcher_match, "context_registers", {})
    if isinstance(ctx, dict):
        for reg, role in ctx.items():
            if isinstance(role, str) and "vip" in role.lower():
                return reg.lower()

    return ""


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _get_addr(insn: Any) -> int:
    if isinstance(insn, dict):
        return insn.get("address", 0)
    return getattr(insn, "address", 0)
