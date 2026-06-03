#!/usr/bin/env python3
"""Generate a small but *valid* x86-64 ELF containing a real bytecode VM.

This is a legitimate stand-in for a VM-protected binary for testing the
devirtualization pipeline end-to-end: it is a genuine compiled artifact
with a fetch -> decode -> dispatch interpreter loop, per-opcode handlers,
and an embedded bytecode program — the same shape VMDragonSlayer targets.

It deliberately does NOT use any real/commercial protector or malware.

Run ``python tests/fixtures/build_vm_sample.py`` to regenerate
``tests/fixtures/vm_sample.elf``.

VM model (register-based):
    rsi = vIP (pointer into the bytecode stream)
    ebx = virtual accumulator register
    opcodes: 0x01 LOAD imm32 -> acc ; 0x02 ADD imm32 ; 0x03 XOR imm32 ;
             0x00 HALT
Bytecode: LOAD 10 ; ADD 5 ; XOR 3 ; HALT  =>  (10 + 5) ^ 3 = 12
"""
from __future__ import annotations

import struct
from pathlib import Path

BASE = 0x400000
EHDR = 64
PHDR = 56
CODE_VADDR = BASE + EHDR + PHDR

_VM_ASM = """
_start:
    lea rsi, [rip + bytecode]
loop:
    movzx eax, byte ptr [rsi]
    inc rsi
    cmp eax, 1
    je h_load
    cmp eax, 2
    je h_add
    cmp eax, 3
    je h_xor
    jmp done
h_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    jmp loop
h_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    jmp loop
h_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
    jmp loop
done:
    hlt
bytecode:
"""

# LOAD 10 ; ADD 5 ; XOR 3 ; HALT
_BYTECODE = (
    b"\x01" + struct.pack("<i", 10)
    + b"\x02" + struct.pack("<i", 5)
    + b"\x03" + struct.pack("<i", 3)
    + b"\x00"
)


def _assemble() -> bytes:
    from keystone import KS_ARCH_X86, KS_MODE_64, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    enc, _ = ks.asm(_VM_ASM)
    return bytes(enc)


def build() -> tuple[bytes, dict]:
    """Return ``(elf_bytes, metadata)``."""
    code = _assemble()
    payload = code + _BYTECODE
    total = EHDR + PHDR + len(payload)

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # e_type = ET_EXEC
        62,           # e_machine = EM_X86_64
        1,            # e_version
        CODE_VADDR,   # e_entry -> dispatcher loop
        EHDR,         # e_phoff
        0,            # e_shoff
        0,            # e_flags
        EHDR,         # e_ehsize
        PHDR,         # e_phentsize
        1,            # e_phnum
        0, 0, 0,      # e_shentsize, e_shnum, e_shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,            # p_type = PT_LOAD
        7,            # p_flags = RWX
        0,            # p_offset
        BASE,         # p_vaddr
        BASE,         # p_paddr
        total,        # p_filesz
        total + 0x1000,  # p_memsz (headroom)
        0x1000,       # p_align
    )
    elf = ehdr + phdr + payload
    meta = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        # The dispatch loop begins right after the 7-byte ``lea rsi,[rip+..]``
        # prologue that initialises the vIP.
        "dispatch_va": CODE_VADDR + 7,
        "code_len": len(code),
        "bytecode_va": CODE_VADDR + len(code),
        "bytecode_len": len(_BYTECODE),
        "expected_result": (10 + 5) ^ 3,  # = 12
    }
    return elf, meta


if __name__ == "__main__":
    elf, meta = build()
    out = Path(__file__).with_name("vm_sample.elf")
    out.write_bytes(elf)
    print(f"wrote {out} ({len(elf)} bytes)")
    print(f"metadata: {meta}")
