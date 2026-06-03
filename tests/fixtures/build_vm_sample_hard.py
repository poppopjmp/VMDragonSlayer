#!/usr/bin/env python3
"""Generate a *hard* x86-64 ELF bytecode VM for honest capability testing.

This is a deliberately harder stand-in than ``build_vm_sample.py`` /
``build_vm_sample_jumptable.py``.  It combines the three obfuscation
features real commercial protectors lean on, so we can see where the
devirtualization pipeline actually breaks (rather than only validating it
against a friendly toy VM):

1. **Nested dispatch (VM-in-VM).**  The outer VM uses a *jump-table*
   dispatcher.  Opcode 5 (``VMCALL``) switches into an *inner* VM that has
   its own ``cmp/je`` dispatch chain (a different dispatcher shape) and its
   own bytecode, accumulator and vIP.

2. **Duplicated handlers.**  Opcode 2 and opcode 4 both implement ADD, but
   via different native instruction bodies — the kind of handler
   duplication used to defeat naive opcode<->semantic mapping.

3. **Handler mutation + opaque predicate.**  Opcode 4's body contains dead
   arithmetic (``+7`` then ``-7``) and an opaque always-false predicate
   (``n*(n+1)`` is always even, so the low bit is 0 and the ``jnz`` is never
   taken) guarding a dead block that would corrupt the accumulator if it
   ever executed.

Not a real protector and not malware: a hand-written interpreter.

VM model
--------
Outer (jump-table dispatch):
    rsi = outer vIP, r10 = handler-table base, ebx = accumulator
    0 HALT ; 1 LOAD imm32 ; 2 ADD imm32 ; 3 XOR imm32 ;
    4 ADD2 imm32 (duplicate ADD, mutated body) ; 5 VMCALL (run inner VM)
Inner (cmp/je dispatch):
    rdi = inner vIP, ecx = inner accumulator
    0 IRET ; 1 ILOAD imm32 ; 2 IMUL imm32

Program
-------
Outer:  LOAD 10 ; ADD 5 ; XOR 3 ; ADD2 7 ; VMCALL ; HALT
Inner:  ILOAD 4 ; IMUL 6 ; IRET   ->  ecx = 24
Result: ((((10 + 5) ^ 3) + 7) + 24) = (((15 ^ 3) + 7) + 24) = ((12 + 7) + 24) = 43
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
    lea rsi, [rip + obc]
    lea r10, [rip + otable]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    jmp qword ptr [r10 + rax*8]

oh_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop

oh_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop

oh_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop

oh_add2:
    mov ecx, dword ptr [rsi]
    add rsi, 4
    mov edx, ecx
    add edx, 7
    sub edx, 7
    mov eax, edx
    inc eax
    imul eax, edx
    test eax, 1
    jnz oh_dead
    add ebx, ecx
    jmp oloop
oh_dead:
    xor ebx, ebx
    not ebx
    jmp oloop

oh_vmcall:
    lea rdi, [rip + ibc]
    xor ecx, ecx
iloop:
    movzx eax, byte ptr [rdi]
    inc rdi
    cmp eax, 1
    je ih_load
    cmp eax, 2
    je ih_mul
    add ebx, ecx
    jmp oloop
ih_load:
    mov ecx, dword ptr [rdi]
    add rdi, 4
    jmp iloop
ih_mul:
    imul ecx, dword ptr [rdi]
    add rdi, 4
    jmp iloop

odone:
    hlt

otable:
    .quad odone
    .quad oh_load
    .quad oh_add
    .quad oh_xor
    .quad oh_add2
    .quad oh_vmcall

obc:
    .byte 1
    .long 10
    .byte 2
    .long 5
    .byte 3
    .long 3
    .byte 4
    .long 7
    .byte 5
    .byte 0

ibc:
    .byte 1
    .long 4
    .byte 2
    .long 6
    .byte 0
"""

# Byte patterns used to locate the embedded bytecode VAs post-assembly.
_OUTER_BC = (
    b"\x01" + struct.pack("<i", 10)
    + b"\x02" + struct.pack("<i", 5)
    + b"\x03" + struct.pack("<i", 3)
    + b"\x04" + struct.pack("<i", 7)
    + b"\x05\x00"
)
_INNER_BC = (
    b"\x01" + struct.pack("<i", 4)
    + b"\x02" + struct.pack("<i", 6)
    + b"\x00"
)


def _assemble() -> bytes:
    from keystone import KS_ARCH_X86, KS_MODE_64, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    # Assemble at the code's runtime VA so `.quad <label>` data entries in
    # the jump table resolve to absolute virtual addresses.
    enc, _ = ks.asm(_VM_ASM, CODE_VADDR)
    return bytes(enc)


def build() -> tuple[bytes, dict]:
    """Return ``(elf_bytes, metadata)``."""
    payload = _assemble()
    total = EHDR + PHDR + len(payload)

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 62, 1, CODE_VADDR, EHDR, 0, 0, EHDR, PHDR, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ", 1, 7, 0, BASE, BASE, total, total + 0x1000, 0x1000,
    )
    elf = ehdr + phdr + payload

    outer_off = payload.find(_OUTER_BC)
    inner_off = payload.find(_INNER_BC)
    meta = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        # Outer jump-table dispatcher loop begins right after the two
        # `lea` prologue instructions (7 bytes each = 14 bytes).
        "dispatch_va": CODE_VADDR + 14,
        "outer_bytecode_va": (CODE_VADDR + outer_off) if outer_off >= 0 else None,
        "inner_bytecode_va": (CODE_VADDR + inner_off) if inner_off >= 0 else None,
        "expected_result": ((((10 + 5) ^ 3) + 7) + (4 * 6)),  # = 43
    }
    return elf, meta


if __name__ == "__main__":
    elf, meta = build()
    out = Path(__file__).with_name("vm_sample_hard.elf")
    out.write_bytes(elf)
    print(f"wrote {out} ({len(elf)} bytes)")
    print(f"metadata: {meta}")
