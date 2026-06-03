#!/usr/bin/env python3
"""Advanced obfuscation zoo — encryption, memory-resident & non-monotonic vIP.

Companion to ``build_vm_zoo.py``.  Each builder returns ``(elf, metadata)``
for a genuine, executable x86-64 interpreter that stresses an obfuscation
technique *beyond* dispatch shape:

* ``build_encrypted_bytecode`` — opcodes and immediates are XOR-encrypted in
  the bytecode stream and decrypted on the fly.  Tests that dynamic tracing
  sees through bytecode encryption that defeats static extraction.
* ``build_self_decrypting``    — the bytecode is decrypted *in place* by a
  startup loop before the VM runs (self-modifying data).  Tests that a hot
  startup decrypt loop does not derail dispatch-loop detection.
* ``build_memory_vip``         — the vIP lives in a VM-context struct in
  memory (loaded/stored each step), not a fixed architectural role.  Tests
  whether the register heuristic still finds the transit register.
* ``build_virtual_loop``       — the bytecode contains a virtual backward
  branch (a loop), so the vIP is **non-monotonic** (revisits addresses).
  Directly stresses the monotonic-vIP assumption.

Not real protectors / not malware — hand-written interpreters.
"""
from __future__ import annotations

import struct

try:  # package import (tests) and direct-script execution both supported
    from .build_vm_zoo import BASE, CODE_VADDR, _wrap_elf  # reuse ELF wrapper
except ImportError:  # pragma: no cover - script execution fallback
    from build_vm_zoo import BASE, CODE_VADDR, _wrap_elf

_KEY = 0x5A


def _meta(code_len: int, *, expected, **extra) -> dict:
    m = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        "code_len": code_len,
        "expected_result": expected,
    }
    m.update(extra)
    return m


# ---------------------------------------------------------------------------
# 1. encrypted bytecode (opcodes + immediates XOR-encrypted, decrypted live)
# ---------------------------------------------------------------------------
def build_encrypted_bytecode() -> tuple[bytes, dict]:
    # plaintext program: LOAD 10 ; ADD 5 ; XOR 3 ; HALT -> 12
    plain = (
        b"\x01" + struct.pack("<i", 10)
        + b"\x02" + struct.pack("<i", 5)
        + b"\x03" + struct.pack("<i", 3)
        + b"\x00"
    )
    enc = bytes(b ^ _KEY for b in plain)
    bc_lines = "bc:\n" + "".join(f"    .byte {b}\n" for b in enc)
    asm = f"""
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
oloop:
    movzx eax, byte ptr [rsi]
    xor al, 0x5a
    inc rsi
    jmp qword ptr [r10 + rax*8]
h_halt:
    hlt
h_load:
    mov ebx, dword ptr [rsi]
    xor ebx, 0x5a5a5a5a
    add rsi, 4
    jmp oloop
h_add:
    mov ecx, dword ptr [rsi]
    xor ecx, 0x5a5a5a5a
    add ebx, ecx
    add rsi, 4
    jmp oloop
h_xor:
    mov ecx, dword ptr [rsi]
    xor ecx, 0x5a5a5a5a
    xor ebx, ecx
    add rsi, 4
    jmp oloop
tbl:
    .quad h_halt
    .quad h_load
    .quad h_add
    .quad h_xor
{bc_lines}
"""
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, expected=(10 + 5) ^ 3, technique="encrypted_bytecode")


# ---------------------------------------------------------------------------
# 2. self-decrypting bytecode (startup loop decrypts in place, then runs)
# ---------------------------------------------------------------------------
def build_self_decrypting() -> tuple[bytes, dict]:
    plain = (
        b"\x01" + struct.pack("<i", 10)
        + b"\x02" + struct.pack("<i", 5)
        + b"\x03" + struct.pack("<i", 3)
        + b"\x00"
    )
    enc = bytes(b ^ _KEY for b in plain)
    bc_lines = "bc:\n" + "".join(f"    .byte {b}\n" for b in enc)
    asm = f"""
_start:
    lea rsi, [rip + bc]
    mov ecx, {len(plain)}
dec_loop:
    xor byte ptr [rsi], 0x5a
    inc rsi
    dec ecx
    jnz dec_loop
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    jmp qword ptr [r10 + rax*8]
h_halt:
    hlt
h_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
tbl:
    .quad h_halt
    .quad h_load
    .quad h_add
    .quad h_xor
{bc_lines}
"""
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, expected=(10 + 5) ^ 3, technique="self_decrypting")


# ---------------------------------------------------------------------------
# 3. memory-resident vIP (VM-context struct; vIP loaded/stored each step)
# ---------------------------------------------------------------------------
def build_memory_vip() -> tuple[bytes, dict]:
    asm = """
_start:
    lea rax, [rip + bc]
    lea r15, [rip + ctx]
    mov qword ptr [r15], rax
    lea r10, [rip + tbl]
oloop:
    mov rbp, qword ptr [r15]
    movzx eax, byte ptr [rbp]
    inc rbp
    mov qword ptr [r15], rbp
    jmp qword ptr [r10 + rax*8]
h_halt:
    hlt
h_load:
    mov rbp, qword ptr [r15]
    mov ebx, dword ptr [rbp]
    add rbp, 4
    mov qword ptr [r15], rbp
    jmp oloop
h_add:
    mov rbp, qword ptr [r15]
    add ebx, dword ptr [rbp]
    add rbp, 4
    mov qword ptr [r15], rbp
    jmp oloop
h_xor:
    mov rbp, qword ptr [r15]
    xor ebx, dword ptr [rbp]
    add rbp, 4
    mov qword ptr [r15], rbp
    jmp oloop
tbl:
    .quad h_halt
    .quad h_load
    .quad h_add
    .quad h_xor
ctx:
    .zero 16
bc:
    .byte 1
    .long 10
    .byte 2
    .long 5
    .byte 3
    .long 3
    .byte 0
"""
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, expected=(10 + 5) ^ 3, technique="memory_vip")


# ---------------------------------------------------------------------------
# 4. virtual loop (non-monotonic vIP via a backward virtual branch)
# ---------------------------------------------------------------------------
def build_virtual_loop() -> tuple[bytes, dict]:
    # opcodes: 0 HALT ; 1 LOAD imm ; 2 ADD imm ; 4 DECJNZ rel8 ; 5 SETCNT imm
    # program: SETCNT 5 ; LOAD 0 ; (loop) ADD 5 ; DECJNZ -7 ; HALT  -> 25
    bc = (
        b"\x05" + struct.pack("<i", 5)     # SETCNT 5   -> edx=5
        + b"\x01" + struct.pack("<i", 0)   # LOAD 0     -> ebx=0
        + b"\x02" + struct.pack("<i", 5)   # ADD 5      (loop target)
        + b"\x04" + struct.pack("<b", -7)  # DECJNZ -7  -> back to ADD
        + b"\x00"                          # HALT
    )
    bc_lines = "bc:\n" + "".join(f"    .byte {b & 0xFF}\n" for b in bc)
    asm = f"""
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    jmp qword ptr [r10 + rax*8]
h_halt:
    hlt
h_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_setcnt:
    mov edx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_decjnz:
    movsx rax, byte ptr [rsi]
    inc rsi
    dec edx
    jz no_jump
    add rsi, rax
no_jump:
    jmp oloop
tbl:
    .quad h_halt
    .quad h_load
    .quad h_add
    .quad 0
    .quad h_decjnz
    .quad h_setcnt
{bc_lines}
"""
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, expected=5 * 5, technique="virtual_loop")


_ADV = {
    "encrypted_bytecode": build_encrypted_bytecode,
    "self_decrypting": build_self_decrypting,
    "memory_vip": build_memory_vip,
    "virtual_loop": build_virtual_loop,
}


if __name__ == "__main__":
    from pathlib import Path
    out_dir = Path(__file__).parent
    for name, fn in _ADV.items():
        elf, meta = fn()
        path = out_dir / f"vm_zoo_{name}.elf"
        path.write_bytes(elf)
        print(f"wrote {path.name} ({len(elf)} bytes)  meta={meta}")
