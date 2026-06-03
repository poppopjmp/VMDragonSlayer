#!/usr/bin/env python3
"""Themida-grade capstone: a 3-layer nested VM with per-layer encryption.

This is the hardest synthetic in the suite — it combines every technique the
earlier fixtures isolate, the way commercial multi-layer protectors
(Themida/WinLicense) actually stack them:

* **Three interpreter layers.**  The outer VM (jump-table dispatch, vIP=rsi)
  has an opcode that *enters* a middle VM (cmp/je dispatch, vIP=rdi), which in
  turn has an opcode that enters an inner VM (jump-table dispatch, vIP=r8).
  Each layer has its own dispatcher shape, vIP, accumulator and bytecode.
* **Per-layer encryption.**  Layer-2 and layer-3 bytecode are XOR-encrypted
  with *different* keys and decrypted in place by a loop at the entry of the
  enclosing handler — so each layer also reproduces the "hot decrypt loop
  masks the dispatcher" situation, at depth.
* **Handler mutation.**  Layer 3 has a duplicate ADD handler (opcode 3) with a
  different, junk-padded body.

Not a real protector / not malware — a hand-written nested interpreter.

Program / expected result
-------------------------
Layer 3:  LOAD 2 ; ADD 3 ; ADD2 1 ; RET          -> edx = 6
Layer 2:  ILOAD 4 ; IMUL 6 ; VMENTER3 ; IRET      -> ecx = 24 + 6 = 30
Layer 1:  LOAD 10 ; ADD 5 ; XOR 3 ; VMENTER2 ; HALT -> ebx = ((10+5)^3) + 30
                                                        = 12 + 30 = 42
"""
from __future__ import annotations

import struct

try:
    from .build_vm_zoo import BASE, CODE_VADDR, _wrap_elf
except ImportError:  # pragma: no cover - script execution fallback
    from build_vm_zoo import BASE, CODE_VADDR, _wrap_elf

_KEY2 = 0x5A
_KEY3 = 0xA5

# Layer-2 plaintext: ILOAD 4 ; IMUL 6 ; VMENTER3 ; IRET
_L2_PLAIN = (
    b"\x01" + struct.pack("<i", 4)
    + b"\x02" + struct.pack("<i", 6)
    + b"\x05"
    + b"\x00"
)
# Layer-3 plaintext: LOAD 2 ; ADD 3 ; ADD2 1 ; RET
_L3_PLAIN = (
    b"\x01" + struct.pack("<i", 2)
    + b"\x02" + struct.pack("<i", 3)
    + b"\x03" + struct.pack("<i", 1)
    + b"\x00"
)


def _enc(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _bytes_dir(label: str, data: bytes) -> str:
    return f"{label}:\n" + "".join(f"    .byte {b}\n" for b in data)


def build() -> tuple[bytes, dict]:
    l2_enc = _enc(_L2_PLAIN, _KEY2)
    l3_enc = _enc(_L3_PLAIN, _KEY3)

    asm = f"""
_start:
    lea rsi, [rip + bc1]
    lea r10, [rip + tbl1]
l1_loop:
    movzx eax, byte ptr [rsi]
    inc rsi
    jmp qword ptr [r10 + rax*8]

l1_halt:
    hlt
l1_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    jmp l1_loop
l1_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    jmp l1_loop
l1_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
    jmp l1_loop

l1_vmenter2:
    lea rax, [rip + bc2]
    mov r9d, {len(_L2_PLAIN)}
l2_dec:
    xor byte ptr [rax], {_KEY2}
    inc rax
    dec r9d
    jnz l2_dec
    lea rdi, [rip + bc2]
    xor ecx, ecx
l2_loop:
    movzx eax, byte ptr [rdi]
    inc rdi
    cmp eax, 1
    je l2_iload
    cmp eax, 2
    je l2_imul
    cmp eax, 5
    je l2_vmenter3
    add ebx, ecx
    jmp l1_loop
l2_iload:
    mov ecx, dword ptr [rdi]
    add rdi, 4
    jmp l2_loop
l2_imul:
    imul ecx, dword ptr [rdi]
    add rdi, 4
    jmp l2_loop

l2_vmenter3:
    lea rax, [rip + bc3]
    mov r9d, {len(_L3_PLAIN)}
l3_dec:
    xor byte ptr [rax], {_KEY3}
    inc rax
    dec r9d
    jnz l3_dec
    lea r8, [rip + bc3]
    lea r11, [rip + tbl3]
    xor edx, edx
l3_loop:
    movzx eax, byte ptr [r8]
    inc r8
    jmp qword ptr [r11 + rax*8]
l3_ret:
    add ecx, edx
    jmp l2_loop
l3_load:
    mov edx, dword ptr [r8]
    add r8, 4
    jmp l3_loop
l3_add:
    add edx, dword ptr [r8]
    add r8, 4
    jmp l3_loop
l3_add2:
    mov eax, dword ptr [r8]
    add r8, 4
    push rax
    pop rax
    add edx, eax
    jmp l3_loop

tbl3:
    .quad l3_ret
    .quad l3_load
    .quad l3_add
    .quad l3_add2

tbl1:
    .quad l1_halt
    .quad l1_load
    .quad l1_add
    .quad l1_xor
    .quad 0
    .quad l1_vmenter2

bc1:
    .byte 1
    .long 10
    .byte 2
    .long 5
    .byte 3
    .long 3
    .byte 5
    .byte 0
{_bytes_dir("bc2", l2_enc)}
{_bytes_dir("bc3", l3_enc)}
"""
    elf, n = _wrap_elf(asm, extra_memsz=0x2000)
    meta = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        "code_len": n,
        "expected_result": ((10 + 5) ^ 3) + (4 * 6) + (2 + 3 + 1),  # 12 + 24 + 6 = 42
        "layers": 3,
        "layer_vips": ["rsi", "rdi", "r8"],
        "technique": "themida_multilayer_encrypted",
    }
    return elf, meta


def load() -> tuple[bytes, dict]:
    """Load the pre-built ELF fixture without invoking keystone.

    Tests use this rather than :func:`build` so assembly happens only when the
    fixture is regenerated (``python build_vm_themida.py``), keeping the test
    path deterministic and free of the keystone engine.
    """
    from pathlib import Path

    elf = Path(__file__).with_name("vm_themida_multilayer.elf").read_bytes()
    meta = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        "code_len": len(elf) - 120,  # ELF header (64) + program header (56)
        "expected_result": ((10 + 5) ^ 3) + (4 * 6) + (2 + 3 + 1),  # 42
        "layers": 3,
        "layer_vips": ["rsi", "rdi", "r8"],
        "technique": "themida_multilayer_encrypted",
    }
    return elf, meta


if __name__ == "__main__":
    from pathlib import Path
    elf, meta = build()
    out = Path(__file__).with_name("vm_themida_multilayer.elf")
    out.write_bytes(elf)
    print(f"wrote {out.name} ({len(elf)} bytes)  meta={meta}")
